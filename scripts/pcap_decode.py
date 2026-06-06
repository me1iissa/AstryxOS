#!/usr/bin/env python3
"""pcap_decode.py — decode a libpcap capture into a human-readable "what's on
the wire" summary, for the AstryxOS serial monitor's /api/wire endpoint.

The capture is produced HOST-SIDE by a QEMU `filter-dump` object tapping the
e1000/SLIRP netdev (`-object filter-dump,id=netdump,netdev=net0,file=…`). That
tap is invisible to the guest, so this module never touches the VM — it only
parses bytes that QEMU already wrote to disk.

What it surfaces (the "what happened on the wire" view):
  * DNS    — queries + responses (names, A/AAAA addrs, the resolver)
  * TCP    — each 4-tuple connection: handshake (SYN/SYN-ACK/ACK), close
             (FIN/RST), retransmits, dup-ACKs, bytes each way, final state
  * TLS    — ClientHello SNI + offered versions + ALPN, ServerHello, whether
             the handshake completed (Finished / appdata) or where it stalled
  * HTTP   — cleartext request lines (method/host/path) + response status
             (HTTPS payload is encrypted: we summarize TLS metadata only)
  * ANOMALIES useful for debugging an OUR-kernel network divergence:
             out-of-order, dup-ACKs, zero-window, premature RST, unanswered
             SYN, half-open connections, retransmissions.

Usage as a library (what /api/wire calls):
    import pcap_decode
    summary = pcap_decode.decode("/path/to/capture.pcap")   # -> dict (JSON-able)

Usage as a CLI (non-interactive, one-shot, JSON to stdout — harness convention):
    python3 scripts/pcap_decode.py <capture.pcap> [--max-packets N] [--pretty]
    python3 scripts/pcap_decode.py --selftest          # craft + decode a tiny
                                                          synthetic pcap, exit 0

Robustness contract (the capture may be PARTIAL / still being written):
  * A truncated final record is dropped, not fatal.
  * A bad/garbled packet is recorded as a parse anomaly and skipped; decoding
    continues.
  * An empty or header-only file yields a valid (empty) summary, never an
    exception. The raw .pcap download path is independent of this module.

Pure Python standard library only. No tshark/scapy dependency. (If a future
caller wants tshark when present, it can shell out separately; this module is
the always-available fallback and the canonical structured view.)

Spec anchors (public only): libpcap savefile format; RFC 791 (IPv4),
RFC 8200 (IPv6), RFC 768 (UDP), RFC 793 (TCP), RFC 826 (ARP), RFC 1035 (DNS),
RFC 8446 + RFC 6066 (TLS 1.3 / SNI / ALPN), RFC 9110 (HTTP semantics),
RFC 894 (Ethernet II framing).
"""
import io
import os
import struct
import sys
import json
import argparse

# ---------------------------------------------------------------------------
# libpcap savefile constants
# ---------------------------------------------------------------------------
PCAP_MAGIC_LE = 0xA1B2C3D4   # microsecond ts, little-endian on-disk
PCAP_MAGIC_BE = 0xD4C3B2A1   # microsecond ts, big-endian on-disk
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond ts, little-endian
PCAP_MAGIC_NS_BE = 0x4D3CB2A1  # nanosecond ts, big-endian
# pcapng uses 0x0A0D0D0A as the first block type — we detect and report it but
# do not parse it (the filter-dump tap writes classic pcap).
PCAPNG_MAGIC = 0x0A0D0D0A

GLOBAL_HDR_LEN = 24
RECORD_HDR_LEN = 16

# DLT / LINKTYPE values we handle.
LINKTYPE_NULL = 0       # BSD loopback: 4-byte AF_* header
LINKTYPE_ETHERNET = 1   # Ethernet II
LINKTYPE_RAW = 101      # raw IP, no link header (some SLIRP dumps)
LINKTYPE_LINUX_SLL = 113  # Linux cooked capture v1
LINKTYPE_LINUX_SLL2 = 276

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
ETH_P_VLAN = 0x8100
ETH_P_VLAN_QINQ = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

# Sanity caps so a corrupt length field can't make us allocate gigabytes.
MAX_SNAPLEN = 262144
DEFAULT_MAX_PACKETS = 200000


# ---------------------------------------------------------------------------
# Address formatting
# ---------------------------------------------------------------------------
def _ipv4_str(b):
    return ".".join(str(x) for x in b)


def _ipv6_str(b):
    # RFC 5952-ish compaction is nice-to-have; a plain hextet form is enough
    # for a debugging summary and avoids edge-case bugs.
    parts = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    s = ":".join(parts)
    # collapse the longest run of :0: groups into ::
    import re as _re
    best = None
    for m in _re.finditer(r"(?:^|:)(0(?::0)+)(?::|$)", s):
        run = m.group(1)
        if best is None or len(run) > len(best[0]):
            best = (run, m.start(1), m.end(1))
    if best:
        run, a, c = best
        s = (s[:a].rstrip(":") + "::" + s[c:].lstrip(":"))
        s = s.replace(":::", "::")
    return s


def _mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


# ---------------------------------------------------------------------------
# pcap file reader (byte-order + ts-precision aware, partial-safe)
# ---------------------------------------------------------------------------
class PcapError(Exception):
    pass


class PcapReader:
    """Iterates (ts_float, linktype, packet_bytes, truncated_flag) records.

    Stops cleanly at EOF or at the first torn record (a partial capture in
    progress) and records that in `self.truncated`. Never raises on a short
    final record."""

    def __init__(self, fileobj):
        self.f = fileobj
        self.truncated = False
        self.ts_div = 1_000_000  # us by default
        hdr = self.f.read(GLOBAL_HDR_LEN)
        if len(hdr) < 4:
            raise PcapError("file too short for a pcap global header")
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == PCAPNG_MAGIC:
            raise PcapError("pcapng format is not supported by this decoder "
                            "(expected classic libpcap)")
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.endian = "<"
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            self.endian = ">"
        else:
            raise PcapError(f"not a libpcap file (bad magic 0x{magic:08x})")
        if magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
            self.ts_div = 1_000_000_000
        if len(hdr) < GLOBAL_HDR_LEN:
            raise PcapError("truncated pcap global header")
        (self.ver_major, self.ver_minor, self.thiszone,
         self.sigfigs, self.snaplen, self.linktype) = struct.unpack(
            self.endian + "HHiIII", hdr[4:GLOBAL_HDR_LEN])

    def __iter__(self):
        ep = self.endian
        while True:
            rh = self.f.read(RECORD_HDR_LEN)
            if not rh:
                return  # clean EOF
            if len(rh) < RECORD_HDR_LEN:
                self.truncated = True
                return  # torn record header (capture still being written)
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(ep + "IIII", rh)
            if incl_len > MAX_SNAPLEN:
                # corrupt length — refuse to read it, flag and stop.
                self.truncated = True
                return
            data = self.f.read(incl_len)
            if len(data) < incl_len:
                self.truncated = True
                return  # torn packet body
            ts = ts_sec + (ts_frac / self.ts_div)
            yield (ts, self.linktype, data, orig_len)


# ---------------------------------------------------------------------------
# Link / network / transport dissection -> a normalised packet dict
# ---------------------------------------------------------------------------
def _strip_link(linktype, data):
    """Return (l3_proto, l3_bytes) where l3_proto is 'ipv4'/'ipv6'/'arp'/None."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return (None, b"", {})
        eth = {"dst_mac": _mac_str(data[0:6]), "src_mac": _mac_str(data[6:12])}
        et = (data[12] << 8) | data[13]
        off = 14
        # peel VLAN tags (RFC 802.1Q) — they sit between MACs and ethertype.
        while et in (ETH_P_VLAN, ETH_P_VLAN_QINQ) and len(data) >= off + 4:
            et = (data[off + 2] << 8) | data[off + 3]
            off += 4
        rest = data[off:]
        if et == ETH_P_IPV4:
            return ("ipv4", rest, eth)
        if et == ETH_P_IPV6:
            return ("ipv6", rest, eth)
        if et == ETH_P_ARP:
            return ("arp", rest, eth)
        return (None, rest, eth)
    if linktype == LINKTYPE_RAW:
        if not data:
            return (None, b"", {})
        ver = data[0] >> 4
        if ver == 4:
            return ("ipv4", data, {})
        if ver == 6:
            return ("ipv6", data, {})
        return (None, data, {})
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return (None, b"", {})
        # 4-byte host-order AF_ family; AF_INET=2 typically, AF_INET6 varies.
        fam = struct.unpack("<I", data[0:4])[0]
        rest = data[4:]
        if fam == 2:
            return ("ipv4", rest, {})
        if fam in (10, 23, 28, 30):
            return ("ipv6", rest, {})
        if rest and (rest[0] >> 4) == 4:
            return ("ipv4", rest, {})
        if rest and (rest[0] >> 4) == 6:
            return ("ipv6", rest, {})
        return (None, rest, {})
    if linktype in (LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
        hlen = 16 if linktype == LINKTYPE_LINUX_SLL else 20
        if len(data) < hlen:
            return (None, b"", {})
        if linktype == LINKTYPE_LINUX_SLL:
            et = (data[14] << 8) | data[15]
        else:
            et = (data[0] << 8) | data[1]
        rest = data[hlen:]
        if et == ETH_P_IPV4:
            return ("ipv4", rest, {})
        if et == ETH_P_IPV6:
            return ("ipv6", rest, {})
        if et == ETH_P_ARP:
            return ("arp", rest, {})
        return (None, rest, {})
    return (None, data, {})


def _parse_ipv4(b):
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    if ihl < 20 or len(b) < ihl:
        return None
    total = (b[2] << 8) | b[3]
    proto = b[9]
    src = _ipv4_str(b[12:16])
    dst = _ipv4_str(b[16:20])
    # frag offset / MF — note fragmentation but still hand over what we have.
    flags_frag = (b[6] << 8) | b[7]
    frag_off = flags_frag & 0x1FFF
    mf = bool(flags_frag & 0x2000)
    payload = b[ihl:total] if 0 < total <= len(b) else b[ihl:]
    return {"ver": 4, "src": src, "dst": dst, "proto": proto,
            "payload": payload, "fragmented": (frag_off != 0 or mf)}


def _parse_ipv6(b):
    if len(b) < 40:
        return None
    plen = (b[4] << 8) | b[5]
    nexthdr = b[6]
    src = _ipv6_str(b[8:24])
    dst = _ipv6_str(b[24:40])
    off = 40
    # Walk the extension-header chain (RFC 8200 §4) to the upper-layer proto.
    EXT = {0, 43, 44, 51, 60}  # hop-by-hop, routing, fragment, AH, dest-opts
    fragmented = False
    guard = 0
    while nexthdr in EXT and len(b) >= off + 2 and guard < 16:
        guard += 1
        if nexthdr == 44:
            fragmented = True
            ext_len = 8
        elif nexthdr == 51:  # AH length is in 4-byte units, +2
            ext_len = (b[off + 1] + 2) * 4
        else:
            ext_len = (b[off + 1] + 1) * 8
        nexthdr = b[off]
        off += ext_len
    payload = b[off:40 + plen] if plen and (40 + plen) <= len(b) else b[off:]
    return {"ver": 6, "src": src, "dst": dst, "proto": nexthdr,
            "payload": payload, "fragmented": fragmented}


def _parse_tcp(b):
    if len(b) < 20:
        return None
    sport = (b[0] << 8) | b[1]
    dport = (b[2] << 8) | b[3]
    seq = struct.unpack(">I", b[4:8])[0]
    ack = struct.unpack(">I", b[8:12])[0]
    data_off = (b[12] >> 4) * 4
    if data_off < 20 or len(b) < data_off:
        data_off = 20
    flags = b[13]
    window = (b[14] << 8) | b[15]
    payload = b[data_off:]
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "window": window, "payload": payload,
        "fin": bool(flags & 0x01), "syn": bool(flags & 0x02),
        "rst": bool(flags & 0x04), "psh": bool(flags & 0x08),
        "ack_flag": bool(flags & 0x10), "urg": bool(flags & 0x20),
    }


def _parse_udp(b):
    if len(b) < 8:
        return None
    sport = (b[0] << 8) | b[1]
    dport = (b[2] << 8) | b[3]
    ulen = (b[4] << 8) | b[5]
    payload = b[8:ulen] if 8 <= ulen <= len(b) else b[8:]
    return {"sport": sport, "dport": dport, "payload": payload}


# ---------------------------------------------------------------------------
# DNS (RFC 1035) — names with compression, A/AAAA/CNAME/PTR answers
# ---------------------------------------------------------------------------
_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 65: "HTTPS",
              64: "SVCB", 257: "CAA"}
_DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}


def _dns_name(b, off):
    """Decode a (possibly compressed) DNS name. Returns (name, next_off)."""
    labels = []
    jumped = False
    next_off = off
    guard = 0
    while True:
        if off >= len(b) or guard > 128:
            break
        guard += 1
        ln = b[off]
        if ln == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if (ln & 0xC0) == 0xC0:  # compression pointer (RFC 1035 §4.1.4)
            if off + 1 >= len(b):
                break
            ptr = ((ln & 0x3F) << 8) | b[off + 1]
            if not jumped:
                next_off = off + 2
            jumped = True
            off = ptr
            continue
        if off + 1 + ln > len(b):
            break
        labels.append(b[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    if not jumped:
        next_off = off
    return (".".join(labels), next_off)


def _parse_dns(payload):
    b = payload
    if len(b) < 12:
        return None
    tid = (b[0] << 8) | b[1]
    flags = (b[2] << 8) | b[3]
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    qd = (b[4] << 8) | b[5]
    an = (b[6] << 8) | b[7]
    off = 12
    questions = []
    for _ in range(min(qd, 64)):
        name, off = _dns_name(b, off)
        if off + 4 > len(b):
            break
        qtype = (b[off] << 8) | b[off + 1]
        off += 4
        questions.append({"name": name, "type": _DNS_TYPES.get(qtype, str(qtype))})
    answers = []
    if qr == 1:
        for _ in range(min(an, 128)):
            name, off = _dns_name(b, off)
            if off + 10 > len(b):
                break
            atype = (b[off] << 8) | b[off + 1]
            rdlen = (b[off + 8] << 8) | b[off + 9]
            off += 10
            if off + rdlen > len(b):
                break
            rdata = b[off:off + rdlen]
            val = None
            if atype == 1 and rdlen == 4:
                val = _ipv4_str(rdata)
            elif atype == 28 and rdlen == 16:
                val = _ipv6_str(rdata)
            elif atype in (5, 2, 12):
                val, _ = _dns_name(b, off)
            answers.append({"name": name,
                            "type": _DNS_TYPES.get(atype, str(atype)),
                            "data": val})
            off += rdlen
    return {"tid": tid, "qr": qr, "opcode": opcode,
            "rcode": _DNS_RCODES.get(rcode, str(rcode)),
            "questions": questions, "answers": answers}


# ---------------------------------------------------------------------------
# TLS (RFC 8446) — ClientHello SNI/ALPN/versions, ServerHello, record types
# ---------------------------------------------------------------------------
_TLS_VERS = {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
             0x0303: "TLS1.2", 0x0304: "TLS1.3"}
_TLS_CONTENT = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",
                23: "ApplicationData", 24: "Heartbeat"}


def _tls_version_name(v):
    return _TLS_VERS.get(v, f"0x{v:04x}")


def _parse_tls_records(payload):
    """Walk the TLS record layer of one TCP segment. Returns a list of records
    [{type, version, len, handshake?}], best-effort across a single segment.

    NOTE: a TLS record can span TCP segments; we decode what is present in this
    segment and mark a record as 'spanning' if its declared length exceeds the
    bytes we hold. The per-connection assembler upgrades this where it can."""
    b = payload
    out = []
    off = 0
    while off + 5 <= len(b):
        ctype = b[off]
        ver = (b[off + 1] << 8) | b[off + 2]
        rlen = (b[off + 3] << 8) | b[off + 4]
        if ctype not in _TLS_CONTENT:
            break  # not TLS (or mid-stream encrypted) — stop scanning
        if ver not in _TLS_VERS:
            break
        rec = {"type": _TLS_CONTENT[ctype], "version": _tls_version_name(ver),
               "len": rlen}
        body = b[off + 5:off + 5 + rlen]
        if len(body) < rlen:
            rec["spanning"] = True
        if ctype == 22 and body:
            hs = _parse_tls_handshake(body)
            if hs:
                rec.update(hs)
        out.append(rec)
        off += 5 + rlen
    return out


def _parse_tls_handshake(body):
    if len(body) < 4:
        return None
    htype = body[0]
    hlen = (body[1] << 16) | (body[2] << 8) | body[3]
    if htype == 1:  # ClientHello
        return _parse_client_hello(body[4:4 + hlen] if hlen else body[4:])
    if htype == 2:  # ServerHello
        return _parse_server_hello(body[4:4 + hlen] if hlen else body[4:])
    names = {11: "Certificate", 12: "ServerKeyExchange",
             13: "CertificateRequest", 14: "ServerHelloDone",
             15: "CertificateVerify", 16: "ClientKeyExchange",
             20: "Finished", 4: "NewSessionTicket", 8: "EncryptedExtensions"}
    return {"handshake": names.get(htype, f"hs_type_{htype}")}


def _parse_hello_extensions(b, off, info):
    """Shared SNI/ALPN/supported_versions extension walk (RFC 6066, RFC 7301,
    RFC 8446 §4.2)."""
    if off + 2 > len(b):
        return
    ext_total = (b[off] << 8) | b[off + 1]
    off += 2
    end = min(len(b), off + ext_total)
    while off + 4 <= end:
        etype = (b[off] << 8) | b[off + 1]
        elen = (b[off + 2] << 8) | b[off + 3]
        off += 4
        edata = b[off:off + elen]
        off += elen
        if etype == 0 and len(edata) >= 5:  # server_name (SNI)
            # server_name_list -> entry: type(1)=host_name + len(2) + name
            p = 2
            if p + 3 <= len(edata) and edata[p] == 0:
                nlen = (edata[p + 1] << 8) | edata[p + 2]
                info["sni"] = edata[p + 3:p + 3 + nlen].decode("ascii", "replace")
        elif etype == 16 and len(edata) >= 2:  # ALPN (RFC 7301)
            alpn = []
            p = 2
            while p < len(edata):
                ln = edata[p]
                p += 1
                if p + ln > len(edata):
                    break
                alpn.append(edata[p:p + ln].decode("ascii", "replace"))
                p += ln
            if alpn:
                info["alpn"] = alpn
        elif etype == 43 and len(edata) >= 1:  # supported_versions (1.3)
            vers = []
            if info.get("_is_server"):
                if len(edata) >= 2:
                    vers.append(_tls_version_name((edata[0] << 8) | edata[1]))
            else:
                ln = edata[0]
                p = 1
                while p + 1 < 1 + ln and p + 1 < len(edata):
                    vers.append(_tls_version_name((edata[p] << 8) | edata[p + 1]))
                    p += 2
            if vers:
                info["supported_versions"] = vers


def _parse_client_hello(b):
    info = {"handshake": "ClientHello", "_is_server": False}
    if len(b) < 38:
        info.pop("_is_server", None)
        return info
    legacy_ver = (b[0] << 8) | b[1]
    info["legacy_version"] = _tls_version_name(legacy_ver)
    off = 2 + 32  # client_version + random
    if off >= len(b):
        info.pop("_is_server", None)
        return info
    sid_len = b[off]; off += 1 + sid_len
    if off + 2 > len(b):
        info.pop("_is_server", None)
        return info
    cs_len = (b[off] << 8) | b[off + 1]; off += 2 + cs_len  # cipher_suites
    if off >= len(b):
        info.pop("_is_server", None)
        return info
    comp_len = b[off]; off += 1 + comp_len  # compression_methods
    _parse_hello_extensions(b, off, info)
    info.pop("_is_server", None)
    return info


def _parse_server_hello(b):
    info = {"handshake": "ServerHello", "_is_server": True}
    if len(b) < 38:
        info.pop("_is_server", None)
        return info
    legacy_ver = (b[0] << 8) | b[1]
    info["legacy_version"] = _tls_version_name(legacy_ver)
    off = 2 + 32
    if off >= len(b):
        info.pop("_is_server", None)
        return info
    sid_len = b[off]; off += 1 + sid_len
    if off + 3 > len(b):
        info.pop("_is_server", None)
        return info
    cipher = (b[off] << 8) | b[off + 1]; off += 2
    info["cipher_suite"] = f"0x{cipher:04x}"
    off += 1  # compression method
    _parse_hello_extensions(b, off, info)
    info.pop("_is_server", None)
    return info


# ---------------------------------------------------------------------------
# HTTP (RFC 9110) — cleartext request/response first lines only
# ---------------------------------------------------------------------------
_HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS",
                 b"PATCH", b"CONNECT", b"TRACE")


def _parse_http(payload):
    if not payload:
        return None
    line0, _, rest = payload.partition(b"\r\n")
    if payload.startswith(b"HTTP/"):
        parts = line0.split(b" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return {"kind": "response", "status": int(parts[1]),
                    "reason": (parts[2].decode("ascii", "replace")
                               if len(parts) > 2 else "")}
        return None
    for m in _HTTP_METHODS:
        if payload.startswith(m + b" "):
            parts = line0.split(b" ")
            if len(parts) >= 2:
                host = ""
                for hl in rest.split(b"\r\n"):
                    if hl.lower().startswith(b"host:"):
                        host = hl[5:].strip().decode("ascii", "replace")
                        break
                return {"kind": "request",
                        "method": m.decode(),
                        "path": parts[1].decode("ascii", "replace"),
                        "host": host}
    return None


# ---------------------------------------------------------------------------
# TCP connection tracking (RFC 793 state inference) + anomaly detection
# ---------------------------------------------------------------------------
class _Conn:
    __slots__ = ("a", "b", "first_ts", "last_ts",
                 "syn", "synack", "established", "fin_a", "fin_b", "rst",
                 "bytes_ab", "bytes_ba", "segs_ab", "segs_ba",
                 "retransmits", "dup_acks", "zero_window", "out_of_order",
                 "tls_client_hello", "tls_server_hello", "tls_complete",
                 "tls_sni", "tls_alpn", "tls_client_versions",
                 "tls_server_version", "http_reqs", "http_resps",
                 "_seen_seqs_ab", "_seen_seqs_ba", "_max_seq_ab", "_max_seq_ba",
                 "_last_ack_a", "_last_ack_a_n", "_last_ack_b", "_last_ack_b_n")

    def __init__(self, a, b, ts):
        self.a = a            # the endpoint that sent the first SYN (client)
        self.b = b            # the other endpoint (server)
        self.first_ts = ts
        self.last_ts = ts
        self.syn = False
        self.synack = False
        self.established = False
        self.fin_a = False
        self.fin_b = False
        self.rst = False
        self.bytes_ab = 0     # a -> b payload bytes
        self.bytes_ba = 0
        self.segs_ab = 0
        self.segs_ba = 0
        self.retransmits = 0
        self.dup_acks = 0
        self.zero_window = 0
        self.out_of_order = 0
        self.tls_client_hello = False
        self.tls_server_hello = False
        self.tls_complete = False
        self.tls_sni = None
        self.tls_alpn = None
        self.tls_client_versions = None
        self.tls_server_version = None
        self.http_reqs = []
        self.http_resps = []
        self._seen_seqs_ab = set()
        self._seen_seqs_ba = set()
        self._max_seq_ab = None
        self._max_seq_ba = None
        self._last_ack_a = None
        self._last_ack_a_n = 0
        self._last_ack_b = None
        self._last_ack_b_n = 0


def _conn_key(src, sp, dst, dp):
    """Order-independent 4-tuple key (so both directions map to one conn)."""
    x, y = (src, sp), (dst, dp)
    return (x, y) if x <= y else (y, x)


class _Tracker:
    def __init__(self):
        self.conns = {}      # key -> _Conn
        self.dns = []        # list of dns event dicts
        self.anomalies = []  # global anomaly list
        self.counts = {"total": 0, "ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0,
                       "dns": 0, "arp": 0, "tls": 0, "http": 0, "icmp": 0,
                       "other": 0, "parse_errors": 0}
        self._ts_lo = None
        self._ts_hi = None

    def _note_ts(self, ts):
        if self._ts_lo is None or ts < self._ts_lo:
            self._ts_lo = ts
        if self._ts_hi is None or ts > self._ts_hi:
            self._ts_hi = ts

    def feed(self, ts, l3proto, ip):
        proto = ip["proto"]
        src, dst = ip["src"], ip["dst"]
        if proto == IPPROTO_TCP:
            tcp = _parse_tcp(ip["payload"])
            if tcp:
                self.counts["tcp"] += 1
                self._tcp(ts, src, dst, tcp)
            else:
                self.counts["parse_errors"] += 1
        elif proto == IPPROTO_UDP:
            udp = _parse_udp(ip["payload"])
            if udp:
                self.counts["udp"] += 1
                self._udp(ts, src, dst, udp)
            else:
                self.counts["parse_errors"] += 1
        elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            self.counts["icmp"] += 1
        else:
            self.counts["other"] += 1

    def _udp(self, ts, src, dst, udp):
        if udp["sport"] == 53 or udp["dport"] == 53:
            dns = None
            try:
                dns = _parse_dns(udp["payload"])
            except Exception:
                self.counts["parse_errors"] += 1
            if dns:
                self.counts["dns"] += 1
                ev = {"ts": round(ts, 6),
                      "resolver": (dst if udp["dport"] == 53 else src),
                      "client": (src if udp["dport"] == 53 else dst)}
                if dns["qr"] == 0:
                    ev["kind"] = "query"
                    ev["questions"] = dns["questions"]
                else:
                    ev["kind"] = "response"
                    ev["rcode"] = dns["rcode"]
                    ev["questions"] = dns["questions"]
                    ev["answers"] = dns["answers"]
                self.dns.append(ev)

    def _tcp(self, ts, src, dst, tcp):
        sp, dp = tcp["sport"], tcp["dport"]
        key = _conn_key(src, sp, dst, dp)
        c = self.conns.get(key)
        if c is None:
            # The first packet seen defines "a" (client) heuristically: a pure
            # SYN's sender is the client; otherwise the current src is "a".
            if tcp["syn"] and not tcp["ack_flag"]:
                c = _Conn((src, sp), (dst, dp), ts)
            else:
                c = _Conn((src, sp), (dst, dp), ts)
            self.conns[key] = c
        c.last_ts = ts
        from_a = ((src, sp) == c.a)

        # --- handshake / teardown flags (RFC 793 §3.4, §3.5) ---
        if tcp["syn"] and not tcp["ack_flag"]:
            c.syn = True
            if not from_a:
                # SYN came from the side we tagged as server: re-tag so "a" is
                # always the active opener.
                c.a, c.b = c.b, c.a
                from_a = True
        if tcp["syn"] and tcp["ack_flag"]:
            c.synack = True
        if tcp["ack_flag"] and c.syn and c.synack:
            c.established = True
        if tcp["fin"]:
            if from_a:
                c.fin_a = True
            else:
                c.fin_b = True
        if tcp["rst"]:
            if not c.rst:
                # premature RST before established is the interesting anomaly.
                if not c.established:
                    self.anomalies.append({
                        "type": "premature_rst",
                        "conn": _fmt_endpoints(c),
                        "detail": "RST before connection established"})
            c.rst = True

        # --- zero window (RFC 793 flow control: receiver advertised 0) ---
        if tcp["window"] == 0 and tcp["ack_flag"] and not tcp["rst"]:
            c.zero_window += 1

        # --- payload accounting + retransmit/out-of-order/dup-ACK ---
        plen = len(tcp["payload"])
        seq = tcp["seq"]
        if from_a:
            c.segs_ab += 1
            c.bytes_ab += plen
            if plen > 0:
                if seq in c._seen_seqs_ab:
                    c.retransmits += 1
                else:
                    c._seen_seqs_ab.add(seq)
                    if c._max_seq_ab is not None and seq < c._max_seq_ab:
                        c.out_of_order += 1
                    if c._max_seq_ab is None or seq > c._max_seq_ab:
                        c._max_seq_ab = seq
            self._dup_ack(c, tcp, "a")
        else:
            c.segs_ba += 1
            c.bytes_ba += plen
            if plen > 0:
                if seq in c._seen_seqs_ba:
                    c.retransmits += 1
                else:
                    c._seen_seqs_ba.add(seq)
                    if c._max_seq_ba is not None and seq < c._max_seq_ba:
                        c.out_of_order += 1
                    if c._max_seq_ba is None or seq > c._max_seq_ba:
                        c._max_seq_ba = seq
            self._dup_ack(c, tcp, "b")

        # --- L7 over this segment ---
        if plen > 0:
            self._l7(c, tcp["payload"], from_a)

    def _dup_ack(self, c, tcp, side):
        """Duplicate-ACK heuristic (RFC 5681 §2): same ACK number repeated with
        no new payload is the fast-retransmit trigger and a loss signal."""
        if not tcp["ack_flag"]:
            return
        ackn = tcp["ack"]
        empty = (len(tcp["payload"]) == 0 and not tcp["syn"] and not tcp["fin"])
        if side == "a":
            if empty and ackn == c._last_ack_a:
                c._last_ack_a_n += 1
                if c._last_ack_a_n >= 2:  # 3rd identical ACK = dup-ACK event
                    c.dup_acks += 1
            else:
                c._last_ack_a = ackn
                c._last_ack_a_n = 1 if empty else 0
        else:
            if empty and ackn == c._last_ack_b:
                c._last_ack_b_n += 1
                if c._last_ack_b_n >= 2:
                    c.dup_acks += 1
            else:
                c._last_ack_b = ackn
                c._last_ack_b_n = 1 if empty else 0

    def _l7(self, c, payload, from_a):
        # TLS first (port 443 is the FF real-website path).
        dport = c.b[1] if from_a else c.a[1]
        sport = c.a[1] if from_a else c.b[1]
        looks_tls = (443 in (sport, dport)) or (payload[:1] in (b"\x16", b"\x17",
                                                                b"\x14", b"\x15"))
        if looks_tls:
            try:
                recs = _parse_tls_records(payload)
            except Exception:
                recs = []
            if recs:
                self.counts["tls"] += 1
                for r in recs:
                    hs = r.get("handshake")
                    if hs == "ClientHello":
                        c.tls_client_hello = True
                        c.tls_sni = r.get("sni") or c.tls_sni
                        c.tls_alpn = r.get("alpn") or c.tls_alpn
                        c.tls_client_versions = (r.get("supported_versions")
                                                 or c.tls_client_versions
                                                 or [r.get("legacy_version")])
                    elif hs == "ServerHello":
                        c.tls_server_hello = True
                        sv = r.get("supported_versions")
                        c.tls_server_version = (sv[0] if sv else
                                                r.get("legacy_version"))
                    if r.get("type") == "ApplicationData":
                        # Encrypted app data flowing => handshake completed.
                        if c.tls_server_hello:
                            c.tls_complete = True
                return
        # Cleartext HTTP (port 80 or anything that parses as a request/status).
        try:
            h = _parse_http(payload)
        except Exception:
            h = None
        if h:
            self.counts["http"] += 1
            if h["kind"] == "request":
                c.http_reqs.append({"method": h["method"], "host": h["host"],
                                    "path": h["path"]})
            else:
                c.http_resps.append({"status": h["status"],
                                     "reason": h["reason"]})

    # ----- finalisation: derive per-conn state + global anomalies -----
    def finalize(self):
        conns_out = []
        for c in self.conns.values():
            state = self._infer_state(c)
            # half-open: SYN seen, no SYN-ACK, never established, no RST.
            if c.syn and not c.synack and not c.established and not c.rst:
                self.anomalies.append({
                    "type": "unanswered_syn",
                    "conn": _fmt_endpoints(c),
                    "detail": "SYN sent, no SYN-ACK observed (server silent "
                              "or capture truncated)"})
            if c.established and (c.fin_a ^ c.fin_b) and not c.rst:
                self.anomalies.append({
                    "type": "half_open",
                    "conn": _fmt_endpoints(c),
                    "detail": "one side sent FIN, the other never closed"})
            if c.retransmits:
                self.anomalies.append({
                    "type": "retransmission", "conn": _fmt_endpoints(c),
                    "detail": f"{c.retransmits} retransmitted segment(s)"})
            if c.out_of_order:
                self.anomalies.append({
                    "type": "out_of_order", "conn": _fmt_endpoints(c),
                    "detail": f"{c.out_of_order} out-of-order segment(s)"})
            if c.dup_acks:
                self.anomalies.append({
                    "type": "dup_acks", "conn": _fmt_endpoints(c),
                    "detail": f"{c.dup_acks} duplicate-ACK event(s)"})
            if c.zero_window:
                self.anomalies.append({
                    "type": "zero_window", "conn": _fmt_endpoints(c),
                    "detail": f"receiver advertised zero window "
                              f"{c.zero_window} time(s)"})
            if c.tls_client_hello and not c.tls_server_hello:
                self.anomalies.append({
                    "type": "tls_stalled", "conn": _fmt_endpoints(c),
                    "detail": "ClientHello sent, no ServerHello "
                              f"(SNI={c.tls_sni or '?'})"})
            co = {
                "client": f"{c.a[0]}:{c.a[1]}",
                "server": f"{c.b[0]}:{c.b[1]}",
                "state": state,
                "handshake": {
                    "syn": c.syn, "syn_ack": c.synack,
                    "established": c.established},
                "close": {"fin_client": c.fin_a, "fin_server": c.fin_b,
                          "rst": c.rst},
                "bytes_c2s": c.bytes_ab, "bytes_s2c": c.bytes_ba,
                "segs_c2s": c.segs_ab, "segs_s2c": c.segs_ba,
                "retransmits": c.retransmits, "dup_acks": c.dup_acks,
                "out_of_order": c.out_of_order, "zero_window": c.zero_window,
                "duration_s": round(c.last_ts - c.first_ts, 6),
            }
            if c.tls_client_hello or c.tls_server_hello:
                co["tls"] = {
                    "client_hello": c.tls_client_hello,
                    "server_hello": c.tls_server_hello,
                    "completed": c.tls_complete,
                    "sni": c.tls_sni,
                    "alpn": c.tls_alpn,
                    "client_versions": c.tls_client_versions,
                    "negotiated_version": c.tls_server_version,
                }
            if c.http_reqs or c.http_resps:
                co["http"] = {"requests": c.http_reqs,
                              "responses": c.http_resps}
            conns_out.append(co)
        # Stable, useful ordering: by start time (clients first), most bytes.
        conns_out.sort(key=lambda x: (-(x["bytes_c2s"] + x["bytes_s2c"])))
        return conns_out

    @staticmethod
    def _infer_state(c):
        # RFC 793 §3.2 state inference from observed flags.
        if c.rst:
            return "RESET"
        if c.fin_a and c.fin_b:
            return "CLOSED"
        if c.fin_a or c.fin_b:
            return "CLOSING"
        if c.established:
            return "ESTABLISHED"
        if c.synack:
            return "SYN_RCVD"
        if c.syn:
            return "SYN_SENT"
        return "UNKNOWN"


def _fmt_endpoints(c):
    return f"{c.a[0]}:{c.a[1]} <-> {c.b[0]}:{c.b[1]}"


# ---------------------------------------------------------------------------
# Top-level decode()
# ---------------------------------------------------------------------------
def decode(pcap_path, max_packets=DEFAULT_MAX_PACKETS):
    """Decode a libpcap capture into a JSON-able wire summary.

    Returns a dict:
      { ok, error?, file, file_size, truncated, linktype,
        capture: {packets, duration_s, first_ts, last_ts},
        counts: {...protocol tallies...},
        dns: [ {kind, resolver, client, questions, answers?, rcode?} ],
        connections: [ {client, server, state, handshake, close, bytes_*,
                        retransmits, dup_acks, tls?, http?} ],
        anomalies: [ {type, conn, detail} ] }

    Never raises on a malformed/partial capture: structural problems land in
    `error` with ok=False but a still-usable partial summary; per-packet
    problems are tallied in counts.parse_errors and as anomalies."""
    result = {
        "ok": True, "error": None,
        "file": os.path.basename(pcap_path),
        "file_size": None, "truncated": False, "linktype": None,
        "capture": {"packets": 0, "duration_s": 0.0,
                    "first_ts": None, "last_ts": None},
        "counts": {}, "dns": [], "connections": [], "anomalies": [],
    }
    try:
        result["file_size"] = os.path.getsize(pcap_path)
    except OSError:
        pass

    try:
        f = open(pcap_path, "rb")
    except OSError as e:
        result["ok"] = False
        result["error"] = f"cannot open capture: {e}"
        return result

    tr = _Tracker()
    n = 0
    with f:
        try:
            reader = PcapReader(f)
        except PcapError as e:
            result["ok"] = False
            result["error"] = str(e)
            return result
        result["linktype"] = reader.linktype
        result["snaplen"] = reader.snaplen
        result["pcap_version"] = f"{reader.ver_major}.{reader.ver_minor}"
        for ts, linktype, data, orig_len in reader:
            n += 1
            tr.counts_total = n
            tr._note_ts(ts)
            if n > max_packets:
                tr.anomalies.append({
                    "type": "capture_capped", "conn": "-",
                    "detail": f"stopped after {max_packets} packets "
                              "(file larger; raise --max-packets to see all)"})
                break
            try:
                l3, l3bytes, _eth = _strip_link(linktype, data)
                if l3 == "ipv4":
                    tr.counts["ipv4"] += 1
                    ip = _parse_ipv4(l3bytes)
                elif l3 == "ipv6":
                    tr.counts["ipv6"] += 1
                    ip = _parse_ipv6(l3bytes)
                elif l3 == "arp":
                    tr.counts["arp"] += 1
                    ip = None
                else:
                    tr.counts["other"] += 1
                    ip = None
                if ip and ip.get("payload") is not None:
                    if ip.get("fragmented"):
                        # We don't reassemble IP fragments; note and skip L4.
                        tr.anomalies.append({
                            "type": "ip_fragment", "conn": "-",
                            "detail": f"IP fragment {ip['src']}->{ip['dst']} "
                                      "(L4 not reassembled)"})
                    else:
                        tr.feed(ts, l3, ip)
            except Exception as e:  # never let one bad packet kill the decode
                tr.counts["parse_errors"] += 1
                if len([a for a in tr.anomalies
                        if a["type"] == "parse_error"]) < 5:
                    tr.anomalies.append({
                        "type": "parse_error", "conn": "-",
                        "detail": f"packet #{n}: {type(e).__name__}: {e}"})
        result["truncated"] = reader.truncated

    tr.counts["total"] = n
    result["counts"] = tr.counts
    result["capture"]["packets"] = n
    if tr._ts_lo is not None:
        result["capture"]["first_ts"] = round(tr._ts_lo, 6)
        result["capture"]["last_ts"] = round(tr._ts_hi, 6)
        result["capture"]["duration_s"] = round(tr._ts_hi - tr._ts_lo, 6)
    result["dns"] = tr.dns
    result["connections"] = tr.finalize()
    result["anomalies"] = tr.anomalies
    if result["truncated"]:
        result["anomalies"].insert(0, {
            "type": "capture_in_progress", "conn": "-",
            "detail": "capture appears to be still being written or was "
                      "truncated; final record dropped (this is normal for a "
                      "live filter-dump)"})
    return result


# ---------------------------------------------------------------------------
# decode_pcap() — serial-web /api/wire adapter
# ---------------------------------------------------------------------------
# The serial-web wire panel (scripts/serial-web.py) consumes a flat,
# UI-oriented summary: top-level `packets`/`bytes` counters and four parallel
# arrays — `dns` ({name,type,answer}), `tls` ({sni,version,dst}),
# `http` ({method,host,path}), `flows` ({dst,bytes,pkts}).  The rich decode()
# output is nested (TLS/HTTP live inside each connection), so this adapter
# projects the connection-centric view onto the UI's flat per-event view while
# passing the full structured detail through verbatim (additive keys) so the
# `wire_summary` / Wireshark-equivalent inspection still has handshake state,
# RFC-793 connection state, and the anomaly list.
def decode_pcap(path, max_packets=None):
    """Adapter to the serial-web /api/wire contract.

    Returns a dict whose flat top-level keys (packets, bytes, dns, tls, http,
    flows) drive the dashboard wire panel, and which also carries the full
    decode() detail (connections, anomalies, counts, capture) so the textual
    wire summary is complete.  Never raises on a partial/torn capture."""
    if max_packets is None:
        d = decode(path)
    else:
        d = decode(path, max_packets=max_packets)

    flows, tls, http = [], [], []
    total_bytes = 0
    for c in d.get("connections", []):
        b = int(c.get("bytes_c2s", 0)) + int(c.get("bytes_s2c", 0))
        pk = int(c.get("segs_c2s", 0)) + int(c.get("segs_s2c", 0))
        total_bytes += b
        dst = c.get("server", "?")
        flows.append({
            "dst": dst,
            "src": c.get("client", "?"),
            "bytes": b,
            "pkts": pk,
            "state": c.get("state", "?"),
        })
        t = c.get("tls")
        if t:
            # RFC 8446 §4.1.2 ClientHello / RFC 6066 §3 SNI.  Surface the SNI,
            # the negotiated (or, if the handshake stalled, the offered) TLS
            # version, and the server endpoint the ClientHello targeted.
            ver = t.get("negotiated_version") or (
                (t.get("client_versions") or ["?"])[0])
            tls.append({
                "sni": t.get("sni") or "(no SNI)",
                "version": ver,
                "dst": dst,
                "alpn": t.get("alpn") or [],
                "completed": bool(t.get("completed")),
            })
        h = c.get("http")
        if h:
            # RFC 9110 §9 request lines.  decode() stores each request as
            # {method, host, path}; surface them as the UI's method/host/path
            # columns (host falls back to the connection's server endpoint when
            # the request carried no Host header, e.g. cleartext HTTP/1.0).
            for req in (h.get("requests") or []):
                if isinstance(req, dict):
                    http.append({
                        "method": req.get("method", "?"),
                        "host": req.get("host") or dst,
                        "path": req.get("path", "/"),
                    })
                else:
                    method, host, pth = _split_http_req(req)
                    http.append({"method": method, "host": host or dst,
                                 "path": pth})

    dns_out = []
    for ev in d.get("dns", []):
        # RFC 1035 §4.1.  One UI row per question, annotated with the first
        # answer (if this is a response) so DNS A/AAAA results are visible.
        qs = ev.get("questions") or []
        ans = ev.get("answers") or []
        first_answer = None
        for a in ans:
            if isinstance(a, dict) and a.get("data"):
                first_answer = a.get("data")
                break
        if not qs:
            dns_out.append({"name": "?", "type": ev.get("kind", "?"),
                            "answer": first_answer})
        for q in qs:
            qname = q.get("name") if isinstance(q, dict) else str(q)
            qtype = q.get("type") if isinstance(q, dict) else "?"
            dns_out.append({
                "name": qname,
                "type": qtype if ev.get("kind") == "query"
                        else (qtype),
                "kind": ev.get("kind"),
                "answer": first_answer,
            })

    out = dict(d)  # pass full structured detail through (connections, etc.)
    out["packets"] = d.get("capture", {}).get("packets", 0)
    out["bytes"] = total_bytes
    out["dns"] = dns_out
    out["tls"] = tls
    out["http"] = http
    out["flows"] = flows
    return out


def _split_http_req(req):
    """Best-effort split of a raw HTTP request line into (method, host, path).

    `req` is typically a request-line string like "GET /index.html HTTP/1.1"
    optionally with a Host: captured.  Returns ('?', None, raw) when it cannot
    be parsed — never raises (RFC 9110 §9 request line syntax)."""
    try:
        s = req if isinstance(req, str) else str(req)
        parts = s.split()
        if len(parts) >= 2 and parts[0].isupper():
            return parts[0], None, parts[1]
        return "?", None, s
    except Exception:
        return "?", None, str(req)


# ---------------------------------------------------------------------------
# Self-test: craft a tiny synthetic pcap (DNS query + TLS ClientHello) and
# decode it, asserting the structured summary comes out. No external file.
# ---------------------------------------------------------------------------
def _u16(v):
    return struct.pack(">H", v)


def _build_eth_ipv4(src_ip, dst_ip, proto, l4):
    ip_hdr = bytearray(20)
    ip_hdr[0] = 0x45
    total = 20 + len(l4)
    ip_hdr[2:4] = _u16(total)
    ip_hdr[8] = 64
    ip_hdr[9] = proto
    ip_hdr[12:16] = bytes(int(x) for x in src_ip.split("."))
    ip_hdr[16:20] = bytes(int(x) for x in dst_ip.split("."))
    eth = (b"\x52\x55\x0a\x00\x02\x02" + b"\x52\x54\x00\x12\x34\x56"
           + _u16(ETH_P_IPV4))
    return eth + bytes(ip_hdr) + l4


def _build_udp(sp, dp, payload):
    return _u16(sp) + _u16(dp) + _u16(8 + len(payload)) + _u16(0) + payload


def _build_tcp(sp, dp, seq, ack, flags, payload=b"", window=64240):
    hdr = bytearray(20)
    hdr[0:2] = _u16(sp)
    hdr[2:4] = _u16(dp)
    hdr[4:8] = struct.pack(">I", seq)
    hdr[8:12] = struct.pack(">I", ack)
    hdr[12] = 0x50  # data offset = 5 words
    hdr[13] = flags
    hdr[14:16] = _u16(window)
    return bytes(hdr) + payload


def _build_dns_query(name="example.com"):
    q = bytearray()
    q += _u16(0x1234) + _u16(0x0100) + _u16(1) + _u16(0) + _u16(0) + _u16(0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + _u16(1) + _u16(1)  # type A, class IN
    return bytes(q)


def _build_client_hello(sni="example.com"):
    # Minimal but spec-shaped TLS record -> handshake -> ClientHello with SNI.
    server_name = sni.encode()
    sni_entry = b"\x00" + _u16(len(server_name)) + server_name  # host_name
    sni_list = _u16(len(sni_entry)) + sni_entry
    ext_sni = _u16(0) + _u16(len(sni_list)) + sni_list
    alpn_protos = b"\x02h2\x08http/1.1"
    alpn = _u16(len(alpn_protos)) + alpn_protos
    ext_alpn = _u16(16) + _u16(len(alpn)) + alpn
    exts = ext_sni + ext_alpn
    body = bytearray()
    body += _u16(0x0303)          # legacy_version TLS1.2
    body += b"\x00" * 32          # random
    body += b"\x00"               # session_id len 0
    body += _u16(2) + _u16(0x1301)  # cipher_suites: TLS_AES_128_GCM_SHA256
    body += b"\x01\x00"           # compression: null
    body += _u16(len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + bytes(body)
    rec = b"\x16" + _u16(0x0303) + _u16(len(hs)) + hs
    return rec


def _write_pcap(records, linktype=LINKTYPE_ETHERNET):
    """records: list of (ts_sec, ts_usec, frame_bytes). Returns pcap bytes."""
    out = io.BytesIO()
    out.write(struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0,
                          65535, linktype))
    for ts_sec, ts_usec, frame in records:
        out.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
        out.write(frame)
    return out.getvalue()


def _selftest():
    import tempfile
    cli = "10.0.2.15"
    res = "10.0.2.3"
    srv = "93.184.216.34"
    frames = []
    # 1. DNS query example.com -> resolver
    frames.append((1, 0, _build_eth_ipv4(cli, res, IPPROTO_UDP,
                   _build_udp(40000, 53, _build_dns_query("example.com")))))
    # 2. DNS response with an A record
    dns_resp = bytearray()
    dns_resp += _u16(0x1234) + _u16(0x8180) + _u16(1) + _u16(1) + _u16(0) + _u16(0)
    for label in "example.com".split("."):
        dns_resp += bytes([len(label)]) + label.encode()
    dns_resp += b"\x00" + _u16(1) + _u16(1)
    dns_resp += b"\xc0\x0c" + _u16(1) + _u16(1) + struct.pack(">I", 300)
    dns_resp += _u16(4) + bytes(int(x) for x in srv.split("."))
    frames.append((1, 5000, _build_eth_ipv4(res, cli, IPPROTO_UDP,
                   _build_udp(53, 40000, bytes(dns_resp)))))
    # 3. TCP SYN cli->srv:443
    frames.append((1, 10000, _build_eth_ipv4(cli, srv, IPPROTO_TCP,
                   _build_tcp(50000, 443, 1000, 0, 0x02))))
    # 4. SYN-ACK srv->cli
    frames.append((1, 12000, _build_eth_ipv4(srv, cli, IPPROTO_TCP,
                   _build_tcp(443, 50000, 9000, 1001, 0x12))))
    # 5. ACK cli->srv
    frames.append((1, 13000, _build_eth_ipv4(cli, srv, IPPROTO_TCP,
                   _build_tcp(50000, 443, 1001, 9001, 0x10))))
    # 6. TLS ClientHello cli->srv
    ch = _build_client_hello("example.com")
    frames.append((1, 14000, _build_eth_ipv4(cli, srv, IPPROTO_TCP,
                   _build_tcp(50000, 443, 1001, 9001, 0x18, ch))))
    # 7. ServerHello (minimal) srv->cli
    sh_body = bytearray()
    sh_body += _u16(0x0303) + b"\x00" * 32 + b"\x00"
    sh_body += _u16(0x1301) + b"\x00"
    sh_body += _u16(0)  # no extensions
    sh_hs = b"\x02" + struct.pack(">I", len(sh_body))[1:] + bytes(sh_body)
    sh_rec = b"\x16" + _u16(0x0303) + _u16(len(sh_hs)) + sh_hs
    frames.append((1, 16000, _build_eth_ipv4(srv, cli, IPPROTO_TCP,
                   _build_tcp(443, 50000, 9001, 1001 + len(ch), 0x18, sh_rec))))
    # 8. Application data srv->cli (=> handshake complete)
    appdata = b"\x17\x03\x03" + _u16(32) + b"\xaa" * 32
    frames.append((1, 18000, _build_eth_ipv4(srv, cli, IPPROTO_TCP,
                   _build_tcp(443, 50000, 9001 + len(sh_rec), 1001 + len(ch),
                              0x18, appdata))))
    # 9. A retransmit of the ClientHello segment (same seq + payload) -> anomaly
    frames.append((1, 20000, _build_eth_ipv4(cli, srv, IPPROTO_TCP,
                   _build_tcp(50000, 443, 1001, 9001, 0x18, ch))))
    # 10. FIN both ways
    frames.append((1, 22000, _build_eth_ipv4(cli, srv, IPPROTO_TCP,
                   _build_tcp(50000, 443, 9999, 9001, 0x11))))
    frames.append((1, 23000, _build_eth_ipv4(srv, cli, IPPROTO_TCP,
                   _build_tcp(443, 50000, 9001, 10000, 0x11))))

    pcap = _write_pcap(frames)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        tf.write(pcap)
        path = tf.name
    try:
        summary = decode(path)
    finally:
        os.unlink(path)

    # Assertions: prove the structured summary captured the wire facts.
    errs = []
    if not summary["ok"]:
        errs.append(f"ok=False: {summary['error']}")
    if summary["capture"]["packets"] != len(frames):
        errs.append(f"packet count {summary['capture']['packets']} != "
                    f"{len(frames)}")
    qnames = [q["name"] for ev in summary["dns"]
              for q in ev.get("questions", [])]
    if "example.com" not in qnames:
        errs.append("DNS query name example.com not found")
    answers = [a["data"] for ev in summary["dns"] for a in ev.get("answers", [])]
    if srv not in answers:
        errs.append(f"DNS A answer {srv} not found (got {answers})")
    if len(summary["connections"]) != 1:
        errs.append(f"expected 1 TCP connection, got "
                    f"{len(summary['connections'])}")
    else:
        conn = summary["connections"][0]
        if not conn["handshake"]["established"]:
            errs.append("TCP handshake not marked established")
        tls = conn.get("tls", {})
        if tls.get("sni") != "example.com":
            errs.append(f"TLS SNI not parsed (got {tls.get('sni')})")
        if tls.get("alpn") != ["h2", "http/1.1"]:
            errs.append(f"TLS ALPN not parsed (got {tls.get('alpn')})")
        if not tls.get("server_hello"):
            errs.append("ServerHello not detected")
        if not tls.get("completed"):
            errs.append("TLS handshake not marked completed")
        if conn["retransmits"] < 1:
            errs.append("retransmit not detected")
        if conn["state"] != "CLOSED":
            errs.append(f"TCP state expected CLOSED, got {conn['state']}")
    atypes = {a["type"] for a in summary["anomalies"]}
    if "retransmission" not in atypes:
        errs.append("retransmission anomaly missing")

    print(json.dumps(summary, indent=2))
    if errs:
        print("\nSELFTEST FAILED:", file=sys.stderr)
        for e in errs:
            print("  -", e, file=sys.stderr)
        return 1
    print("\nSELFTEST PASSED: all wire facts decoded "
          f"({len(frames)} packets, 1 TCP conn, DNS A, TLS SNI/ALPN, "
          "retransmit, CLOSED).", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decode a libpcap capture into a wire summary (JSON).")
    ap.add_argument("pcap", nargs="?", help="path to a .pcap capture")
    ap.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS,
                    help="cap packets processed (default %(default)s)")
    ap.add_argument("--pretty", action="store_true",
                    help="indent the JSON output")
    ap.add_argument("--selftest", action="store_true",
                    help="craft + decode a synthetic pcap, assert, exit")
    args = ap.parse_args(argv)
    if args.selftest:
        return _selftest()
    if not args.pcap:
        ap.error("a pcap path is required (or use --selftest)")
    summary = decode(args.pcap, max_packets=args.max_packets)
    print(json.dumps(summary, indent=2 if args.pretty else None))
    return 0 if summary["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
