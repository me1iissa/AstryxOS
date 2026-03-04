//! NT Advanced Local Procedure Call (ALPC) — High-Performance IPC
//!
//! Inspired by the Windows NT LPC/ALPC mechanism (ntoskrnl/lpc/, ntoskrnl/alpc/).
//! Provides fast message-passing between kernel subsystems with support for
//! request/reply semantics, connection handshake, datagrams, and shared views.
//!
//! # Architecture
//! - `PortMessage` — legacy message header + data payload (backward compat)
//! - `AlpcMessage` — enhanced message with ID, type, source tracking
//! - `ConnectionPort` — server endpoint that accepts connections
//! - `CommunicationChannel` — established bidirectional message channel
//! - `AlpcView` — shared memory region attached to a channel
//!
//! # ALPC Enhancements over basic LPC
//! - Unique message IDs via global atomic counter
//! - Request/reply correlation with `msg_id`
//! - Server accept/reject connection handshake
//! - Datagram (one-way, fire-and-forget) messages
//! - View/section support (shared memory stub)
//! - Port security via optional SecurityDescriptor
//! - Ports registered in OB namespace under `\ALPC\<name>`

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::security::SecurityDescriptor;

/// Maximum ALPC message data size (bytes).
const MAX_MESSAGE_SIZE: usize = 256;
/// Maximum pending messages per channel.
const MAX_QUEUED_MSGS: usize = 16;
/// Maximum pending connection requests per port.
const MAX_PENDING_CONNECTIONS: usize = 8;

// ============================================================================
// ALPC Message Types
// ============================================================================

/// ALPC message type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpcMessageType {
    /// Request expecting a reply.
    Request,
    /// Reply to a previous request.
    Reply,
    /// One-way datagram, no reply expected.
    Datagram,
    /// Connection request from client to server port.
    ConnectionRequest,
    /// Connection reply (accept/reject) from server.
    ConnectionReply,
}

// ============================================================================
// ALPC Message
// ============================================================================

/// Enhanced ALPC message with unique ID and source tracking.
#[derive(Clone)]
pub struct AlpcMessage {
    /// Unique message ID (auto-incremented).
    pub msg_id: u64,
    /// Message type (request, reply, datagram, etc.).
    pub msg_type: AlpcMessageType,
    /// Source process ID.
    pub source_pid: u64,
    /// Source port handle/ID.
    pub source_port: u32,
    /// For Reply messages, the msg_id this is replying to.
    pub reply_to: u64,
    /// Message data payload (up to MAX_MESSAGE_SIZE).
    pub data: Vec<u8>,
}

/// Global atomic counter for unique message IDs.
static NEXT_MSG_ID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Allocate the next unique message ID.
pub fn next_message_id() -> u64 {
    NEXT_MSG_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

// ============================================================================
// ALPC View — Shared Memory (Stub)
// ============================================================================

/// Shared memory view attached to an ALPC channel.
///
/// Allows server and client to share a memory region for large data
/// transfers without copying through the message queue.
#[derive(Clone, Debug)]
pub struct AlpcView {
    /// Physical base address of the shared memory region.
    pub phys_base: u64,
    /// Size of the shared region in bytes.
    pub size: usize,
    /// Virtual address mapped in the server process.
    pub server_vaddr: u64,
    /// Virtual address mapped in the client process.
    pub client_vaddr: u64,
}

// ============================================================================
// Legacy PortMessage (backward compatibility)
// ============================================================================

/// LPC port message (legacy format, kept for backward compatibility).
#[derive(Clone)]
pub struct PortMessage {
    /// Message type (application-defined).
    pub msg_type: u32,
    /// Source port ID.
    pub source_port: u32,
    /// Message data.
    pub data: Vec<u8>,
}

// ============================================================================
// Connection Port
// ============================================================================

/// Pending connection request waiting for server accept/reject.
struct PendingConnection {
    /// The connection request message (contains client info).
    request: AlpcMessage,
    /// Client-provided port ID.
    client_port: u32,
}

/// Connection port — server endpoint that listens for connections.
struct ConnectionPort {
    name: String,
    port_id: u32,
    /// Legacy pending connections (client port IDs).
    pending_connections: VecDeque<u32>,
    /// ALPC pending connection requests awaiting accept/reject.
    pending_alpc_connections: VecDeque<PendingConnection>,
    /// Optional security descriptor controlling who can connect.
    security_descriptor: Option<SecurityDescriptor>,
}

// ============================================================================
// Communication Channel
// ============================================================================

/// Communication channel — established bidirectional link.
struct CommunicationChannel {
    channel_id: u32,
    server_port: u32,
    client_port: u32,
    /// Legacy server→client queue.
    server_queue: VecDeque<PortMessage>,
    /// Legacy client→server queue.
    client_queue: VecDeque<PortMessage>,
    /// ALPC server→client message queue.
    alpc_server_queue: VecDeque<AlpcMessage>,
    /// ALPC client→server message queue.
    alpc_client_queue: VecDeque<AlpcMessage>,
    /// Optional shared memory view.
    view: Option<AlpcView>,
}

// ============================================================================
// Global State
// ============================================================================

/// Next port/channel ID.
static NEXT_PORT_ID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

/// All connection ports.
static PORTS: Mutex<Vec<ConnectionPort>> = Mutex::new(Vec::new());
/// All communication channels.
static CHANNELS: Mutex<Vec<CommunicationChannel>> = Mutex::new(Vec::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the LPC/ALPC subsystem.
pub fn init() {
    // Create well-known ports (also registered in OB namespace)
    create_port("\\LPC\\ApiPort");
    create_port("\\LPC\\SbApiPort");
    create_port("\\LPC\\DbgSsApiPort");

    crate::serial_println!("[LPC] Advanced Local Procedure Call (ALPC) subsystem initialized");
}

// ============================================================================
// Port Management
// ============================================================================

/// Create a named connection port. Returns port ID.
///
/// The port is also registered in the OB namespace under `\ALPC\<name>`.
pub fn create_port(name: &str) -> u32 {
    let id = NEXT_PORT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    PORTS.lock().push(ConnectionPort {
        name: String::from(name),
        port_id: id,
        pending_connections: VecDeque::new(),
        pending_alpc_connections: VecDeque::new(),
        security_descriptor: None,
    });

    // Register in OB namespace
    let ob_path = if name.starts_with('\\') {
        // If already an absolute path like \ALPC\CsrApiPort, use directly
        String::from(name)
    } else {
        alloc::format!("\\ALPC\\{}", name)
    };
    crate::ob::insert_object(&ob_path, crate::ob::ObjectType::Port);

    id
}

/// Create a named connection port with a security descriptor.
pub fn create_port_with_security(name: &str, sd: Option<SecurityDescriptor>) -> u32 {
    let id = NEXT_PORT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    PORTS.lock().push(ConnectionPort {
        name: String::from(name),
        port_id: id,
        pending_connections: VecDeque::new(),
        pending_alpc_connections: VecDeque::new(),
        security_descriptor: sd.clone(),
    });

    // Register in OB namespace with security descriptor
    let ob_path = if name.starts_with('\\') {
        String::from(name)
    } else {
        alloc::format!("\\ALPC\\{}", name)
    };
    crate::ob::insert_object_with_sd(&ob_path, crate::ob::ObjectType::Port, sd);

    id
}

/// Get the security descriptor of a port, if any.
pub fn get_port_security(port_id: u32) -> Option<SecurityDescriptor> {
    let ports = PORTS.lock();
    ports.iter()
        .find(|p| p.port_id == port_id)
        .and_then(|p| p.security_descriptor.clone())
}

/// Look up a port ID by name.
pub fn find_port(name: &str) -> Option<u32> {
    let ports = PORTS.lock();
    ports.iter().find(|p| p.name == name).map(|p| p.port_id)
}

// ============================================================================
// Legacy Connection (backward compatible)
// ============================================================================

/// Connect to a named port (legacy, auto-accept). Returns a channel ID on success.
pub fn connect(port_name: &str) -> Option<u32> {
    let client_port = NEXT_PORT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut ports = PORTS.lock();

    let port = ports.iter_mut().find(|p| p.name == port_name)?;
    let server_port = port.port_id;

    let channel_id = NEXT_PORT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let mut channels = CHANNELS.lock();
    channels.push(CommunicationChannel {
        channel_id,
        server_port,
        client_port,
        server_queue: VecDeque::new(),
        client_queue: VecDeque::new(),
        alpc_server_queue: VecDeque::new(),
        alpc_client_queue: VecDeque::new(),
        view: None,
    });

    Some(channel_id)
}

// ============================================================================
// ALPC Connection Handshake
// ============================================================================

/// Send a connection request to a named port (ALPC handshake).
///
/// The request is queued on the server's pending connection list.
/// The server must call `accept_connection` to complete the handshake.
/// Returns the msg_id of the connection request.
pub fn connect_request(port_name: &str, source_pid: u64, data: &[u8]) -> Option<u64> {
    let client_port = NEXT_PORT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let msg_id = next_message_id();

    let mut ports = PORTS.lock();
    let port = ports.iter_mut().find(|p| p.name == port_name)?;

    if port.pending_alpc_connections.len() >= MAX_PENDING_CONNECTIONS {
        return None; // Too many pending connections
    }

    let request = AlpcMessage {
        msg_id,
        msg_type: AlpcMessageType::ConnectionRequest,
        source_pid,
        source_port: client_port,
        reply_to: 0,
        data: Vec::from(data),
    };

    port.pending_alpc_connections.push_back(PendingConnection {
        request,
        client_port,
    });

    Some(msg_id)
}

/// Listen on a port for the next pending connection request.
///
/// Returns the connection request message if one is queued, or None.
pub fn listen_port(port_id: u32) -> Option<AlpcMessage> {
    let ports = PORTS.lock();
    let port = ports.iter().find(|p| p.port_id == port_id)?;
    port.pending_alpc_connections.front().map(|pc| pc.request.clone())
}

/// Accept or reject a pending connection on a port.
///
/// `conn_msg_id`: The msg_id of the ConnectionRequest to accept/reject.
/// `accept`: true to accept, false to reject.
///
/// Returns the new channel ID if accepted, or None if rejected or not found.
pub fn accept_connection(port_id: u32, conn_msg_id: u64, accept: bool) -> Option<u32> {
    let mut ports = PORTS.lock();
    let port = ports.iter_mut().find(|p| p.port_id == port_id)?;

    // Find the pending connection with the matching msg_id
    let idx = port.pending_alpc_connections.iter()
        .position(|pc| pc.request.msg_id == conn_msg_id)?;

    let pending = port.pending_alpc_connections.remove(idx)?;

    if !accept {
        return None; // Connection rejected
    }

    // Create a communication channel
    let channel_id = NEXT_PORT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut channels = CHANNELS.lock();
    channels.push(CommunicationChannel {
        channel_id,
        server_port: port.port_id,
        client_port: pending.client_port,
        server_queue: VecDeque::new(),
        client_queue: VecDeque::new(),
        alpc_server_queue: VecDeque::new(),
        alpc_client_queue: VecDeque::new(),
        view: None,
    });

    Some(channel_id)
}

// ============================================================================
// ALPC Request/Reply
// ============================================================================

/// Send a request message on a channel. Returns the msg_id.
///
/// The server should eventually call `send_reply` with this msg_id.
pub fn send_request(channel_id: u32, data: &[u8]) -> Option<u64> {
    let msg_id = next_message_id();
    let mut channels = CHANNELS.lock();
    let ch = channels.iter_mut().find(|c| c.channel_id == channel_id)?;

    if ch.alpc_server_queue.len() >= MAX_QUEUED_MSGS {
        return None; // Queue full
    }

    let msg = AlpcMessage {
        msg_id,
        msg_type: AlpcMessageType::Request,
        source_pid: 0, // caller can set if needed
        source_port: ch.client_port,
        reply_to: 0,
        data: Vec::from(data),
    };

    ch.alpc_server_queue.push_back(msg);
    Some(msg_id)
}

/// Wait for a reply to a specific request message on a channel.
///
/// Searches the client queue for a Reply message whose `reply_to` matches `msg_id`.
/// Returns the reply data if found, or None if not yet available.
pub fn wait_reply(channel_id: u32, msg_id: u64) -> Option<Vec<u8>> {
    let mut channels = CHANNELS.lock();
    let ch = channels.iter_mut().find(|c| c.channel_id == channel_id)?;

    // Search for a reply to our msg_id
    let idx = ch.alpc_client_queue.iter()
        .position(|m| m.msg_type == AlpcMessageType::Reply && m.reply_to == msg_id)?;

    let reply = ch.alpc_client_queue.remove(idx)?;
    Some(reply.data)
}

/// Send a reply to a previous request on a channel.
///
/// `reply_to_msg_id`: The msg_id of the Request message being answered.
pub fn send_reply(channel_id: u32, reply_to_msg_id: u64, data: &[u8]) -> bool {
    let msg_id = next_message_id();
    let mut channels = CHANNELS.lock();
    let ch = match channels.iter_mut().find(|c| c.channel_id == channel_id) {
        Some(c) => c,
        None => return false,
    };

    if ch.alpc_client_queue.len() >= MAX_QUEUED_MSGS {
        return false; // Queue full
    }

    let msg = AlpcMessage {
        msg_id,
        msg_type: AlpcMessageType::Reply,
        source_pid: 0,
        source_port: ch.server_port,
        reply_to: reply_to_msg_id,
        data: Vec::from(data),
    };

    ch.alpc_client_queue.push_back(msg);
    true
}

/// Send a one-way datagram on a channel (no reply expected).
pub fn send_datagram(channel_id: u32, data: &[u8]) -> bool {
    let msg_id = next_message_id();
    let mut channels = CHANNELS.lock();
    let ch = match channels.iter_mut().find(|c| c.channel_id == channel_id) {
        Some(c) => c,
        None => return false,
    };

    if ch.alpc_server_queue.len() >= MAX_QUEUED_MSGS {
        return false;
    }

    let msg = AlpcMessage {
        msg_id,
        msg_type: AlpcMessageType::Datagram,
        source_pid: 0,
        source_port: ch.client_port,
        reply_to: 0,
        data: Vec::from(data),
    };

    ch.alpc_server_queue.push_back(msg);
    true
}

/// Receive the next ALPC message from a channel's server queue.
///
/// This is used by the server to receive requests and datagrams.
pub fn recv_alpc_message(channel_id: u32) -> Option<AlpcMessage> {
    let mut channels = CHANNELS.lock();
    let ch = channels.iter_mut().find(|c| c.channel_id == channel_id)?;
    ch.alpc_server_queue.pop_front()
}

// ============================================================================
// ALPC View Management
// ============================================================================

/// Attach a shared memory view to a channel.
pub fn attach_view(channel_id: u32, view: AlpcView) -> bool {
    let mut channels = CHANNELS.lock();
    let ch = match channels.iter_mut().find(|c| c.channel_id == channel_id) {
        Some(c) => c,
        None => return false,
    };
    ch.view = Some(view);
    true
}

/// Get a clone of the view attached to a channel, if any.
pub fn get_view(channel_id: u32) -> Option<AlpcView> {
    let channels = CHANNELS.lock();
    let ch = channels.iter().find(|c| c.channel_id == channel_id)?;
    ch.view.clone()
}

// ============================================================================
// Legacy Message API (backward compatible)
// ============================================================================

/// Send a message on a channel (legacy PortMessage API).
pub fn send_message(channel_id: u32, msg: PortMessage, to_server: bool) -> bool {
    let mut channels = CHANNELS.lock();
    if let Some(ch) = channels.iter_mut().find(|c| c.channel_id == channel_id) {
        let queue = if to_server { &mut ch.server_queue } else { &mut ch.client_queue };
        if queue.len() >= MAX_QUEUED_MSGS {
            return false; // Queue full
        }
        queue.push_back(msg);
        true
    } else {
        false
    }
}

/// Receive a message from a channel (legacy PortMessage API).
pub fn recv_message(channel_id: u32, from_server: bool) -> Option<PortMessage> {
    let mut channels = CHANNELS.lock();
    if let Some(ch) = channels.iter_mut().find(|c| c.channel_id == channel_id) {
        let queue = if from_server { &mut ch.server_queue } else { &mut ch.client_queue };
        queue.pop_front()
    } else {
        None
    }
}

// ============================================================================
// Diagnostics
// ============================================================================

/// List all registered ports (for diagnostics).
pub fn list_ports() -> Vec<(u32, String)> {
    PORTS.lock().iter().map(|p| (p.port_id, p.name.clone())).collect()
}

/// Get channel count.
pub fn channel_count() -> usize {
    CHANNELS.lock().len()
}

/// Get port count.
pub fn port_count() -> usize {
    PORTS.lock().len()
}
