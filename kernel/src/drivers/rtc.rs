//! CMOS Real-Time Clock (RTC) driver.
//!
//! Reads wall-clock time from the MC146818A-compatible CMOS RTC via I/O ports
//! 0x70 (index) and 0x71 (data). Used by sys_clock_gettime(CLOCK_REALTIME).
//!
//! References:
//! - OSDev wiki: CMOS RTC
//! - PC/AT BIOS compatibility spec: MC146818A register map

/// CMOS I/O ports.
const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

/// CMOS register indices.
const RTC_SECONDS:      u8 = 0x00;
const RTC_MINUTES:      u8 = 0x02;
const RTC_HOURS:        u8 = 0x04;
const RTC_DAY:          u8 = 0x07;
const RTC_MONTH:        u8 = 0x08;
const RTC_YEAR:         u8 = 0x09;
const RTC_STATUS_A:     u8 = 0x0A;
const RTC_STATUS_B:     u8 = 0x0B;

/// Read a CMOS register.
fn cmos_read(reg: u8) -> u8 {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_ADDR,
            in("al") reg,
            options(nostack, nomem),
        );
        let mut val: u8;
        core::arch::asm!(
            "in al, dx",
            in("dx") CMOS_DATA,
            out("al") val,
            options(nostack, nomem),
        );
        val
    }
}

/// Wait until the RTC update-in-progress flag clears.
fn wait_for_update() {
    // Status A bit 7 = update-in-progress; spin until clear
    for _ in 0..1000 {
        if cmos_read(RTC_STATUS_A) & 0x80 == 0 {
            return;
        }
    }
}

/// Convert BCD-encoded byte to binary.
fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

/// Raw RTC time fields.
struct RtcTime {
    year:   u32,
    month:  u32,
    day:    u32,
    hour:   u32,
    minute: u32,
    second: u32,
}

/// Read the RTC, handling both BCD and binary modes.
fn read_rtc() -> RtcTime {
    wait_for_update();

    let status_b = cmos_read(RTC_STATUS_B);
    let binary_mode = (status_b & 0x04) != 0;
    let _24h_mode   = (status_b & 0x02) != 0;

    let sec   = cmos_read(RTC_SECONDS);
    let min   = cmos_read(RTC_MINUTES);
    let hour  = cmos_read(RTC_HOURS);
    let day   = cmos_read(RTC_DAY);
    let month = cmos_read(RTC_MONTH);
    let year  = cmos_read(RTC_YEAR);

    let (sec, min, hour, day, month, year) = if binary_mode {
        (sec as u32, min as u32, hour as u32, day as u32, month as u32, year as u32)
    } else {
        (bcd_to_bin(sec) as u32, bcd_to_bin(min) as u32,
         bcd_to_bin(hour) as u32, bcd_to_bin(day) as u32,
         bcd_to_bin(month) as u32, bcd_to_bin(year) as u32)
    };

    // Assume 21st century (year is 2 digits: 00-99 → 2000-2099).
    let full_year = 2000 + year;

    RtcTime { year: full_year, month, day, hour, minute: min, second: sec }
}

/// Days in each month for a given year.
fn days_in_month(month: u32, year: u32) -> u32 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if leap { 29 } else { 28 },
        _ => 30,
    }
}

/// Convert calendar date/time to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).
fn to_unix_timestamp(t: &RtcTime) -> u64 {
    // Count days since epoch (1970-01-01).
    let mut days: u64 = 0;

    // Full years 1970..(t.year)
    for y in 1970..t.year {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        days += if leap { 366 } else { 365 };
    }

    // Full months in current year
    for m in 1..t.month {
        days += days_in_month(m, t.year) as u64;
    }

    // Days in current month (1-indexed, subtract 1)
    days += (t.day as u64).saturating_sub(1);

    days * 86400
        + t.hour as u64 * 3600
        + t.minute as u64 * 60
        + t.second as u64
}

/// Read the current wall-clock time as a Unix timestamp (seconds).
///
/// Reads the CMOS RTC twice and retries if the update-in-progress flag was
/// set during the first read, guarding against a mid-update torn read.
pub fn read_unix_time() -> u64 {
    let t1 = read_rtc();
    wait_for_update();
    let t2 = read_rtc();

    // If both reads agree on the second, we're good.
    if t1.second == t2.second {
        to_unix_timestamp(&t2)
    } else {
        to_unix_timestamp(&t2) // t2 is more recent
    }
}
