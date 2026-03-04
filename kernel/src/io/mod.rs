//! I/O Subsystem — NT-Inspired I/O Manager with IRP Model
//!
//! Provides the I/O Request Packet (IRP) model, driver/device object
//! management, and dispatch infrastructure inspired by the NT I/O Manager
//! (ntoskrnl/io/).
//!
//! # Architecture
//! - **IRP** — Describes a single I/O request (read, write, create, control, …).
//! - **DriverObject** — Represents a loaded driver with a dispatch table.
//! - **DeviceObject** — Represents a device created by a driver.
//! - **IoManager** — Central registry of drivers and devices.
//!
//! Built-in drivers registered at init time:
//! - `\Driver\Null` → `\Device\Null`
//! - `\Driver\Console` → `\Device\Console`
//! - `\Driver\Serial` → `\Device\Serial0`
//! - `\Driver\E1000` → `\Device\E1000`

pub mod devmgr;
pub mod completion;
pub mod async_io;

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use astryx_shared::ntstatus::*;
use spin::Mutex;

// ============================================================================
// IRP Major Function Codes
// ============================================================================

/// Major function code identifying the type of I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IrpMajorFunction {
    Create           = 0,  // IRP_MJ_CREATE
    Close            = 1,  // IRP_MJ_CLOSE
    Read             = 2,  // IRP_MJ_READ
    Write            = 3,  // IRP_MJ_WRITE
    DeviceControl    = 4,  // IRP_MJ_DEVICE_CONTROL
    QueryInformation = 5,  // IRP_MJ_QUERY_INFORMATION
    SetInformation   = 6,  // IRP_MJ_SET_INFORMATION
    Cleanup          = 7,  // IRP_MJ_CLEANUP
    Shutdown         = 8,  // IRP_MJ_SHUTDOWN
}

/// Number of major function slots in a dispatch table.
const IRP_MJ_COUNT: usize = 9;

// ============================================================================
// IRP Parameters
// ============================================================================

/// Type-specific parameters carried in an IRP.
#[derive(Debug)]
pub enum IrpParameters {
    Create { desired_access: u32, share_access: u32 },
    Read { length: usize, offset: u64 },
    Write { length: usize, offset: u64 },
    DeviceControl { ioctl_code: u32, input_len: usize, output_len: usize },
    None,
}

// ============================================================================
// I/O Request Packet (IRP)
// ============================================================================

/// An I/O Request Packet — the central data structure for I/O operations.
#[derive(Debug)]
pub struct Irp {
    /// Which driver entry point to call.
    pub major_function: IrpMajorFunction,
    /// Sub-function code (driver-specific).
    pub minor_function: u8,
    /// Target device name (e.g. `\Device\Null`).
    pub device_name: String,
    /// Completion status set by the driver.
    pub status: NtStatus,
    /// Extra information (bytes transferred, etc.).
    pub information: u64,
    /// Optional buffered I/O data.
    pub system_buffer: Option<Vec<u8>>,
    /// User-space buffer pointer (for direct I/O).
    pub user_buffer: u64,
    /// Type-specific parameters.
    pub parameters: IrpParameters,
}

impl Irp {
    /// Create a new IRP for the given device and major function.
    pub fn new(device_name: &str, major: IrpMajorFunction, params: IrpParameters) -> Self {
        Self {
            major_function: major,
            minor_function: 0,
            device_name: String::from(device_name),
            status: STATUS_PENDING,
            information: 0,
            system_buffer: None,
            user_buffer: 0,
            parameters: params,
        }
    }
}

// ============================================================================
// Driver Dispatch Function
// ============================================================================

/// Signature for driver dispatch routines.
pub type DispatchFn = fn(&mut Irp) -> NtStatus;

// ============================================================================
// DriverObject
// ============================================================================

/// Represents a loaded kernel-mode driver.
pub struct DriverObject {
    /// Driver name (e.g. `\Driver\Null`).
    pub name: String,
    /// Dispatch table indexed by IrpMajorFunction.
    pub dispatch_table: [Option<DispatchFn>; IRP_MJ_COUNT],
    /// Device names owned by this driver.
    pub devices: Vec<String>,
}

// ============================================================================
// DeviceObject
// ============================================================================

/// Device type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Disk,
    Network,
    Console,
    Serial,
    Null,
    Unknown,
}

/// Represents a device created by a driver.
pub struct DeviceObject {
    /// Device name (e.g. `\Device\Null`).
    pub name: String,
    /// Category of device.
    pub device_type: DeviceType,
    /// Name of the owning driver.
    pub driver_name: String,
    /// Device characteristics flags.
    pub characteristics: u32,
}

// ============================================================================
// IoManager
// ============================================================================

/// Central registry of drivers and devices.
pub struct IoManager {
    drivers: BTreeMap<String, DriverObject>,
    devices: BTreeMap<String, DeviceObject>,
}

static IO_MANAGER: Mutex<Option<IoManager>> = Mutex::new(None);

/// Register a driver with the I/O Manager.
pub fn register_driver(driver: DriverObject) {
    let mut mgr = IO_MANAGER.lock();
    if let Some(ref mut m) = *mgr {
        m.drivers.insert(driver.name.clone(), driver);
    }
}

/// Register a device with the I/O Manager.
pub fn register_device(device: DeviceObject) {
    let mut mgr = IO_MANAGER.lock();
    if let Some(ref mut m) = *mgr {
        m.devices.insert(device.name.clone(), device);
    }
}

/// Dispatch an IRP to the appropriate driver based on the device name.
///
/// Looks up device → driver → dispatch table entry for the IRP's major function.
pub fn io_call_driver(device_name: &str, irp: &mut Irp) -> NtStatus {
    let mgr = IO_MANAGER.lock();
    let m = match mgr.as_ref() {
        Some(m) => m,
        None => {
            irp.status = STATUS_UNSUCCESSFUL;
            return STATUS_UNSUCCESSFUL;
        }
    };

    // Find the device
    let device = match m.devices.get(device_name) {
        Some(d) => d,
        None => {
            irp.status = STATUS_NO_SUCH_DEVICE;
            return STATUS_NO_SUCH_DEVICE;
        }
    };

    // Find the driver
    let driver = match m.drivers.get(&device.driver_name) {
        Some(d) => d,
        None => {
            irp.status = STATUS_NO_SUCH_DEVICE;
            return STATUS_NO_SUCH_DEVICE;
        }
    };

    // Dispatch
    let mj_index = irp.major_function as usize;
    if mj_index >= IRP_MJ_COUNT {
        irp.status = STATUS_INVALID_DEVICE_REQUEST;
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    match driver.dispatch_table[mj_index] {
        Some(dispatch_fn) => dispatch_fn(irp),
        None => {
            irp.status = STATUS_INVALID_DEVICE_REQUEST;
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Create and dispatch an IRP_MJ_CREATE for the given device.
pub fn io_create_file(device_name: &str, desired_access: u32) -> NtStatus {
    let mut irp = Irp::new(
        device_name,
        IrpMajorFunction::Create,
        IrpParameters::Create { desired_access, share_access: 0 },
    );
    io_call_driver(device_name, &mut irp)
}

/// Mark an IRP as complete with the given status.
pub fn io_complete_request(irp: &mut Irp, status: NtStatus) {
    irp.status = status;
}

// ============================================================================
// Built-in driver dispatch routines
// ============================================================================

// ── NullDriver ──────────────────────────────────────────────────────────────

fn null_create(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = 0;
    STATUS_SUCCESS
}

fn null_close(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = 0;
    STATUS_SUCCESS
}

fn null_read(irp: &mut Irp) -> NtStatus {
    // Read from \Device\Null always returns 0 bytes.
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = 0;
    STATUS_SUCCESS
}

fn null_write(irp: &mut Irp) -> NtStatus {
    // Write to \Device\Null discards all data ("success").
    let bytes = match &irp.parameters {
        IrpParameters::Write { length, .. } => *length as u64,
        _ => 0,
    };
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = bytes;
    STATUS_SUCCESS
}

// ── ConsoleDriver ───────────────────────────────────────────────────────────

fn console_create(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

fn console_close(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

fn console_read(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = 0;
    STATUS_SUCCESS
}

fn console_write(irp: &mut Irp) -> NtStatus {
    let bytes = match &irp.parameters {
        IrpParameters::Write { length, .. } => *length as u64,
        _ => 0,
    };
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = bytes;
    STATUS_SUCCESS
}

// ── SerialDriver ────────────────────────────────────────────────────────────

fn serial_create(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

fn serial_close(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

fn serial_read(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = 0;
    STATUS_SUCCESS
}

fn serial_write(irp: &mut Irp) -> NtStatus {
    let bytes = match &irp.parameters {
        IrpParameters::Write { length, .. } => *length as u64,
        _ => 0,
    };
    io_complete_request(irp, STATUS_SUCCESS);
    irp.information = bytes;
    STATUS_SUCCESS
}

// ── E1000Driver (stub) ─────────────────────────────────────────────────────

fn e1000_create(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

fn e1000_close(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

// ── VfsDriver (filesystem bridge) ───────────────────────────────────────────

/// Extract a UTF-8 path from `irp.system_buffer` (up to the first NUL, or the
/// entire buffer if there is no NUL).
fn extract_path(irp: &Irp) -> Option<String> {
    irp.system_buffer.as_ref().and_then(|buf| {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        core::str::from_utf8(&buf[..end]).ok().map(String::from)
    })
}

fn vfs_create(irp: &mut Irp) -> NtStatus {
    let path = match extract_path(irp) {
        Some(p) => p,
        None => {
            io_complete_request(irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
    };

    let create_if_missing = match &irp.parameters {
        IrpParameters::Create { desired_access, .. } => *desired_access & 0x40 != 0, // O_CREAT
        _ => false,
    };

    match crate::vfs::stat(&path) {
        Ok(st) => {
            irp.information = st.inode;
            io_complete_request(irp, STATUS_SUCCESS);
            STATUS_SUCCESS
        }
        Err(crate::vfs::VfsError::NotFound) if create_if_missing => {
            match crate::vfs::create_file(&path) {
                Ok(()) => {
                    let ino = crate::vfs::stat(&path).map(|s| s.inode).unwrap_or(0);
                    irp.information = ino;
                    io_complete_request(irp, STATUS_SUCCESS);
                    STATUS_SUCCESS
                }
                Err(_) => {
                    io_complete_request(irp, STATUS_UNSUCCESSFUL);
                    STATUS_UNSUCCESSFUL
                }
            }
        }
        Err(_) => {
            io_complete_request(irp, STATUS_NO_SUCH_FILE);
            STATUS_NO_SUCH_FILE
        }
    }
}

fn vfs_close(irp: &mut Irp) -> NtStatus {
    io_complete_request(irp, STATUS_SUCCESS);
    STATUS_SUCCESS
}

fn vfs_read(irp: &mut Irp) -> NtStatus {
    let path = match extract_path(irp) {
        Some(p) => p,
        None => {
            io_complete_request(irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
    };

    match crate::vfs::read_file(&path) {
        Ok(data) => {
            irp.information = data.len() as u64;
            irp.system_buffer = Some(data);
            io_complete_request(irp, STATUS_SUCCESS);
            STATUS_SUCCESS
        }
        Err(_) => {
            io_complete_request(irp, STATUS_UNSUCCESSFUL);
            STATUS_UNSUCCESSFUL
        }
    }
}

fn vfs_write(irp: &mut Irp) -> NtStatus {
    // system_buffer layout: path bytes ++ NUL ++ data bytes
    let buf = match irp.system_buffer.take() {
        Some(b) => b,
        None => {
            io_complete_request(irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
    };

    let null_pos = match buf.iter().position(|&b| b == 0) {
        Some(p) => p,
        None => {
            io_complete_request(irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
    };

    let path = match core::str::from_utf8(&buf[..null_pos]) {
        Ok(s) => s,
        Err(_) => {
            io_complete_request(irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
    };

    let data = &buf[null_pos + 1..];

    match crate::vfs::write_file(path, data) {
        Ok(n) => {
            irp.information = n as u64;
            io_complete_request(irp, STATUS_SUCCESS);
            STATUS_SUCCESS
        }
        Err(_) => {
            io_complete_request(irp, STATUS_UNSUCCESSFUL);
            STATUS_UNSUCCESSFUL
        }
    }
}

fn vfs_query_info(irp: &mut Irp) -> NtStatus {
    let path = match extract_path(irp) {
        Some(p) => p,
        None => {
            io_complete_request(irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
    };

    match crate::vfs::stat(&path) {
        Ok(st) => {
            let mut buf = Vec::with_capacity(21);
            buf.extend_from_slice(&st.size.to_le_bytes());        // 8 bytes
            buf.push(st.file_type as u8);                          // 1 byte
            buf.extend_from_slice(&st.permissions.to_le_bytes()); // 4 bytes
            buf.extend_from_slice(&st.inode.to_le_bytes());       // 8 bytes
            irp.information = buf.len() as u64;
            irp.system_buffer = Some(buf);
            io_complete_request(irp, STATUS_SUCCESS);
            STATUS_SUCCESS
        }
        Err(_) => {
            io_complete_request(irp, STATUS_NO_SUCH_FILE);
            STATUS_NO_SUCH_FILE
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Register built-in drivers and devices.
fn io_manager_init() {
    let mut mgr = IoManager {
        drivers: BTreeMap::new(),
        devices: BTreeMap::new(),
    };

    // ── NullDriver ──────────────────────────────────────────────────────
    {
        let mut dt: [Option<DispatchFn>; IRP_MJ_COUNT] = [None; IRP_MJ_COUNT];
        dt[IrpMajorFunction::Create as usize] = Some(null_create);
        dt[IrpMajorFunction::Close as usize]  = Some(null_close);
        dt[IrpMajorFunction::Read as usize]   = Some(null_read);
        dt[IrpMajorFunction::Write as usize]  = Some(null_write);

        mgr.drivers.insert(String::from("\\Driver\\Null"), DriverObject {
            name: String::from("\\Driver\\Null"),
            dispatch_table: dt,
            devices: Vec::from([String::from("\\Device\\Null")]),
        });

        mgr.devices.insert(String::from("\\Device\\Null"), DeviceObject {
            name: String::from("\\Device\\Null"),
            device_type: DeviceType::Null,
            driver_name: String::from("\\Driver\\Null"),
            characteristics: 0,
        });
    }

    // ── ConsoleDriver ───────────────────────────────────────────────────
    {
        let mut dt: [Option<DispatchFn>; IRP_MJ_COUNT] = [None; IRP_MJ_COUNT];
        dt[IrpMajorFunction::Create as usize] = Some(console_create);
        dt[IrpMajorFunction::Close as usize]  = Some(console_close);
        dt[IrpMajorFunction::Read as usize]   = Some(console_read);
        dt[IrpMajorFunction::Write as usize]  = Some(console_write);

        mgr.drivers.insert(String::from("\\Driver\\Console"), DriverObject {
            name: String::from("\\Driver\\Console"),
            dispatch_table: dt,
            devices: Vec::from([String::from("\\Device\\Console")]),
        });

        mgr.devices.insert(String::from("\\Device\\Console"), DeviceObject {
            name: String::from("\\Device\\Console"),
            device_type: DeviceType::Console,
            driver_name: String::from("\\Driver\\Console"),
            characteristics: 0,
        });
    }

    // ── SerialDriver ────────────────────────────────────────────────────
    {
        let mut dt: [Option<DispatchFn>; IRP_MJ_COUNT] = [None; IRP_MJ_COUNT];
        dt[IrpMajorFunction::Create as usize] = Some(serial_create);
        dt[IrpMajorFunction::Close as usize]  = Some(serial_close);
        dt[IrpMajorFunction::Read as usize]   = Some(serial_read);
        dt[IrpMajorFunction::Write as usize]  = Some(serial_write);

        mgr.drivers.insert(String::from("\\Driver\\Serial"), DriverObject {
            name: String::from("\\Driver\\Serial"),
            dispatch_table: dt,
            devices: Vec::from([String::from("\\Device\\Serial0")]),
        });

        mgr.devices.insert(String::from("\\Device\\Serial0"), DeviceObject {
            name: String::from("\\Device\\Serial0"),
            device_type: DeviceType::Serial,
            driver_name: String::from("\\Driver\\Serial"),
            characteristics: 0,
        });
    }

    // ── E1000Driver (stub) ──────────────────────────────────────────────
    {
        let mut dt: [Option<DispatchFn>; IRP_MJ_COUNT] = [None; IRP_MJ_COUNT];
        dt[IrpMajorFunction::Create as usize] = Some(e1000_create);
        dt[IrpMajorFunction::Close as usize]  = Some(e1000_close);

        mgr.drivers.insert(String::from("\\Driver\\E1000"), DriverObject {
            name: String::from("\\Driver\\E1000"),
            dispatch_table: dt,
            devices: Vec::from([String::from("\\Device\\E1000")]),
        });

        mgr.devices.insert(String::from("\\Device\\E1000"), DeviceObject {
            name: String::from("\\Device\\E1000"),
            device_type: DeviceType::Network,
            driver_name: String::from("\\Driver\\E1000"),
            characteristics: 0,
        });
    }

    // ── VfsDriver (filesystem bridge) ───────────────────────────────────
    {
        let mut dt: [Option<DispatchFn>; IRP_MJ_COUNT] = [None; IRP_MJ_COUNT];
        dt[IrpMajorFunction::Create as usize]           = Some(vfs_create);
        dt[IrpMajorFunction::Close as usize]            = Some(vfs_close);
        dt[IrpMajorFunction::Read as usize]             = Some(vfs_read);
        dt[IrpMajorFunction::Write as usize]            = Some(vfs_write);
        dt[IrpMajorFunction::QueryInformation as usize] = Some(vfs_query_info);

        mgr.drivers.insert(String::from("\\Driver\\Filesystem"), DriverObject {
            name: String::from("\\Driver\\Filesystem"),
            dispatch_table: dt,
            devices: Vec::from([String::from("\\Device\\Vfs")]),
        });

        mgr.devices.insert(String::from("\\Device\\Vfs"), DeviceObject {
            name: String::from("\\Device\\Vfs"),
            device_type: DeviceType::Disk,
            driver_name: String::from("\\Driver\\Filesystem"),
            characteristics: 0,
        });
    }

    *IO_MANAGER.lock() = Some(mgr);
    crate::serial_println!("[IO] I/O Manager initialized (5 drivers, 5 devices)");
}

/// Return the number of registered devices.
pub fn device_count() -> usize {
    let mgr = IO_MANAGER.lock();
    mgr.as_ref().map_or(0, |m| m.devices.len())
}

/// Return the number of registered drivers.
pub fn driver_count() -> usize {
    let mgr = IO_MANAGER.lock();
    mgr.as_ref().map_or(0, |m| m.drivers.len())
}

/// Initialize the I/O subsystem.
pub fn init() {
    devmgr::init();
    io_manager_init();
    completion::init();
    async_io::init_async_io();
    crate::serial_println!("[IO] I/O subsystem initialized");
}
