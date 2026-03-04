//! Device Manager — Hardware Device Tree
//!
//! Provides a device enumeration and management subsystem.
//! Enumerates known devices and presents them in a tree for diagnostics.
//! Inspired by the NT I/O Manager's device object hierarchy.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

/// Device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Running,
    Stopped,
    Error,
    Unknown,
}

impl core::fmt::Display for DeviceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error   => write!(f, "Error"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Device category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    System,
    Display,
    Network,
    Storage,
    Input,
    Bus,
    Serial,
}

impl core::fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::System  => write!(f, "System"),
            Self::Display => write!(f, "Display"),
            Self::Network => write!(f, "Network"),
            Self::Storage => write!(f, "Storage"),
            Self::Input   => write!(f, "Input"),
            Self::Bus     => write!(f, "Bus"),
            Self::Serial  => write!(f, "Serial"),
        }
    }
}

/// A device node in the device tree.
pub struct DeviceNode {
    pub name: String,
    pub class: DeviceClass,
    pub state: DeviceState,
    pub driver: String,
    pub children: Vec<DeviceNode>,
}

/// Global device tree.
static DEVICE_TREE: Mutex<Option<DeviceNode>> = Mutex::new(None);

/// Initialize the device manager — populates the device tree with known devices.
pub fn init() {
    let root = DeviceNode {
        name: String::from("AstryxOS System"),
        class: DeviceClass::System,
        state: DeviceState::Running,
        driver: String::from("hal"),
        children: alloc::vec![
            DeviceNode {
                name: String::from("PCI Bus 0"),
                class: DeviceClass::Bus,
                state: DeviceState::Running,
                driver: String::from("pci"),
                children: alloc::vec![
                    DeviceNode {
                        name: String::from("Intel e1000 Ethernet Controller"),
                        class: DeviceClass::Network,
                        state: if crate::net::e1000::is_available() {
                            DeviceState::Running
                        } else {
                            DeviceState::Stopped
                        },
                        driver: String::from("e1000"),
                        children: Vec::new(),
                    },
                    DeviceNode {
                        name: String::from("UEFI GOP Framebuffer"),
                        class: DeviceClass::Display,
                        state: DeviceState::Running,
                        driver: String::from("console"),
                        children: Vec::new(),
                    },
                ],
            },
            DeviceNode {
                name: String::from("ISA Bus"),
                class: DeviceClass::Bus,
                state: DeviceState::Running,
                driver: String::from("isa"),
                children: alloc::vec![
                    DeviceNode {
                        name: String::from("i8042 PS/2 Controller"),
                        class: DeviceClass::Input,
                        state: DeviceState::Running,
                        driver: String::from("keyboard"),
                        children: alloc::vec![
                            DeviceNode {
                                name: String::from("PS/2 Keyboard"),
                                class: DeviceClass::Input,
                                state: DeviceState::Running,
                                driver: String::from("keyboard"),
                                children: Vec::new(),
                            },
                        ],
                    },
                    DeviceNode {
                        name: String::from("COM1 Serial Port (0x3F8)"),
                        class: DeviceClass::Serial,
                        state: DeviceState::Running,
                        driver: String::from("serial"),
                        children: Vec::new(),
                    },
                    DeviceNode {
                        name: String::from("PIT Timer (IRQ 0, 100 Hz)"),
                        class: DeviceClass::System,
                        state: DeviceState::Running,
                        driver: String::from("irq"),
                        children: Vec::new(),
                    },
                ],
            },
            DeviceNode {
                name: String::from("RAM Disk"),
                class: DeviceClass::Storage,
                state: DeviceState::Running,
                driver: String::from("ramfs"),
                children: Vec::new(),
            },
        ],
    };

    *DEVICE_TREE.lock() = Some(root);
    crate::serial_println!("[DEVMGR] Device tree populated");
}

/// Dump the device tree to the console.
pub fn dump_device_tree() {
    let tree = DEVICE_TREE.lock();
    match tree.as_ref() {
        Some(root) => {
            crate::kprintln!("Device Tree:");
            print_device(root, "", true);
        }
        None => crate::kprintln!("Device Manager not initialized"),
    }
}

fn print_device(node: &DeviceNode, prefix: &str, is_last: bool) {
    let connector = if prefix.is_empty() { "" } else if is_last { "└── " } else { "├── " };
    let state_indicator = match node.state {
        DeviceState::Running => "\x1b[32m[OK]\x1b[0m",    // Green
        DeviceState::Stopped => "\x1b[33m[--]\x1b[0m",    // Yellow
        DeviceState::Error   => "\x1b[31m[!!]\x1b[0m",    // Red
        DeviceState::Unknown => "\x1b[90m[??]\x1b[0m",    // Gray
    };

    crate::kprintln!("{}{}{} {} ({})", prefix, connector, node.name,
        state_indicator, node.driver);

    let child_prefix = if prefix.is_empty() {
        String::from("  ")
    } else {
        alloc::format!("{}{}", prefix, if is_last { "    " } else { "│   " })
    };

    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1;
        print_device(child, &child_prefix, child_is_last);
    }
}

/// Get device count.
pub fn device_count() -> usize {
    fn count_recursive(node: &DeviceNode) -> usize {
        1 + node.children.iter().map(count_recursive).sum::<usize>()
    }
    let tree = DEVICE_TREE.lock();
    tree.as_ref().map_or(0, count_recursive)
}
