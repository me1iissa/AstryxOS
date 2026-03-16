# Drivers & HAL Gaps

> Reference: Windows XP `drivers/` (2,891 C files), Linux `drivers/` (extensive),
>             `XP/base/ntos/io/` (75 C files — I/O manager)
> AstryxOS: `drivers/`, `hal/mod.rs`, `io/`

---

## What We Have

- PCI bus enumeration: vendor/device ID scan, basic BAR reading
- AHCI disk controller: port init, IDENTIFY, read/write sectors via command engine
- ATA command set: READ/WRITE DMA
- Block device layer: MBR partition parsing, partition abstraction
- PS/2 keyboard: scancode decode → keycode → Unicode
- PS/2 mouse: relative delta, button state
- AC97 audio: PCM playback, register config, 48 KHz stereo
- VMware SVGA II: framebuffer mapping, mode set, hardware cursor
- Serial UART: 16550-compatible I/O for console output
- TTY: cooked/raw modes, line discipline basics
- PTY: 16 master/slave pairs, bidirectional ring buffers, epoll integration
- USB xHCI stub: device probing, no actual transfers
- E1000 NIC: ring descriptor TX/RX, interrupt handling
- Virtio-net stub: feature negotiation, no ring processing

---

## Missing (Critical)

### MSI / MSI-X Interrupt Routing
**What**: Modern PCI devices use Message Signaled Interrupts (MSI) instead of legacy INTx line
interrupts. MSI writes to a host memory address to trigger an interrupt; MSI-X extends this
to 2048 independent interrupt vectors per device.

**Why critical**: NVMe SSDs and modern NICs require MSI-X. Legacy INT line IRQ sharing causes
interrupt storms on busy systems. Any PCIe device on a machine without ISA-style IRQ routing
(common in modern VMs) requires MSI.

**Reference**: `linux/drivers/pci/msi/` (msi.c, irqdomain.c);
`XP/base/busdrv/pci/msi.c`

---

### PCIe Extended Config Space (ECAM)
**What**: PCIe devices have 4 KiB of configuration space (extended registers 0x100-0xFFF) vs
the legacy 256-byte PCI config. ECAM maps the entire config space to MMIO. Capabilities
like SR-IOV, AER, ACS, PASID require extended config space.

**Reference**: `linux/drivers/pci/ecam.c`; ACPI MCFG table provides MMIO base

---

### IOMMU / DMA Remapping
**What**: The IOMMU (VT-d on Intel, AMD-Vi on AMD) translates DMA addresses from device
perspective to physical memory. Without it: a malicious or buggy driver can DMA to any
physical address including kernel memory.

**Current state**: All DMA assumes physical addresses are valid. `e1000` and `AHCI` pass
kernel virtual addresses directly to hardware (wrong — should be physical).

**Reference**: `linux/drivers/iommu/intel/iommu.c`; `linux/drivers/dma/`

---

### Interrupt Affinity (IRQ per CPU)
**What**: Route device interrupts to specific CPUs. On SMP, routing all IRQs to BSP (CPU 0)
creates a bottleneck. MSI-X allows each queue to interrupt a different CPU.

**Current state**: All IRQs go to BSP.

**Reference**: `linux/kernel/irq/manage.c` (`irq_set_affinity`)

---

## Missing (High)

### USB Full Implementation (xHCI)
**What**: xHCI driver exists as a stub. USB is required for: keyboard/mouse on modern hardware,
USB storage, USB Ethernet, USB serial.

**Minimum viable**: USB hub enumeration → HID device detection → keyboard/mouse HID driver.
The xHCI driver in `drivers/usb/xhci.rs` has device probing but no ring management.

**Reference**: `linux/drivers/usb/host/xhci.c` (4,000 LOC);
`XP/drivers/wdm/usb/hcd/uhcd/` (UHCI reference simpler)

---

### NVMe Driver
**What**: Modern VM setups (particularly with virtio-blk or NVMe emulation) won't have AHCI.
NVMe is the standard SSD interface. NVMe uses PCIe-native command queues.

**Reference**: `linux/drivers/nvme/host/core.c` (4,500 LOC);
`linux/drivers/nvme/host/pci.c` (2,800 LOC)

---

### Virtio-Block Driver
**What**: QEMU q35 machines can expose storage via virtio-blk (faster than AHCI emulation).
The current `drivers/block.rs` has AHCI only. Many cloud VMs don't have AHCI.

**Reference**: `linux/drivers/block/virtio_blk.c` (900 LOC)

---

### Power State Transitions (D0-D3)
**What**: PCI devices have power states D0 (fully on) through D3 (off/sleep). Transitioning
to D3 and back to D0 is required for system suspend/resume.

**Reference**: `linux/drivers/pci/pci.c` (`pci_set_power_state`);
`XP/base/busdrv/pci/power.c`

---

### Device Hot-Plug
**What**: PCIe allows devices to be removed/added at runtime. Hot-plug requires:
- PCIe hot-plug capable slot detection (PCIe capabilities)
- Interrupt on device arrival/removal
- Re-enumerate bus segment
- Driver attach/detach callbacks

**Reference**: `linux/drivers/pci/hotplug/` (pciehp_ctrl.c);
`XP/base/busdrv/pci/hotplug.c`

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| I/O APIC full routing | Route all PCI IRQs through I/O APIC properly | `linux/arch/x86/kernel/apic/io_apic.c` |
| Memory ordering (wmb/rmb/mb) | Explicit barriers for MMIO device regs | `linux/arch/x86/include/asm/barrier.h` |
| PCI resource claiming | Track which BAR regions are allocated | `linux/drivers/pci/pci.c` (`request_region`) |
| DMA pool allocator | Allocate DMA-coherent memory | `linux/lib/dma-pool.c` |
| TRIM / DISCARD (ATA) | Wear leveling for SSD (ATA DATA SET MGMT) | `linux/drivers/ata/libata-core.c` |
| Bad block tracking | Remap defective sectors | Drive firmware (vendor specific) |
| Hardware random generator | Read RDSEED/RDRAND properly as separate driver | `linux/drivers/char/hw_random/` |
| RTC driver | CMOS RTC read (time base for wall clock) | `linux/drivers/rtc/rtc-cmos.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| I2C bus controller | Required for EEPROM, sensors, PMICs |
| SPI bus controller | Required for flash storage, displays |
| PCIe AER (Advanced Error Reporting) | Detect PCIe link errors |
| Firmware loading (request_firmware) | Load opaque blobs from disk for devices |
| DRM/KMS (Direct Rendering Manager) | GPU-native display and OpenGL/Vulkan |
| VFIO / device passthrough | Assign device directly to VM |

---

## I/O Subsystem Architecture Gaps

The current I/O model (direct function calls from syscall → driver) has no:

- **IRP queue**: requests stack up per device with cancellation
- **Filter drivers**: no layered driver stack (e.g., encryption filter on top of block)
- **I/O cancel**: once a request is dispatched, can't cancel it
- **I/O completion ports**: async I/O notification mechanism (NT IOCP / Linux io_uring)
- **Buffered vs direct I/O**: all I/O goes through user buffer copy; no zero-copy path
- **I/O statistics**: no per-device bytes-read/written counters

**Reference**: `XP/base/ntos/io/iomgr.c` (IRP lifecycle);
`linux/block/blk-mq.c` (multi-queue block layer);
`linux/fs/io_uring.c` (async I/O ring, ~8,000 LOC)

---

## Implementation Priority

1. **Virtio-block** — easiest, high-value for QEMU setup
2. **RTC driver** — read CMOS 0x70/0x71 for wall clock time (needed for HTTPS cert validation)
3. **MSI support** — PCIe capability walker → write MSI address/data registers
4. **USB HID** — extend xHCI stub to actually enumerate devices + HID keyboard
5. **NVMe** — if AHCI isn't available in deployment environment
6. **I/O APIC routing** — move from PIC to I/O APIC for proper IRQ routing
