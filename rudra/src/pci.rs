//! Перебор шины PCI через порты `0xCF8` / `0xCFC`.
//!
//! Это шаг к VirtIO-blk: сначала видим устройства QEMU (мост, VGA, диск),
//! потом поднимаем virtqueue. Сканируется шина 0, этого хватает для одной
//! машины QEMU.

use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

fn addr(slot: u8, func: u8, offset: u8) -> u32 {
    1 << 31 | (slot as u32) << 11 | (func as u32) << 8 | (offset as u32 & 0xFC)
}

fn read32(slot: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        let mut address = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data = Port::<u32>::new(CONFIG_DATA);
        address.write(addr(slot, func, offset));
        data.read()
    }
}

fn write32(slot: u8, func: u8, offset: u8, value: u32) {
    unsafe {
        let mut address = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data = Port::<u32>::new(CONFIG_DATA);
        address.write(addr(slot, func, offset));
        data.write(value);
    }
}

/// Напечатать все функции на шине 0. Пустые слоты (`vendor == 0xFFFF`) пропускаются.
pub fn scan() {
    for slot in 0..32u8 {
        let header = read32( slot, 0, 0x0C);
        let max_func = if ((header >> 16) & 0x80) != 0 { 8 } else { 1 };
        for func in 0..max_func {
            let id = read32( slot, func, 0x00);
            let vendor = (id & 0xFFFF) as u16;
            if vendor == 0xFFFF {
                continue;
            }
            let device = (id >> 16) as u16;
            let classreg = read32( slot, func, 0x08);
            let class = (classreg >> 24) as u8;
            let subclass = (classreg >> 16) as u8;
            let progif = (classreg >> 8) as u8;
            crate::serial_println!(
                "[pci] 00:{:02x}.{} {:04x}:{:04x} class {:02x}{:02x}{:02x}",
                slot,
                func,
                vendor,
                device,
                class,
                subclass,
                progif
            );
        }
    }
}

/// Первая функция на шине 0 с парой vendor/device.
pub fn find(vendor: u16, device: u16) -> Option<(u8, u8)> {
    for slot in 0..32u8 {
        let header = read32( slot, 0, 0x0C);
        let max_func = if ((header >> 16) & 0x80) != 0 { 8 } else { 1 };
        for func in 0..max_func {
            let id = read32( slot, func, 0x00);
            let v = (id & 0xFFFF) as u16;
            if v == 0xFFFF {
                continue;
            }
            if v == vendor && (id >> 16) as u16 == device {
                return Some((slot, func));
            }
        }
    }
    None
}

/// BAR0, если это порт ввода-вывода (младший бит установлен).
pub fn bar0_io(slot: u8, func: u8) -> Option<u16> {
    let bar = read32( slot, func, 0x10);
    if bar & 1 == 0 || (bar & 0xFFFC) == 0 {
        return None;
    }
    Some((bar & 0xFFFC) as u16)
}

/// Разрешить IO-space и bus master. Без bus master DMA virtqueue не доезжает.
pub fn enable_io_bus_master(slot: u8, func: u8) {
    let mut cmd = read32( slot, func, 0x04);
    cmd |= 1 | 4; // IO space | bus master
    write32(slot, func, 0x04, cmd);
}

/// Линия IRQ, которую прописал BIOS (регистр Interrupt Line). 0xFF — нет.
pub fn interrupt_line(slot: u8, func: u8) -> u8 {
    (read32( slot, func, 0x3C) & 0xFF) as u8
}
