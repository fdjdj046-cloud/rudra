//! Перебор шины PCI через порты `0xCF8` / `0xCFC`.
//!
//! Это шаг к VirtIO-blk: сначала видим устройства QEMU (мост, VGA, диск),
//! потом поднимаем virtqueue. Сканируется шина 0, этого хватает для одной
//! машины QEMU.

use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

fn read32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 1 << 31
        | (bus as u32) << 16
        | (slot as u32) << 11
        | (func as u32) << 8
        | (offset as u32 & 0xFC);
    unsafe {
        let mut address = Port::<u32>::new(CONFIG_ADDRESS);
        let mut data = Port::<u32>::new(CONFIG_DATA);
        address.write(addr);
        data.read()
    }
}

/// Напечатать все функции на шине 0. Пустые слоты (`vendor == 0xFFFF`) пропускаются.
pub fn scan() {
    for slot in 0..32u8 {
        let header = read32(0, slot, 0, 0x0C);
        let max_func = if ((header >> 16) & 0x80) != 0 { 8 } else { 1 };
        for func in 0..max_func {
            let id = read32(0, slot, func, 0x00);
            let vendor = (id & 0xFFFF) as u16;
            if vendor == 0xFFFF {
                continue;
            }
            let device = (id >> 16) as u16;
            let classreg = read32(0, slot, func, 0x08);
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
