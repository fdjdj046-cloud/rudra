#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use bootloader_api::config::Mapping;
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::panic::PanicInfo;
use rudra::{println, serial_println};

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    // Маппим всю физическую память по динамическому смещению —
    // так ядру доступны page tables и MMIO.
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    rudra::serial::init();
    serial_println!("rudra: early serial up");
    rudra::init(boot_info);

    println!("rudra kernel v0.1.0");
    println!("gdt/idt: ok, paging: ok, heap: ok");
    serial_println!("rudra: serial output alive");

    heap_demo();

    println!("It did not crash!");
    serial_println!("rudra: init complete, entering hlt loop");
    rudra::hlt_loop()
}

fn heap_demo() {
    let mut v: Vec<u64> = Vec::new();
    for i in 0..500 {
        v.push(i);
    }
    assert_eq!(v.iter().sum::<u64>(), (0..500u64).sum());
    println!("heap demo: allocated Vec of {} u64s, sum ok", v.len());
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("PANIC: {}", info);
    rudra::hlt_loop()
}
