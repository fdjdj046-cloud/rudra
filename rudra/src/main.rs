#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use bootloader::BootInfo;
use core::panic::PanicInfo;
use rudra::{println, serial_println};

#[no_mangle]
pub extern "C" fn _start(boot_info: &'static BootInfo) -> ! {
    rudra::serial::init();
    rudra::serial_println!("rudra: early serial up");
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

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    serial_println!("PANIC: {}", info);
    rudra::hlt_loop()
}
