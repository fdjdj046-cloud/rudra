#![no_std]
#![no_main]

//! Простейшая user-программа: приветствие и exit.

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    user::write("hello from userspace!\n");
    user::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::write("hello panic\n");
    user::exit(1)
}
