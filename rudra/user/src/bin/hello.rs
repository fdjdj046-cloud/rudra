//! Приветствие: демонстрация write/exit через Linux ABI.

#![no_std]
#![no_main]

use rudra::println;

fn main() {
    println!("Hello from rudra userspace (ring 3)!");
    println!("pid = {}", rudra::getpid());
}

rudra::entry!(main);
