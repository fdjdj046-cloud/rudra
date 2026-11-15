//! Счётчик с nanosleep: демонстрация блокирующего сна в ядре.

#![no_std]
#![no_main]

use rudra::println;

fn main() {
    for i in 1..=5 {
        println!("counter: {}", i);
        rudra::sleep_ms(300);
    }
}

rudra::entry!(main);
