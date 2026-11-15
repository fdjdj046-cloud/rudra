//! FizzBuzz 1..=20.

#![no_std]
#![no_main]

use rudra::println;

fn main() {
    for i in 1..=20 {
        match (i % 3, i % 5) {
            (0, 0) => println!("FizzBuzz"),
            (0, _) => println!("Fizz"),
            (_, 0) => println!("Buzz"),
            _ => println!("{}", i),
        }
    }
}

rudra::entry!(main);
