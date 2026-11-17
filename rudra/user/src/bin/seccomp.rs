#![no_std]
#![no_main]

use rudra::{exit, getpid, println, syscall6};

fn main() {
    // PR_SET_SECCOMP = 22, SECCOMP_MODE_STRICT = 1.
    let rc = unsafe { syscall6(157, 22, 1, 0, 0, 0, 0) };
    if rc != 0 {
        println!("seccomp-bad prctl {}", rc);
        exit(1);
    }
    println!("seccomp-ok");
    let pid = getpid();
    println!("seccomp-bad {}", pid);
    exit(2);
}

rudra::entry!(main);
