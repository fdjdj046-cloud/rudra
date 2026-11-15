//! Level-triggered epoll на читающем конце pipe.
//!
//! Пустой wait с таймаутом 0 возвращает 0. После одного байта wait
//! возвращает EPOLLIN и data, равную номеру читающего fd.

#![no_std]
#![no_main]

use rudra::{exit, println, syscall6};

fn main() {
    let mut fds = [0i32; 2];
    let rc = unsafe { syscall6(22, fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
    if rc != 0 {
        println!("epoll-bad pipe {:#x}", rc);
        exit(2);
    }
    let rfd = fds[0] as u64;
    let wfd = fds[1] as u64;
    let ep = unsafe { syscall6(291, 0, 0, 0, 0, 0, 0) };
    if (ep as i64) < 0 {
        println!("epoll-bad create {:#x}", ep);
        exit(3);
    }
    // struct epoll_event: u32 events + u64 data, 12 байт.
    let mut ev = [0u8; 12];
    ev[0..4].copy_from_slice(&1u32.to_le_bytes());
    ev[4..12].copy_from_slice(&rfd.to_le_bytes());
    let rc = unsafe { syscall6(233, ep, 1, rfd, ev.as_ptr() as u64, 0, 0) };
    if rc != 0 {
        println!("epoll-bad add {:#x}", rc);
        exit(4);
    }
    let mut out = [0u8; 12];
    let n = unsafe { syscall6(232, ep, out.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != 0 {
        println!("epoll-bad empty {:#x}", n);
        exit(5);
    }
    let byte = [b'x'];
    let wr = unsafe { syscall6(1, wfd, byte.as_ptr() as u64, 1, 0, 0, 0) };
    if wr != 1 {
        println!("epoll-bad write {:#x}", wr);
        exit(6);
    }
    let n = unsafe { syscall6(232, ep, out.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != 1 {
        println!("epoll-bad wait {:#x}", n);
        exit(7);
    }
    let got_ev = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let got_data = u64::from_le_bytes(out[4..12].try_into().unwrap());
    if got_ev & 1 == 0 || got_data != rfd {
        println!("epoll-bad event {:#x} data {:#x}", got_ev, got_data);
        exit(8);
    }
    println!("epoll-ok");
}

rudra::entry!(main);
