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
    // ET: тот же интерес с EPOLLET. Первый wait — фронт по новому байту.
    // Второй wait без новых данных — 0 (level дал бы 1). После ещё одного
    // байта — снова 1.
    let mut ev_et = [0u8; 12];
    ev_et[0..4].copy_from_slice(&(1u32 | 0x8000_0000).to_le_bytes());
    ev_et[4..12].copy_from_slice(&rfd.to_le_bytes());
    let rc = unsafe { syscall6(233, ep, 3, rfd, ev_et.as_ptr() as u64, 0, 0) };
    if rc != 0 {
        println!("epoll-bad mod-et {:#x}", rc);
        exit(9);
    }
    // Дренируем pipe, чтобы следующий байт дал фронт.
    let mut drain = [0u8; 1];
    let rd = unsafe { syscall6(0, rfd, drain.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if rd != 1 {
        println!("epoll-bad drain {:#x}", rd);
        exit(10);
    }
    let wr = unsafe { syscall6(1, wfd, byte.as_ptr() as u64, 1, 0, 0, 0) };
    if wr != 1 {
        println!("epoll-bad write2 {:#x}", wr);
        exit(11);
    }
    let n = unsafe { syscall6(232, ep, out.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != 1 {
        println!("epoll-bad et-first {:#x}", n);
        exit(12);
    }
    let n = unsafe { syscall6(232, ep, out.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != 0 {
        println!("epoll-bad et-level {:#x}", n);
        exit(13);
    }
    println!("epoll-ok");
}

rudra::entry!(main);
