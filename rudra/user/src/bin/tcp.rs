//! Петля TCP на 127.0.0.1: bind, listen, connect, accept, обмен, EOF.
//! Провод: `tcp.elf wire` — DHCP, коннект на 10.0.2.2:19013 (host echo),
//! обмен, печать `tcp-wire-ok`. IPv6 и listen на UDP — ошибка.

#![no_std]
#![no_main]

use rudra::{exit, println, syscall6};

fn sa(port: u16, ip: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0..2].copy_from_slice(&2u16.to_le_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&ip.to_be_bytes());
    a
}

fn bad(what: &str, rc: u64) -> ! {
    println!("tcp-bad {} {:#x}", what, rc);
    exit(1);
}

/// Сравнение в той же функции, что и syscall: иначе rustc выкидывает чтение буфера.
fn got(fd: u64, expect: &[u8]) -> bool {
    let mut buf = [0u8; 8];
    let n = unsafe { syscall6(0, fd, buf.as_mut_ptr() as u64, expect.len() as u64, 0, 0, 0) };
    if n == expect.len() as u64 && &buf[..expect.len()] == expect {
        return true;
    }
    println!("tcp-bad bytes {:#x} {}", n, buf[0]);
    false
}

fn cstr_eq(p: *const u8, lit: &[u8]) -> bool {
    if p.is_null() {
        return false;
    }
    unsafe {
        for (i, &b) in lit.iter().enumerate() {
            if *p.add(i) != b {
                return false;
            }
        }
        *p.add(lit.len()) == 0
    }
}

/// Проводной тест: DHCP, echo на 10.0.2.2:19013 (QEMU user-net: host).
fn wire_test() -> ! {
    let ip = unsafe { syscall6(1001, 0, 0, 0, 0, 0, 0) };
    if ip == u64::MAX {
        println!("tcp-wire-bad dhcp");
        exit(1);
    }
    println!("dhcp-ok {:#x}", ip);
    let fd = unsafe { syscall6(41, 2, 1, 0, 0, 0, 0) };
    if (fd as i64) < 0 {
        bad("socket", fd);
    }
    let dst = sa(19013, 0x0a00_0202);
    let rc = unsafe { syscall6(42, fd, dst.as_ptr() as u64, 16, 0, 0, 0) };
    if rc != 0 {
        bad("connect", rc);
    }
    let msg = *b"rudra-ping";
    let n = unsafe { syscall6(1, fd, msg.as_ptr() as u64, 10, 0, 0, 0) };
    if n != 10 {
        bad("send", n);
    }
    let mut buf = [0u8; 10];
    let n = unsafe { syscall6(0, fd, buf.as_mut_ptr() as u64, 10, 0, 0, 0) };
    if n != 10 || buf != msg {
        println!("tcp-wire-bad echo {} {}", n, buf[0]);
        exit(1);
    }
    unsafe { syscall6(3, fd, 0, 0, 0, 0, 0) };
    println!("tcp-wire-ok");
    exit(0);
}

fn main() {
    let v6 = unsafe { syscall6(41, 10, 1, 0, 0, 0, 0) };
    if v6 as i64 != -97 {
        bad("v6", v6);
    }

    let udp = unsafe { syscall6(41, 2, 2, 0, 0, 0, 0) };
    if (udp as i64) < 0 {
        bad("udp", udp);
    }
    let lrc = unsafe { syscall6(50, udp, 1, 0, 0, 0, 0) };
    if lrc as i64 != -95 {
        bad("udp-listen", lrc);
    }
    unsafe { syscall6(3, udp, 0, 0, 0, 0, 0) };

    let lst = unsafe { syscall6(41, 2, 1, 0, 0, 0, 0) };
    if (lst as i64) < 0 {
        bad("socket", lst);
    }
    let addr = sa(19011, 0x7f00_0001);
    let rc = unsafe { syscall6(49, lst, addr.as_ptr() as u64, 16, 0, 0, 0) };
    if rc != 0 {
        bad("bind", rc);
    }
    let rc = unsafe { syscall6(50, lst, 1, 0, 0, 0, 0) };
    if rc != 0 {
        bad("listen", rc);
    }

    let cli = unsafe { syscall6(41, 2, 1, 0, 0, 0, 0) };
    if (cli as i64) < 0 {
        bad("client", cli);
    }
    // Провод теперь живой: без DHCP (нет адреса) — ENETUNREACH, иначе хост
    // отвечает RST на закрытый порт (ECONNREFUSED) или молчит (ETIMEDOUT).
    // Всё — честный исход попытки, любой из трёх принимаем.
    let wire = sa(19011, 0x0a00_0202);
    let rc = unsafe { syscall6(42, cli, wire.as_ptr() as u64, 16, 0, 0, 0) } as i64;
    if rc != -101 && rc != -111 && rc != -110 {
        bad("wire", rc as u64);
    }
    // После неудачного проводного connect сокет в SynSent может остаться;
    // для петли берём свежий.
    let cli2 = unsafe { syscall6(41, 2, 1, 0, 0, 0, 0) };
    if (cli2 as i64) < 0 {
        bad("client2", cli2);
    }
    let miss = sa(9, 0x7f00_0001);
    let rc = unsafe { syscall6(42, cli2, miss.as_ptr() as u64, 16, 0, 0, 0) };
    if rc as i64 != -111 {
        bad("refused", rc);
    }
    let ok = sa(19011, 0x7f00_0001);
    let rc = unsafe { syscall6(42, cli2, ok.as_ptr() as u64, 16, 0, 0, 0) };
    if rc != 0 {
        bad("connect", rc);
    }

    let acc = unsafe { syscall6(43, lst, 0, 0, 0, 0, 0) };
    if (acc as i64) < 0 {
        bad("accept", acc);
    }

    let msg = *b"ping";
    let n = unsafe { syscall6(1, cli2, msg.as_ptr() as u64, 4, 0, 0, 0) };
    if n != 4 {
        bad("send", n);
    }
    if !got(acc, b"ping") {
        exit(1);
    }
    let reply = *b"pong";
    let n = unsafe { syscall6(1, acc, reply.as_ptr() as u64, 4, 0, 0, 0) };
    if n != 4 {
        bad("reply", n);
    }
    if !got(cli2, b"pong") {
        exit(1);
    }

    unsafe { syscall6(3, cli2, 0, 0, 0, 0, 0) };
    let mut end = [0u8; 1];
    let n = unsafe { syscall6(0, acc, end.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != 0 {
        bad("eof", n);
    }
    let _ = end[0];
    println!("tcp-ok");
}

/// Свой _start через global_asm: argc/argv читаются из [rsp] (Linux ABI
/// гарантирует только rsp; прочие регистры после execve не определены).
/// "wire" — проводной echo-тест, иначе — петля.
core::arch::global_asm!(
    r#"
    .global _start
_start:
    mov rdi, rsp
    and rsp, -16
    call start_rs
    "#
);

#[no_mangle]
extern "C" fn start_rs(sp: *const u64) -> ! {
    // argc = [sp], argv = sp+1. Ищем "wire" среди ВСЕХ строк argv до NULL.
    let argv = unsafe { sp.add(1) } as *const *const u8;
    let mut wire = false;
    let mut i = 0usize;
    loop {
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            break;
        }
        if cstr_eq(p, b"wire") {
            wire = true;
        }
        i += 1;
    }
    if wire {
        wire_test();
    }
    main();
    rudra::exit(0);
}
