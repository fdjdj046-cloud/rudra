#![no_std]
#![no_main]

use rudra::{exit, println, syscall6};

fn id(nr: u64) -> u64 {
    unsafe { syscall6(nr, 0, 0, 0, 0, 0, 0) }
}

fn main() {
    let uid = id(102);
    let gid = id(104);
    let euid = id(107);
    let egid = id(108);
    let pid = id(39);
    let ppid = id(110);
    let tid = id(186);
    if uid != 0 || euid != 0 || gid != 0 || egid != 0 {
        println!("cred-bad root {} {} {} {}", uid, euid, gid, egid);
        exit(1);
    }
    if pid == 0 || ppid == 0 || ppid == pid || tid != pid {
        println!("cred-bad ids {} {} {}", pid, ppid, tid);
        exit(2);
    }
    let rc = unsafe { syscall6(105, 1000, 0, 0, 0, 0, 0) };
    if rc != 0 || id(102) != 1000 || id(107) != 1000 {
        println!("cred-bad setuid {} {} {}", rc, id(102), id(107));
        exit(3);
    }
    let rc = unsafe { syscall6(105, 0, 0, 0, 0, 0, 0) };
    if rc != (-1i64 as u64) {
        println!("cred-bad regain {}", rc);
        exit(4);
    }
    if id(102) != 1000 || id(107) != 1000 {
        println!("cred-bad stayed {} {}", id(102), id(107));
        exit(5);
    }
    let rc = unsafe { syscall6(106, 1000, 0, 0, 0, 0, 0) };
    if rc != 0 || id(104) != 1000 || id(108) != 1000 {
        println!("cred-bad setgid {} {} {}", rc, id(104), id(108));
        exit(6);
    }
    let rc = unsafe { syscall6(106, 0, 0, 0, 0, 0, 0) };
    if rc != (-1i64 as u64) {
        println!("cred-bad setgid0 {}", rc);
        exit(7);
    }
    println!("cred-ok");
}

rudra::entry!(main);
