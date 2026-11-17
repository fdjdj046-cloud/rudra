//! Данные, на которые указывает GS в режиме ядра.
//!
//! Вход в syscall и в таймер из ring 3 делает `swapgs`: в ядре `GS_BASE` —
//! этот слот CPU, пользовательский GS лежит в `KERNEL_GS_BASE`. Обратно —
//! перед `sysret` и перед `iret` в ring 3.

use x86_64::registers::model_specific::Msr;

pub const MAX_CPUS: usize = 8;
const GS_BASE: u32 = 0xC000_0101;
const KERNEL_GS_BASE: u32 = 0xC000_0102;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct GsSlot {
    pub scratch: u64,
    pub kstack: u64,
}

#[allow(static_mut_refs)]
pub static mut GS: [GsSlot; MAX_CPUS] = [GsSlot { scratch: 0, kstack: 0 }; MAX_CPUS];

pub fn bind(index: usize) {
    let index = index.min(MAX_CPUS - 1);
    let addr = unsafe { core::ptr::addr_of!(GS[index]) as u64 };
    unsafe {
        Msr::new(GS_BASE).write(addr);
        Msr::new(KERNEL_GS_BASE).write(0);
    }
}

pub fn set_kstack(index: usize, top: u64) {
    let index = index.min(MAX_CPUS - 1);
    unsafe { GS[index].kstack = top };
}

pub fn read_user_gs() -> u64 {
    unsafe { Msr::new(KERNEL_GS_BASE).read() }
}

pub fn write_user_gs(value: u64) {
    unsafe { Msr::new(KERNEL_GS_BASE).write(value) };
}
