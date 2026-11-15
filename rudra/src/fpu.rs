//! SSE2 для пользователей (статический glibc без этого ловит #UD на movd/movaps).
//!
//! Ядро собрано без SSE и регистры xmm не трогает, поэтому через syscall
//! они сохраняются сами. На переключении задач состояние пишется FXSAVE64.

use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// MXCSR: все SIMD-исключения маскированы, округление к ближайшему.
const MXCSR_DEFAULT: u32 = 0x1F80;

/// 512 байт образа FXSAVE. `live` — образ уже снят с CPU, его можно fxrstor.
#[repr(C, align(16))]
pub struct FxState {
    bytes: [u8; 512],
    live: bool,
}

impl FxState {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 512],
            live: false,
        }
    }
}

/// Разрешить SSE: CR0.EM=0, CR0.MP=1, CR0.TS=0, CR4.OSFXSR, CR4.OSXMMEXCPT.
pub fn enable() {
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    unsafe { Cr0::write(cr0) };

    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
    unsafe { Cr4::write(cr4) };

    reset_cpu();
}

/// Чистое x87/MXCSR (как после загрузки процесса в Linux).
pub fn reset_cpu() {
    let mxcsr = MXCSR_DEFAULT;
    unsafe {
        core::arch::asm!(
            "fninit",
            "ldmxcsr [{mx}]",
            mx = in(reg) &mxcsr,
            options(nostack),
        );
    }
}

/// Сбросить сохранённый образ: следующее восстановление сделает fninit.
pub fn forget(state: &mut FxState) {
    state.live = false;
}

/// Снять текущие xmm/x87 в `state` (снимок родителя для fork/clone).
pub fn save(state: &mut FxState) {
    let ptr = state.bytes.as_mut_ptr();
    unsafe {
        core::arch::asm!(
            "fxsave64 [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags),
        );
    }
    state.live = true;
}

/// Вернуть состояние задачи. Пустой образ — чистый FPU, не нулевой MXCSR
/// (нули сняли бы маски исключений и дали #XM).
pub fn restore(state: &FxState) {
    if !state.live {
        reset_cpu();
        return;
    }
    let ptr = state.bytes.as_ptr();
    unsafe {
        core::arch::asm!(
            "fxrstor64 [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags),
        );
    }
}

