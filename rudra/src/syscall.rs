//! Интерфейс syscall/sysret между ring 3 и ядром.
//!
//! Конвенция (Linux ABI): rax = номер, rdi/rsi/rdx/r10/r8/r9 = аргументы,
//! возврат в rax. Диспетчеризация — в `linux::dispatch`.
//!
//! syscall НЕ переключает стек сам — entry после `swapgs` читает вершину
//! kernel-стека из слота GS этого CPU (`cpu::GsSlot::kstack`).
//! Шестым аргументом в диспетчер передаётся указатель на сохранённый
//! фрейм (нужен clone/fork/execve — см. `FRAME`).

use x86_64::registers::model_specific::{Efer, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

/// Смещения (в u64-слотах от rsp) в сохранённом фрейме syscall_entry.
/// Порядок push'ей: user-rsp, rcx, r11, rax, rdi, rsi, rdx, r8, r9, rbx, rbp, r12..r15.
/// Слот RSP — это user-rsp, не исходный r10: arg4 передаётся в диспетчер из регистра.
pub mod FRAME {
    pub const R15: usize = 0;
    pub const R14: usize = 1;
    pub const R13: usize = 2;
    pub const R12: usize = 3;
    pub const RBP: usize = 4;
    pub const RBX: usize = 5;
    pub const R9: usize = 6;
    pub const R8: usize = 7;
    pub const RDX: usize = 8;
    pub const RSI: usize = 9;
    pub const RDI: usize = 10;
    pub const RAX: usize = 11;
    pub const RFLAGS: usize = 12;
    pub const RIP: usize = 13;
    pub const RSP: usize = 14;
}

/// Вершина kernel-стека задачи на том CPU, который нас позвал.
pub fn set_current_kstack(top: u64) {
    crate::cpu::set_kstack(crate::smp::this_cpu(), top);
}

/// Запасной стек BSP, пока ни одна задача не выставила свой.
pub fn boot_kstack_top() -> u64 {
    extern "C" {
        static syscall_boot_stack_top: u8;
    }
    core::ptr::addr_of!(syscall_boot_stack_top) as u64
}

core::arch::global_asm!(r#"
    .section .bss
    .global syscall_boot_stack
syscall_boot_stack:
    .space 32768
    .global syscall_boot_stack_top
syscall_boot_stack_top:

    .text
    .global syscall_entry
syscall_entry:
    # На входе: rax=nr, rdi/rsi/rdx/r10/r8/r9=args, rcx=user rip, r11=user
    # rflags, IF очищен через SFMask. Стек — пользовательский.
    # swapgs: GS_BASE становится слотом CPU, пользовательский GS уходит
    # в KERNEL_GS_BASE. r10 — Linux-arg4, его НЕЛЬЗЯ затирать: user-rsp
    # лежит в gs:0, вершина kernel-стека — в gs:8.
    swapgs
    mov qword ptr gs:[0], rsp
    mov rsp, qword ptr gs:[8]
    test rsp, rsp
    jnz 1f
    lea rsp, [rip + syscall_boot_stack_top]
1:
    push qword ptr gs:[0]       # user rsp
    push rcx                    # user rip
    push r11                    # user rflags
    push rax                    # nr
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    # Стек (top=rsp): r15,r14,r13,r12,rbp,rbx,r9,r8,rdx,rsi,rdi,rax,r11,rcx,user-rsp
    # r10 всё ещё содержит настоящий arg4.
    # 15 пушей оставляют rsp кратным 8, но не 16. call тогда входит в Rust
    # с rsp ≡ 0 (mod 16), а psABI требует ≡ 8 — иначе align(16) локали
    # (образ FXSAVE) попадают на #GP. rbx уже сохранён, держим в нём фрейм.
    mov rbx, rsp
    mov rdi, [rbx + 11*8]       # nr
    mov rsi, [rbx + 10*8]       # arg1 (rdi)
    mov rdx, [rbx + 9*8]        # arg2 (rsi)
    mov rcx, [rbx + 8*8]        # arg3 (rdx)
    mov r8, r10                 # arg4 (настоящий r10, не user-rsp)
    mov r9, rbx                 # arg6: указатель на фрейм (arg5/6 оттуда)
    and rsp, -16
    sti
    call syscall_dispatch
    cli
    mov rsp, rbx
    # rax = возврат, кладём в слот rax на стеке
    mov [rsp + 11*8], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    add rsp, 8                  # слот rax: значение уже в rax
    pop r11
    pop rcx
    pop r10
    mov rsp, r10                # обратно на user-стек
    swapgs
    sysretq
"#);

extern "C" {
    fn syscall_entry();
}

/// Адрес asm-обработчика syscall (через fn-указатель — иначе линт
/// о прямом касте fn-item в integer).
fn entry_addr() -> u64 {
    let f: unsafe extern "C" fn() = syscall_entry;
    f as u64
}

/// Настроить EFER.SCE, LSTAR, STAR, SFMASK.
pub fn init() {
    use x86_64::registers::model_specific::EferFlags;
    unsafe { Efer::update(|efer| efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS)) };

    let (user_data, user_code) = crate::gdt::user_segments();
    let s = &crate::gdt::GDT.get().expect("gdt not initialized").1;
    Star::write(
        user_code,  // cs_sysret (0x30|3)
        user_data,  // ss_sysret (0x28|3)
        s.code,     // cs_syscall (0x08)
        s.data,     // ss_syscall (0x10)
    )
    .expect("invalid STAR segment selectors");
    LStar::write(VirtAddr::new(entry_addr()));
    // На входе в syscall гасим IF: сохранимся на kernel-стеке, потом sti.
    SFMask::write(RFlags::INTERRUPT_FLAG);
}

/// Диспетчер системных вызовов (вызывается из asm, frame — сохранённый
/// стековый фрейм; linux::dispatch сама знает про номера Linux ABI).
#[no_mangle]
extern "C" fn syscall_dispatch(
    nr: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    frame: *mut u64,
) -> u64 {
    let ret = crate::linux::dispatch(nr, a1, a2, a3, a4, frame);
    crate::signal::deliver_pending(frame, ret)
}
