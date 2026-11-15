//! Интерфейс syscall/sysret между ring 3 и ядром.
//!
//! Конвенция: rax = номер, rdi/rsi/rdx = аргументы 1-3, возврат в rax.
//! Номера: 1 = write(ptr, len), 2 = exit(code).
//!
//! syscall НЕ переключает стек сам — entry переключается на kernel-стек
//! текущей задачи (см. `CURRENT_KSTACK`), обновляемый планировщиком.

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::model_specific::{Efer, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

/// Вершина kernel-стека текущей задачи (для syscall entry).
#[no_mangle]
pub static CURRENT_KSTACK: AtomicU64 = AtomicU64::new(0);

pub fn set_current_kstack(top: u64) {
    CURRENT_KSTACK.store(top, Ordering::Release);
}

core::arch::global_asm!(r#"
    .section .bss
    .global syscall_boot_stack
syscall_boot_stack:
    .space 32768
syscall_boot_stack_top:

    .text
    .global syscall_entry
syscall_entry:
    # На входе: rax=nr, rdi/rsi/rdx=args, rcx=user rip, r11=user rflags,
    # IF очищен через SFMask. Стек — пользовательский.
    mov r10, rsp
    mov rsp, qword ptr [rip + CURRENT_KSTACK]
    test rsp, rsp
    jnz 1f
    lea rsp, [rip + syscall_boot_stack_top]
1:
    push r10                    # user rsp
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

    # Стек (top=rsp): r15,r14,r13,r12,rbp,rbx,r9,r8,rdx,rsi,rdi,rax,r11,rcx,r10
    mov rdi, [rsp + 11*8]       # nr
    mov rsi, [rsp + 10*8]       # arg1
    mov rdx, [rsp + 9*8]        # arg2
    mov rcx, [rsp + 8*8]        # arg3
    sti
    call syscall_dispatch
    cli
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
    sysretq
"#);

extern "C" {
    fn syscall_entry();
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
    LStar::write(VirtAddr::new(syscall_entry as u64));
    // На входе в syscall гасим IF: сохранимся на kernel-стеке, потом sti.
    SFMask::write(RFlags::INTERRUPT_FLAG);
}

/// Диспетчер системных вызовов (вызывается из asm).
///
/// Номера: 1=write(ptr,len), 2=exit(code), 3=read(buf,len) — блокирующий,
/// 4=yield, 5=spawn(program_id).
#[no_mangle]
extern "C" fn syscall_dispatch(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    match nr {
        1 => sys_write(a1 as *const u8, a2 as usize),
        2 => sys_exit(a1),
        3 => sys_read(a1 as *mut u8, a2 as usize),
        4 => 0, // yield: PIT и так вытесняет; syscall для симметрии API
        5 => crate::task::spawn(a1),
        _ => {
            crate::serial_println!("[syscall] unknown nr={} args={},{},{}", nr, a1, a2, a3);
            u64::MAX
        }
    }
}

fn sys_write(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    // Побайтовый вывод: serial и экран раздельно (иначе serial получит
    // дубль, т.к. framebuffer::_print сам печатает в serial).
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    for &b in slice {
        if b == b'\n' || (0x20..=0x7e).contains(&b) {
            crate::serial::_print(core::format_args!("{}", b as char));
            crate::framebuffer::_print_screen(core::format_args!("{}", b as char));
        }
    }
    len as u64
}

/// Блокирующее чтение одного байта из очереди клавиатуры.
/// IF остаётся включённым (мы после sti в entry): таймер вытесняет задачу,
/// клавиатура пополняет очередь.
fn sys_read(ptr: *mut u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    loop {
        let b = crate::input::INPUT_QUEUE.lock().pop();
        if let Some(b) = b {
            unsafe { ptr.write(b) };
            return 1;
        }
        core::hint::spin_loop();
    }
}

fn sys_exit(code: u64) -> u64 {
    crate::serial_println!("[syscall] task {} exited with code {}", crate::task::current_slot(), code);
    crate::task::exit_current();
    // Планировщик больше не выберет эту задачу; тикаем hlt до конца таймсов.
    loop {
        x86_64::instructions::hlt();
    }
}
