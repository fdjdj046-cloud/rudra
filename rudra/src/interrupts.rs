use crate::{gdt, serial_println};
use core::sync::atomic::AtomicU64;
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::{self, Mutex};
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// Счётчик тиков планировщика. После `apic::start_timer` это LAPIC ~250 Гц,
/// иначе IRQ0 PIT (~18.2 Гц).
pub static TICKS: AtomicU64 = AtomicU64::new(0);

/// Тики по CPU (для `cpuN` в `/proc/stat` и наблюдаемости балансировки).
pub static PER_CPU_TICKS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];

/// Разложение тика: пользователь, ядро, простой. Сумма по CPU — поля `/proc/stat`.
pub static USER_TICKS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
pub static SYS_TICKS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
pub static IDLE_TICKS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];

/// Аптайм в миллисекундах по TSC. `TICKS` — счётчик тиков планировщика, не часы.
pub fn uptime_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// Chained PICs, ремаппленные на векторы 32..=47 (чтобы не пересекаться с CPU exceptions).
pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        // Таймер — asm-обработчик (полное сохранение регистров + переключение задач).
        unsafe {
            idt[InterruptIndex::Timer.as_u8()].set_handler_addr(x86_64::VirtAddr::new(
                crate::task::timer_handler_addr(),
            ));
        }
        idt[InterruptIndex::Keyboard.as_u8()].set_handler_fn(keyboard_interrupt_handler);
        unsafe {
            idt[crate::apic::TIMER_VECTOR].set_handler_addr(x86_64::VirtAddr::new(
                crate::task::lapic_timer_handler_addr(),
            ));
        }
        idt[0xFFu8].set_handler_fn(spurious_apic_handler);
        idt[crate::smp::IPI_VECTOR].set_handler_fn(apic_ipi_handler);
        idt[crate::smp::MB_VECTOR].set_handler_fn(membarrier_ipi_handler);
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

/// Ремаппинг и маскирование PIC. Вызывать после загрузки IDT.
///
/// # Safety
/// Требует корректной инициализации контроллеров прерываний (стандартный flow).
pub unsafe fn init_pics() {
    PICS.lock().initialize();
}

/// Замаскировать IRQ0. Планировщик перешёл на таймер локального APIC.
pub fn mask_pit() {
    // Клавиатурный IRQ тоже берёт `PICS`. IF должен быть выключен на время лока.
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        let mut pics = PICS.lock();
        let masks = pics.read_masks();
        pics.write_masks(masks[0] | 1, masks[1]);
    });
}

/// Снова пустить IRQ0, если таймер APIC не завёлся.
pub fn unmask_pit() {
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        let mut pics = PICS.lock();
        let masks = pics.read_masks();
        pics.write_masks(masks[0] & !1, masks[1]);
    });
}

/// Замаскировать линию IRQ на PIC. Таймер (0) маскирует только `mask_pit`.
/// Клавиатуру (1) и каскад (2) не трогаем.
pub fn mask_irq(irq: u8) {
    if !(3..16).contains(&irq) {
        return;
    }
    unsafe {
        let mut pics = PICS.lock();
        let masks = pics.read_masks();
        let (mut m0, mut m1) = (masks[0], masks[1]);
        if irq < 8 {
            m0 |= 1 << irq;
        } else {
            m1 |= 1 << (irq - 8);
        }
        pics.write_masks(m0, m1);
    }
}

extern "x86-interrupt" fn spurious_apic_handler(_stack_frame: InterruptStackFrame) {}

extern "x86-interrupt" fn apic_ipi_handler(_stack_frame: InterruptStackFrame) {
    crate::smp::on_ipi();
    crate::apic::eoi();
}

extern "x86-interrupt" fn membarrier_ipi_handler(_stack_frame: InterruptStackFrame) {
    crate::smp::on_membarrier_ipi();
    crate::apic::eoi();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let accessed = x86_64::registers::control::Cr2::read();
    // Fault из ring 3 — убиваем задачу, а не всю систему: таймер уведёт
    // управление на другую задачу (см. task::exit_current).
    if stack_frame.code_segment.0 & 0x3 == 3 {
        serial_println!(
            "[task {}] PAGE FAULT at {:?}, code {:?}, rip {:#x} rsp {:#x} — killing task",
            crate::task::current_slot(),
            accessed,
            error_code,
            stack_frame.instruction_pointer.as_u64(),
            stack_frame.stack_pointer.as_u64(),
        );
        kill_user_and_yield();
    }
    // Копирование указателя syscall идёт в режиме ядра. Несмапленный
    // пользовательский адрес не должен ронять ядро: задача умирает, шелл жив.
    // Адрес ядра (выше USER_TOP) по-прежнему паника — это баг ядра.
    if crate::task::current_slot() >= 0 {
        if let Ok(addr) = accessed {
            if addr.as_u64() < crate::task::USER_TOP {
                // Убиваем задачу, чтобы шелл жил. Это может прятать баг ядра:
                // fault случился в ring 0, а не в коде пользователя.
                serial_println!(
                    "[task {}] KERNEL PAGE FAULT below 4GiB in ring 0 — killing task (may hide a kernel bug)",
                    crate::task::current_slot(),
                );
                serial_println!(
                    "  CR2 {:?} code {:?} rip {:#x} rsp {:#x} cs {:#x}",
                    addr,
                    error_code,
                    stack_frame.instruction_pointer.as_u64(),
                    stack_frame.stack_pointer.as_u64(),
                    stack_frame.code_segment.0,
                );
                kill_user_and_yield();
            }
        }
    }
    serial_println!("EXCEPTION: PAGE FAULT");
    serial_println!("  accessed address (CR2): {:?}", accessed);
    serial_println!("  error code: {:?}", error_code);
    if let Ok(addr) = accessed {
        dump_page_tables(addr.as_u64());
    }
    serial_println!("  {:#?}", stack_frame);
    panic!("page fault at {:?}, code {:?}", accessed, error_code);
}

/// Задача в ring 3 смертельна для себя, но не для ядра: помечаем её
/// завершённой и открываем прерывания, чтобы таймер переключил контекст.
fn kill_user_and_yield() -> ! {
    crate::task::exit_current();
    x86_64::instructions::interrupts::enable();
    loop {
        x86_64::instructions::hlt();
    }
}

/// Обход таблиц страниц для адреса: печатаем present-флаги по уровням.
fn dump_page_tables(addr: u64) {
    use x86_64::structures::paging::PageTable;
    use x86_64::structures::paging::page_table::PageTableLevel;
    let phys_offset = x86_64::VirtAddr::new(crate::PHYS_OFFSET.load(core::sync::atomic::Ordering::Relaxed));
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    serial_println!("  [pt] CR3 = {:?}", l4_frame.start_address());
    let mut frame = l4_frame;
    for level in [PageTableLevel::Four, PageTableLevel::Three, PageTableLevel::Two, PageTableLevel::One] {
        let table = unsafe { &*((phys_offset + frame.start_address().as_u64()).as_mut_ptr() as *const PageTable) };
        let idx = match level {
            PageTableLevel::Four => (addr >> 39) & 0x1ff,
            PageTableLevel::Three => (addr >> 30) & 0x1ff,
            PageTableLevel::Two => (addr >> 21) & 0x1ff,
            PageTableLevel::One => (addr >> 12) & 0x1ff,
        };
        let entry = &table[idx as usize];
        serial_println!(
            "  [pt] L{}[{}] = {:#x} present={}",
            level as u8, idx, entry.addr().as_u64(), entry.flags().contains(x86_64::structures::paging::PageTableFlags::PRESENT)
        );
        if !entry.flags().contains(x86_64::structures::paging::PageTableFlags::PRESENT) {
            return;
        }
        match x86_64::structures::paging::PhysFrame::from_start_address(entry.addr()) {
            Ok(f) => frame = f,
            Err(_) => return, // huge page
        }
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    if stack_frame.code_segment.0 & 0x3 == 3 {
        serial_println!(
            "[task {}] #UD rip {:#x} rsp {:#x} — killing task",
            crate::task::current_slot(),
            stack_frame.instruction_pointer.as_u64(),
            stack_frame.stack_pointer.as_u64(),
        );
        kill_user_and_yield();
    }
    serial_println!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
    panic!("invalid opcode");
}

extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    if stack_frame.code_segment.0 & 0x3 == 3 {
        serial_println!(
            "[task {}] #NM rip {:#x} — killing task",
            crate::task::current_slot(),
            stack_frame.instruction_pointer.as_u64(),
        );
        kill_user_and_yield();
    }
    serial_println!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
    panic!("device not available");
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    if stack_frame.code_segment.0 & 0x3 == 3 {
        serial_println!(
            "[task {}] GENERAL PROTECTION FAULT, code {:#x} rip {:#x} rsp {:#x} — killing task",
            crate::task::current_slot(),
            error_code,
            stack_frame.instruction_pointer.as_u64(),
            stack_frame.stack_pointer.as_u64(),
        );
        kill_user_and_yield();
    }
    serial_println!("EXCEPTION: GENERAL PROTECTION FAULT, code {:#x}", error_code);
    serial_println!("  {:#?}", stack_frame);
    panic!("general protection fault, code {:#x}", error_code);
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use x86_64::instructions::port::Port;

    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(
                ScancodeSet1::new(),
                layouts::Us104Key,
                HandleControl::Ignore
            ));
    }

    let mut port = Port::<u8>::new(0x60);
    let scancode: u8 = unsafe { port.read() };

    let mut keyboard = KEYBOARD.lock();
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                // Символы уходят в очередь ввода — эхо делает user-программа
                // (шелл). В serial больше не дублируем, чтобы не смешивать
                // отладочный вывод с сессией шелла.
                DecodedKey::Unicode(c) => {
                    crate::input::with_input(|q| q.push(c as u8));
                }
                DecodedKey::RawKey(_) => {}
            }
        }
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn breakpoint_exception() {
        serial_print!("test breakpoint_exception... ");
        // int3 вызывает breakpoint_handler, печатает стек и возвращается.
        x86_64::instructions::interrupts::int3();
        serial_println!("[ok]");
    }
}
