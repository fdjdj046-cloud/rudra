use crate::{gdt, serial_print, serial_println};
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::{self, Mutex};
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

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
    fn as_u8(self) -> u8 {
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
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_u8()].set_handler_fn(keyboard_interrupt_handler);
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
    serial_println!("EXCEPTION: PAGE FAULT");
    serial_println!("  accessed address (CR2): {:?}", accessed);
    serial_println!("  error code: {:?}", error_code);
    serial_println!("  {:#?}", stack_frame);
    panic!("page fault at {:?}, code {:?}", accessed, error_code);
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_println!("EXCEPTION: GENERAL PROTECTION FAULT, code {:#x}", error_code);
    serial_println!("  {:#?}", stack_frame);
    panic!("general protection fault, code {:#x}", error_code);
}

static TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    let ticks = TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    // PIT по умолчанию ~18.2 Гц: раз в ~100 тиков (~5 с) печатаем heartbeat.
    if ticks % 100 == 0 {
        serial_println!("timer: {} ticks (~{} s)", ticks, ticks / 18);
    }
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
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
                DecodedKey::Unicode(c) => serial_print!("{}", c),
                DecodedKey::RawKey(k) => serial_println!("\n[key: {:?}]", k),
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
