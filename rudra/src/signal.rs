//! Сигналы 1–31 для текущего потока.
//!
//! Перехваченный сигнал с `SA_RESTORER` ставится и на возврате из syscall,
//! и когда тик таймера возвращается в ring 3. Кадр тика — не кадр syscall:
//! `deliver_pending` туда писать нельзя. Смертельный сигнал и `SIGKILL`
//! с тика не забираются: `sys_exit` встал бы в `hlt` при выключенном IF.
//! Блокирующий `read` и `nanosleep` не прерываются. На стеке нет
//! исполняемого трамплина. `SIGSTOP` и сигналы остановки сбрасываются.
//! Смерть по умолчанию — `exit(128+sig)`, статус wait выглядит как обычный
//! код выхода, не как `WIFSIGNALED`.

use crate::syscall::FRAME;
use crate::task::{self, user_read, user_write};

const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const SA_SIGINFO: u32 = 4;
const SA_RESTORER: u32 = 0x0400_0000;
const SA_RESTART: u32 = 0x1000_0000;
const SA_NODEFER: u32 = 0x4000_0000;
const SA_RESETHAND: u32 = 0x8000_0000;
const KEEP_FLAGS: u32 = SA_SIGINFO | SA_RESTORER | SA_RESTART | SA_NODEFER | SA_RESETHAND;

/// `rt_sigframe`: pretcode, ucontext (304 байта), siginfo (128 байт).
const FRAME_BYTES: usize = 440;
const MCTX: usize = 48;
const SIGMASK_AT: usize = 304;
const SIGINFO_AT: usize = 312;

#[derive(Clone, Copy)]
pub struct Signals {
    pending: u64,
    mask: u64,
    handler: [u64; 32],
    restorer: [u64; 32],
    sa_mask: [u64; 32],
    sa_flags: [u32; 32],
}

enum Pop {
    Ignored,
    Fatal(u32),
    Catch(Catch),
}

struct Catch {
    sig: u32,
    handler: u64,
    restorer: u64,
    old_mask: u64,
    flags: u32,
}

impl Signals {
    pub const fn new() -> Self {
        Self {
            pending: 0,
            mask: 0,
            handler: [0; 32],
            restorer: [0; 32],
            sa_mask: [0; 32],
            sa_flags: [0; 32],
        }
    }

    /// Потомок копирует обработчики и маску. Ожидающие сигналы — нет.
    pub fn for_child(self) -> Self {
        let mut child = self;
        child.pending = 0;
        child
    }

    fn pop(&mut self) -> Option<Pop> {
        let blocked = self.mask & !(bit(SIGKILL) | bit(SIGSTOP));
        let bits = self.pending & !blocked;
        if bits == 0 {
            return None;
        }
        let sig = bits.trailing_zeros() + 1;
        let mark = bit(sig);
        self.pending &= !mark;
        if sig == SIGKILL || (self.handler[sig as usize] == 0 && fatal_default(sig)) {
            return Some(Pop::Fatal(sig));
        }
        // SIG_DFL для игнорируемых, SIG_IGN и остановка без обработчика.
        // Настоящий адрес обрабатывается и у SIGCHLD тоже.
        if self.handler[sig as usize] <= 1 {
            return Some(Pop::Ignored);
        }
        let handler = self.handler[sig as usize];
        let restorer = self.restorer[sig as usize];
        let flags = self.sa_flags[sig as usize];
        if restorer < 0x1000 || handler < 0x1000 {
            return Some(if fatal_default(sig) {
                Pop::Fatal(sig)
            } else {
                Pop::Ignored
            });
        }
        let old_mask = self.mask;
        if flags & SA_NODEFER == 0 {
            self.mask |= mark;
        }
        self.mask |= self.sa_mask[sig as usize];
        self.mask &= !(bit(SIGKILL) | bit(SIGSTOP));
        if flags & SA_RESETHAND != 0 {
            self.handler[sig as usize] = 0;
            self.restorer[sig as usize] = 0;
            self.sa_flags[sig as usize] = 0;
        }
        Some(Pop::Catch(Catch {
            sig,
            handler,
            restorer,
            old_mask,
            flags,
        }))
    }

    fn undo(&mut self, caught: &Catch) {
        self.pending |= bit(caught.sig);
        self.mask = caught.old_mask;
        if caught.flags & SA_RESETHAND != 0 {
            self.handler[caught.sig as usize] = caught.handler;
            self.restorer[caught.sig as usize] = caught.restorer;
            self.sa_flags[caught.sig as usize] = caught.flags;
        }
    }
}

fn bit(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

fn stop_or_ignore(sig: u32) -> bool {
    matches!(sig, 17 | 18 | 19 | 20 | 21 | 22 | 23 | 28)
}

fn fatal_default(sig: u32) -> bool {
    !stop_or_ignore(sig)
}

fn put_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn get_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

fn read_frame_u64(frame: *mut u64, slot: usize) -> u64 {
    unsafe { core::ptr::read(frame.add(slot)) }
}

fn write_slot(frame: *mut u64, slot: usize, val: u64) {
    unsafe { core::ptr::write(frame.add(slot), val) }
}

/// Один перехваченный сигнал в кадр `timer_entry` / `lapic_timer_entry`.
///
/// `kernel_rsp` — указатель, который asm передал в `timer_switch`: на +0
/// лежит r15, на +120 user RIP, на +128 CS, на +136 RFLAGS, на +144 user RSP.
/// Смертельный сигнал остаётся в `pending` до возврата из syscall.
pub fn deliver_timer(kernel_rsp: u64) {
    if kernel_rsp < 0x1000 || task::current_slot() < 0 {
        return;
    }
    let cs = tread(kernel_rsp, T_CS);
    if cs & 3 != 3 {
        return;
    }
    for _ in 0..32 {
        let popped = task::with_current_task(|t| t.signals.pop());
        let Some(popped) = popped else {
            return;
        };
        match popped {
            None => return,
            Some(Pop::Ignored) => continue,
            Some(Pop::Fatal(sig)) => {
                let _ = task::with_current_task(|t| t.signals.pending |= bit(sig));
                return;
            }
            Some(Pop::Catch(caught)) => {
                if !arm_timer(kernel_rsp, &caught) {
                    let _ = task::with_current_task(|t| t.signals.undo(&caught));
                }
                return;
            }
        }
    }
}

/// Слоты кадра тика, в байтах от `kernel_rsp`. Совпадают с синтетическим
/// кадром `sys_clone`: 15 push, затем iret (rip, cs, rflags, rsp, ss).
const T_R15: usize = 0;
const T_R14: usize = 8;
const T_R13: usize = 16;
const T_R12: usize = 24;
const T_RBP: usize = 32;
const T_RBX: usize = 40;
const T_R9: usize = 64;
const T_R8: usize = 72;
const T_RDI: usize = 80;
const T_RSI: usize = 88;
const T_RDX: usize = 96;
const T_RAX: usize = 112;
const T_RIP: usize = 120;
const T_CS: usize = 128;
const T_RFLAGS: usize = 136;
const T_RSP: usize = 144;

fn tread(kernel_rsp: u64, off: usize) -> u64 {
    unsafe { core::ptr::read_unaligned((kernel_rsp + off as u64) as *const u64) }
}

fn twrite(kernel_rsp: u64, off: usize, val: u64) {
    unsafe { core::ptr::write_unaligned((kernel_rsp + off as u64) as *mut u64, val) }
}

fn arm_timer(kernel_rsp: u64, caught: &Catch) -> bool {
    let user_rsp = tread(kernel_rsp, T_RSP);
    let rip = tread(kernel_rsp, T_RIP);
    let rflags = tread(kernel_rsp, T_RFLAGS);
    let rax = tread(kernel_rsp, T_RAX);
    let mut sp = user_rsp.saturating_sub(128 + FRAME_BYTES as u64) & !15;
    sp = sp.saturating_sub(8);
    if sp < 0x1000 {
        return false;
    }
    let mut raw = [0u8; FRAME_BYTES];
    put_u64(&mut raw, 0, caught.restorer);
    let sc = MCTX;
    put_u64(&mut raw, sc + 0, tread(kernel_rsp, T_R8));
    put_u64(&mut raw, sc + 8, tread(kernel_rsp, T_R9));
    put_u64(&mut raw, sc + 24, rflags);
    put_u64(&mut raw, sc + 32, tread(kernel_rsp, T_R12));
    put_u64(&mut raw, sc + 40, tread(kernel_rsp, T_R13));
    put_u64(&mut raw, sc + 48, tread(kernel_rsp, T_R14));
    put_u64(&mut raw, sc + 56, tread(kernel_rsp, T_R15));
    put_u64(&mut raw, sc + 64, tread(kernel_rsp, T_RDI));
    put_u64(&mut raw, sc + 72, tread(kernel_rsp, T_RSI));
    put_u64(&mut raw, sc + 80, tread(kernel_rsp, T_RBP));
    put_u64(&mut raw, sc + 88, tread(kernel_rsp, T_RBX));
    put_u64(&mut raw, sc + 96, tread(kernel_rsp, T_RDX));
    put_u64(&mut raw, sc + 104, rax);
    put_u64(&mut raw, sc + 112, rip);
    put_u64(&mut raw, sc + 120, user_rsp);
    put_u64(&mut raw, sc + 128, rip);
    put_u64(&mut raw, sc + 136, rflags);
    put_u64(&mut raw, SIGMASK_AT, caught.old_mask);
    put_u32(&mut raw, SIGINFO_AT, caught.sig);
    put_u32(&mut raw, SIGINFO_AT + 16, task::current_tid() as u32);
    if !user_write(sp, &raw) {
        return false;
    }
    twrite(kernel_rsp, T_RDI, u64::from(caught.sig));
    twrite(kernel_rsp, T_RSI, sp + SIGINFO_AT as u64);
    twrite(kernel_rsp, T_RDX, sp + 8);
    twrite(kernel_rsp, T_RIP, caught.handler);
    twrite(kernel_rsp, T_RSP, sp);
    twrite(kernel_rsp, T_RFLAGS, 0x202);
    true
}

/// Поставить один ожидающий сигнал в пользовательский кадр syscall.
/// `ret` — результат syscall, который увидит sigreturn в `rax`.
pub fn deliver_pending(frame: *mut u64, ret: u64) -> u64 {
    if frame.is_null() || task::current_slot() < 0 {
        return ret;
    }
    for _ in 0..32 {
        let popped = task::with_current_task(|t| t.signals.pop());
        let Some(popped) = popped else {
            return ret;
        };
        match popped {
            None => return ret,
            Some(Pop::Ignored) => continue,
            Some(Pop::Fatal(sig)) => task::sys_exit(128 + u64::from(sig)),
            Some(Pop::Catch(caught)) => {
                if !arm_handler(frame, &caught, ret) {
                    let _ = task::with_current_task(|t| t.signals.undo(&caught));
                    return ret;
                }
                return 0;
            }
        }
    }
    ret
}

fn arm_handler(frame: *mut u64, caught: &Catch, ret: u64) -> bool {
    let user_rsp = read_frame_u64(frame, FRAME::RSP);
    let mut sp = user_rsp.saturating_sub(128 + FRAME_BYTES as u64) & !15;
    sp = sp.saturating_sub(8);
    if sp < 0x1000 {
        return false;
    }
    let mut raw = [0u8; FRAME_BYTES];
    put_u64(&mut raw, 0, caught.restorer);
    let sc = MCTX;
    put_u64(&mut raw, sc + 0, read_frame_u64(frame, FRAME::R8));
    put_u64(&mut raw, sc + 8, read_frame_u64(frame, FRAME::R9));
    put_u64(&mut raw, sc + 24, read_frame_u64(frame, FRAME::RFLAGS));
    put_u64(&mut raw, sc + 32, read_frame_u64(frame, FRAME::R12));
    put_u64(&mut raw, sc + 40, read_frame_u64(frame, FRAME::R13));
    put_u64(&mut raw, sc + 48, read_frame_u64(frame, FRAME::R14));
    put_u64(&mut raw, sc + 56, read_frame_u64(frame, FRAME::R15));
    put_u64(&mut raw, sc + 64, read_frame_u64(frame, FRAME::RDI));
    put_u64(&mut raw, sc + 72, read_frame_u64(frame, FRAME::RSI));
    put_u64(&mut raw, sc + 80, read_frame_u64(frame, FRAME::RBP));
    put_u64(&mut raw, sc + 88, read_frame_u64(frame, FRAME::RBX));
    put_u64(&mut raw, sc + 96, read_frame_u64(frame, FRAME::RDX));
    put_u64(&mut raw, sc + 104, ret);
    put_u64(&mut raw, sc + 112, read_frame_u64(frame, FRAME::RIP));
    put_u64(&mut raw, sc + 120, user_rsp);
    put_u64(&mut raw, sc + 128, read_frame_u64(frame, FRAME::RIP));
    put_u64(&mut raw, sc + 136, read_frame_u64(frame, FRAME::RFLAGS));
    put_u64(&mut raw, SIGMASK_AT, caught.old_mask);
    put_u32(&mut raw, SIGINFO_AT, caught.sig);
    put_u32(&mut raw, SIGINFO_AT + 16, task::current_tid() as u32);
    if !user_write(sp, &raw) {
        return false;
    }
    write_slot(frame, FRAME::RDI, u64::from(caught.sig));
    write_slot(frame, FRAME::RSI, sp + SIGINFO_AT as u64);
    write_slot(frame, FRAME::RDX, sp + 8);
    write_slot(frame, FRAME::RIP, caught.handler);
    write_slot(frame, FRAME::RSP, sp);
    write_slot(frame, FRAME::RFLAGS, 0x202);
    true
}

pub fn sys_rt_sigreturn(frame: *mut u64) -> u64 {
    if frame.is_null() || task::current_slot() < 0 {
        return crate::linux::EINVAL;
    }
    let user_rsp = read_frame_u64(frame, FRAME::RSP);
    let base = user_rsp.wrapping_sub(8);
    let mut raw = [0u8; FRAME_BYTES];
    if !user_read(base, &mut raw) {
        return crate::linux::EFAULT;
    }
    let sc = MCTX;
    write_slot(frame, FRAME::R8, get_u64(&raw, sc + 0));
    write_slot(frame, FRAME::R9, get_u64(&raw, sc + 8));
    write_slot(frame, FRAME::R12, get_u64(&raw, sc + 32));
    write_slot(frame, FRAME::R13, get_u64(&raw, sc + 40));
    write_slot(frame, FRAME::R14, get_u64(&raw, sc + 48));
    write_slot(frame, FRAME::R15, get_u64(&raw, sc + 56));
    write_slot(frame, FRAME::RDI, get_u64(&raw, sc + 64));
    write_slot(frame, FRAME::RSI, get_u64(&raw, sc + 72));
    write_slot(frame, FRAME::RBP, get_u64(&raw, sc + 80));
    write_slot(frame, FRAME::RBX, get_u64(&raw, sc + 88));
    write_slot(frame, FRAME::RDX, get_u64(&raw, sc + 96));
    write_slot(frame, FRAME::RSP, get_u64(&raw, sc + 120));
    write_slot(frame, FRAME::RIP, get_u64(&raw, sc + 128));
    write_slot(frame, FRAME::RFLAGS, get_u64(&raw, sc + 136) | 0x2);
    let saved_mask = get_u64(&raw, SIGMASK_AT) & !(bit(SIGKILL) | bit(SIGSTOP));
    let _ = task::with_current_task(|t| t.signals.mask = saved_mask);
    get_u64(&raw, sc + 104)
}

pub fn sys_rt_sigaction(sig: u64, act: u64, old: u64, setsize: u64) -> u64 {
    if setsize != 8 || sig == 0 || sig > 31 || sig == u64::from(SIGKILL) || sig == u64::from(SIGSTOP)
    {
        return crate::linux::EINVAL;
    }
    let Some(rc) = task::with_current_task(|t| {
        let idx = sig as usize;
        if old != 0 {
            let mut raw = [0u8; 32];
            put_u64(&mut raw, 0, t.signals.handler[idx]);
            put_u64(&mut raw, 8, u64::from(t.signals.sa_flags[idx]));
            put_u64(&mut raw, 16, t.signals.restorer[idx]);
            put_u64(&mut raw, 24, t.signals.sa_mask[idx]);
            if !user_write(old, &raw) {
                return crate::linux::EFAULT;
            }
        }
        if act != 0 {
            let mut raw = [0u8; 32];
            if !user_read(act, &mut raw) {
                return crate::linux::EFAULT;
            }
            let handler = get_u64(&raw, 0);
            let flags = get_u64(&raw, 8) as u32;
            let restorer = get_u64(&raw, 16);
            let sa_mask = get_u64(&raw, 24) & !(bit(SIGKILL) | bit(SIGSTOP));
            if handler > 1 && (handler < 0x1000 || handler >= task::USER_TOP) {
                return crate::linux::EFAULT;
            }
            if flags & SA_RESTORER != 0 && restorer != 0 && restorer < 0x1000 {
                return crate::linux::EFAULT;
            }
            t.signals.handler[idx] = handler;
            t.signals.sa_flags[idx] = flags & KEEP_FLAGS;
            t.signals.restorer[idx] = if flags & SA_RESTORER != 0 { restorer } else { 0 };
            t.signals.sa_mask[idx] = sa_mask;
        }
        0
    }) else {
        return crate::linux::EINVAL;
    };
    rc
}

pub fn sys_rt_sigprocmask(how: u64, set: u64, oldset: u64, setsize: u64) -> u64 {
    if setsize != 8 || how > 2 {
        return crate::linux::EINVAL;
    }
    let Some(rc) = task::with_current_task(|t| {
        if oldset != 0 && !user_write(oldset, &t.signals.mask.to_le_bytes()) {
            return crate::linux::EFAULT;
        }
        if set != 0 {
            let mut raw = [0u8; 8];
            if !user_read(set, &mut raw) {
                return crate::linux::EFAULT;
            }
            let bits = u64::from_le_bytes(raw) & !(bit(SIGKILL) | bit(SIGSTOP));
            t.signals.mask = match how {
                0 => t.signals.mask | bits,
                1 => t.signals.mask & !bits,
                _ => bits,
            };
            t.signals.mask &= !(bit(SIGKILL) | bit(SIGSTOP));
        }
        0
    }) else {
        return crate::linux::EINVAL;
    };
    rc
}

pub fn sys_kill(pid: u64, sig: u64) -> u64 {
    if sig > 31 || task::current_slot() < 0 {
        return crate::linux::EINVAL;
    }
    let me = task::current_tid();
    if pid != me && task::with_task(pid, |_| ()).is_none() {
        return crate::linux::ESRCH;
    }
    if sig == 0 {
        return 0;
    }
    if sig == u64::from(SIGKILL) && pid == me {
        task::sys_exit(128 + u64::from(SIGKILL));
    }
    let mark = bit(sig as u32);
    let armed = if pid == me {
        task::with_current_task(|t| t.signals.pending |= mark).is_some()
    } else {
        task::with_task(pid, |t| t.signals.pending |= mark).is_some()
    };
    if armed {
        0
    } else {
        crate::linux::ESRCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn sigkill_is_fatal_even_when_masked() {
        crate::serial_print!("test sigkill_is_fatal_even_when_masked... ");
        let mut signals = Signals::new();
        signals.mask = u64::MAX;
        signals.pending = bit(SIGKILL) | bit(17);
        match signals.pop() {
            Some(Pop::Fatal(9)) => {}
            _ => panic!("SIGKILL masked"),
        }
        signals.mask = 0;
        match signals.pop() {
            Some(Pop::Ignored) => {}
            _ => panic!("SIGCHLD default"),
        }
        assert!(signals.pop().is_none());
        signals.pending = bit(SIGSTOP);
        match signals.pop() {
            Some(Pop::Ignored) => {}
            _ => panic!("SIGSTOP"),
        }
        assert_eq!(sys_rt_sigaction(10, 0, 0, 8), crate::linux::EINVAL);
        assert_eq!(sys_kill(1, 10), crate::linux::EINVAL);
        crate::serial_println!("[ok]");
    }
}
