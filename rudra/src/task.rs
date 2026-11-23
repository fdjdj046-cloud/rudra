//! Задачи userspace (ring 3), адресные пространства и round-robin планировщик.
//!
//! Адресное пространство (AddressSpace) — самостоятельная сущность с
//! refcount (Arc): несколько потоков одного процесса разделяют одно АП
//! (CLONE_VM), fork делает глубокую копию. Каждая задача имеет свой
//! kernel-стек; переключение — в обработчике таймера (asm `timer_entry`):
//! сохраняем регистры на kernel-стеке, в Rust-коде (timer_switch) меняем
//! CR3/TSS/syscall-стек/fs_base, возвращаем rsp следующей задачи.
//!
//! Раскладка userspace (всё в L4[0], 0..0x80_0000_0000):
//!   0x400000        ELF-образ (PT_LOAD)
//!   0x800000        ELF интерпретатора, если у программы есть PT_INTERP
//!   0x600000        резерв (раньше — страница аргумента)
//!   0x2000000       ET_DYN из DT_NEEDED, шаг 2 МиБ, ниже brk
//!   0x40000000      main-стек (растёт вниз от USER_STACK_TOP)
//!   0x10000000      brk-heap (растёт вверх до BRK_MAX)
//!   0x50000000      mmap-регион (bump вверх)
//!   0x70000000      стеки потоков (по 1 МиБ на поток)

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{
    AtomicBool, AtomicI64, AtomicIsize, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::PhysAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
    Size4KiB, Translate,
};
use x86_64::VirtAddr;

use crate::gdt;
use crate::memory::{active_level_4_table, BootInfoFrameAllocator};
use crate::syscall::FRAME;
use crate::{serial_println, syscall};

pub const USER_STACK_TOP: u64 = 0x4000_0000;
pub const USER_STACK_SIZE: u64 = 256 * 1024;
/// Пользовательские адреса строго ниже этой границы.
/// Куча ядра (`0x4444_4444_0000`) и physmap выше, поэтому адрес ядра
/// в аргументе syscall сюда не попадает.
pub const USER_TOP: u64 = 0x1_0000_0000;
pub const BRK_BASE: u64 = 0x1000_0000;
pub const BRK_MAX: u64 = 0x5000_0000;
pub const MMAP_BASE: u64 = 0x5000_0000;
pub const MMAP_TOP: u64 = 0x6000_0000;
pub const THREAD_STACK_BASE: u64 = 0x7000_0000;
pub const THREAD_STACK_SIZE: u64 = 1024 * 1024;
pub const MAX_THREADS_PER_PROC: u64 = 32;

const KERNEL_STACK_SIZE: usize = 64 * 1024;

pub const MAX_TASKS: usize = 32;

/// Результат загрузки ELF: точка входа и вершина user-стека (с argv/auxv).
pub struct LoadedImage {
    pub entry: u64,
    pub user_rsp: u64,
}

// ---- ELF64 ----

struct LoadSeg {
    offset: u64,
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ElfKind {
    Exec,
    Dyn,
}

struct RelaRel {
    offset: u64,
    addend: u64,
    /// st_value до базы определившего объекта. None — это R_X86_64_RELATIVE
    /// либо ещё не связанный внешний символ.
    sym: Option<u64>,
    /// База объекта, который определил символ. None — применить базу того
    /// объекта, в котором лежит релокация (свой символ или RELATIVE).
    def_bias: Option<u64>,
    /// Внешний символ: в этом объекте его нет, его закроет связь DT_NEEDED.
    ext: Option<ExtSym>,
}

#[derive(Clone)]
struct ExtSym {
    name: Vec<u8>,
    weak: bool,
}

struct DynSym {
    symtab: Option<usize>,
    syment: u64,
    strtab: Option<usize>,
    nchain: u64,
}

impl DynSym {
    const fn none() -> Self {
        Self {
            symtab: None,
            syment: 24,
            strtab: None,
            nchain: 0,
        }
    }
}

struct ElfParsed {
    kind: ElfKind,
    entry: u64,
    phdr_vaddr: u64,
    phnum: u64,
    segments: Vec<LoadSeg>,
    interp: Option<String>,
    relative: Vec<RelaRel>,
    needed: Vec<String>,
    dynsym: DynSym,
}

struct ParsedDyn {
    rels: Vec<RelaRel>,
    needed: Vec<String>,
    dynsym: DynSym,
}

enum LocalSym {
    /// st_value, к нему прибавится база этого объекта.
    Own(u64),
    /// SHN_ABS: значение уже абсолютное, базу не прибавлять.
    Abs(u64),
    Ext { name: Vec<u8>, weak: bool },
}

fn rd16(b: &[u8], off: usize) -> u64 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) as u64
}
fn rd32(b: &[u8], off: usize) -> u64 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as u64
}
fn rd64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// ELF64 x86_64, ET_EXEC или ET_DYN. PT_INTERP запоминается, а не отвергается.
/// Релокации: `R_X86_64_RELATIVE`, `R_X86_64_64`, `R_X86_64_GLOB_DAT` и
/// `R_X86_64_JUMP_SLOT` (в `DT_RELA` и в `DT_JMPREL`, если `DT_PLTREL` —
/// RELA). Символ, определённый в этом объекте, берётся сразу. `SHN_UNDEF`
/// ищется здесь же по имени, иначе остаётся внешним до связи `DT_NEEDED`.
/// Граница `.dynsym` — `nchain` из `DT_HASH`. Без хеша символьная релокация
/// отвергается. `DT_REL` отвергается. Прочие типы — отказ.
fn parse_elf64(elf: &[u8]) -> Option<ElfParsed> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 {
        return None;
    }
    let etype = rd16(elf, 16);
    let machine = rd16(elf, 18);
    let kind = match etype {
        2 => ElfKind::Exec,
        3 => ElfKind::Dyn,
        _ => return None,
    };
    if machine != 62 {
        return None;
    }
    let entry = rd64(elf, 24);
    let phoff = rd64(elf, 32);
    let phentsize = rd16(elf, 54) as usize;
    let phnum = rd16(elf, 56) as usize;
    if phentsize < 56 || phnum == 0 || phnum > 64 {
        return None;
    }
    let mut segs = Vec::new();
    let mut phdr_vaddr = 0u64;
    let mut interp: Option<String> = None;
    let mut dyn_span: Option<(usize, usize)> = None;
    for i in 0..phnum {
        let base = (phoff as usize).checked_add(i.checked_mul(phentsize)?)?;
        if base + 56 > elf.len() {
            return None;
        }
        let p_type = rd32(elf, base);
        let off = rd64(elf, base + 8);
        let vaddr = rd64(elf, base + 16);
        let file_size = rd64(elf, base + 32);
        let mem_size = rd64(elf, base + 40);
        if p_type == 3 {
            if interp.is_some() || file_size == 0 || file_size > 128 {
                return None;
            }
            let start = off as usize;
            let end = start.checked_add(file_size as usize)?;
            if end > elf.len() {
                return None;
            }
            let raw = &elf[start..end];
            let n = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            let text = core::str::from_utf8(&raw[..n]).ok()?;
            if text.is_empty() || !text.starts_with('/') {
                return None;
            }
            interp = Some(String::from(text));
        } else if p_type == 2 {
            let start = off as usize;
            let end = start.checked_add(file_size as usize)?;
            if end > elf.len() || file_size > 1 << 20 {
                return None;
            }
            dyn_span = Some((start, end));
        } else if p_type == 1 {
            let seg = LoadSeg {
                offset: off,
                vaddr,
                file_size,
                mem_size,
            };
            if phdr_vaddr == 0 && phoff >= seg.offset && phoff < seg.offset + seg.file_size {
                phdr_vaddr = seg.vaddr + (phoff - seg.offset);
            }
            segs.push(seg);
        }
    }
    if segs.is_empty() {
        return None;
    }
    let (relative, needed, dynsym) = match dyn_span {
        Some((start, end)) => {
            let parsed = parse_relative(elf, &segs, &elf[start..end])?;
            (parsed.rels, parsed.needed, parsed.dynsym)
        }
        None => (Vec::new(), Vec::new(), DynSym::none()),
    };
    Some(ElfParsed {
        kind,
        entry,
        phdr_vaddr,
        phnum: phnum as u64,
        segments: segs,
        interp,
        relative,
        needed,
        dynsym,
    })
}

/// Имя в таблице строк. Пустое имя — `Ok(None)`. Выход за файл — ошибка.
fn sym_name(elf: &[u8], strtab: usize, name_off: usize) -> Result<Option<&[u8]>, ()> {
    let Some(start) = strtab.checked_add(name_off) else {
        return Err(());
    };
    if start >= elf.len() {
        return Err(());
    }
    if elf[start] == 0 {
        return Ok(None);
    }
    let Some(rel) = elf[start..].iter().position(|b| *b == 0) else {
        return Err(());
    };
    Ok(Some(&elf[start..start + rel]))
}

fn local_defined(elf: &[u8], ent: usize, shndx: u64) -> Option<LocalSym> {
    if shndx == 0xfff2 || shndx == 0xffff {
        return None;
    }
    let val = rd64(elf, ent + 8);
    if shndx == 0xfff1 {
        Some(LocalSym::Abs(val))
    } else {
        Some(LocalSym::Own(val))
    }
}

/// Символ по индексу внутри этого объекта. Определённый — его st_value.
/// SHN_UNDEF ищется по имени среди определённых. Если здесь его нет, это
/// внешний символ: связь с DT_NEEDED закроет его позже.
fn resolve_local(
    elf: &[u8],
    symtab: usize,
    syment: u64,
    strtab: usize,
    nchain: u64,
    idx: u64,
) -> Option<LocalSym> {
    if syment < 24 || idx >= nchain {
        return None;
    }
    let ent = symtab.checked_add((idx as usize).checked_mul(syment as usize)?)?;
    if ent.checked_add(24)? > elf.len() {
        return None;
    }
    let shndx = rd16(elf, ent + 6);
    let bind = elf[ent + 4] >> 4;
    if shndx != 0 {
        return local_defined(elf, ent, shndx);
    }
    let name = match sym_name(elf, strtab, rd32(elf, ent) as usize) {
        Ok(Some(n)) => n,
        _ => return None,
    };
    for i in 0..nchain {
        let e = symtab.checked_add((i as usize).checked_mul(syment as usize)?)?;
        if e + 24 > elf.len() {
            return None;
        }
        let sx = rd16(elf, e + 6);
        if sx == 0 {
            continue;
        }
        let other = match sym_name(elf, strtab, rd32(elf, e) as usize) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(()) => return None,
        };
        if other == name {
            return local_defined(elf, e, sx);
        }
    }
    if name.len() > 256 {
        return None;
    }
    Some(LocalSym::Ext {
        name: name.to_vec(),
        weak: bind == 2,
    })
}

fn parse_relative(elf: &[u8], segs: &[LoadSeg], dynamic: &[u8]) -> Option<ParsedDyn> {
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_PLTRELSZ: u64 = 2;
    const DT_HASH: u64 = 4;
    const DT_STRTAB: u64 = 5;
    const DT_SYMTAB: u64 = 6;
    const DT_RELA: u64 = 7;
    const DT_RELASZ: u64 = 8;
    const DT_RELAENT: u64 = 9;
    const DT_SYMENT: u64 = 11;
    const DT_REL: u64 = 17;
    const DT_RELSZ: u64 = 18;
    const DT_PLTREL: u64 = 20;
    const DT_JMPREL: u64 = 23;
    const R_X86_64_64: u64 = 1;
    const R_GLOB_DAT: u64 = 6;
    const R_JUMP_SLOT: u64 = 7;
    const R_RELATIVE: u64 = 8;
    let mut rela_addr = 0u64;
    let mut rela_sz = 0u64;
    let mut rela_ent = 24u64;
    let mut saw_rela = false;
    let mut strtab = 0u64;
    let mut saw_strtab = false;
    let mut symtab = 0u64;
    let mut saw_symtab = false;
    let mut syment = 24u64;
    let mut hash_addr = 0u64;
    let mut rel_addr = 0u64;
    let mut rel_sz = 0u64;
    let mut jmprel = 0u64;
    let mut pltrelsz = 0u64;
    let mut pltrel = 0u64;
    let mut needed_off: Vec<u64> = Vec::new();
    let mut i = 0;
    while i + 16 <= dynamic.len() {
        let tag = rd64(dynamic, i);
        let val = rd64(dynamic, i + 8);
        i += 16;
        if tag == DT_NULL {
            break;
        } else if tag == DT_NEEDED {
            if needed_off.len() >= 32 {
                return None;
            }
            needed_off.push(val);
        } else if tag == DT_PLTRELSZ {
            pltrelsz = val;
        } else if tag == DT_RELA {
            rela_addr = val;
            saw_rela = true;
        } else if tag == DT_RELASZ {
            rela_sz = val;
        } else if tag == DT_RELAENT {
            rela_ent = val;
        } else if tag == DT_STRTAB {
            strtab = val;
            saw_strtab = true;
        } else if tag == DT_SYMTAB {
            symtab = val;
            saw_symtab = true;
        } else if tag == DT_SYMENT {
            syment = val;
        } else if tag == DT_HASH {
            hash_addr = val;
        } else if tag == DT_REL {
            rel_addr = val;
        } else if tag == DT_RELSZ {
            rel_sz = val;
        } else if tag == DT_PLTREL {
            pltrel = val;
        } else if tag == DT_JMPREL {
            jmprel = val;
        }
    }
    // REL (не RELA) не применяется. Молча пропустить — значит оставить нули.
    if rel_addr != 0 || rel_sz != 0 {
        return None;
    }
    if jmprel != 0 && (pltrel != DT_RELA || pltrelsz == 0) {
        return None;
    }
    let strtab_off = if saw_strtab {
        Some(vaddr_file_off(segs, strtab)? as usize)
    } else {
        None
    };
    let mut needed = Vec::new();
    if !needed_off.is_empty() {
        let base = strtab_off?;
        for off in needed_off {
            let at = base.checked_add(off as usize)?;
            let raw = sym_name(elf, 0, at).ok()??;
            let text = core::str::from_utf8(raw).ok()?;
            if text.len() > 200 {
                return None;
            }
            needed.push(String::from(text));
        }
    }
    let symtab_off = if saw_symtab {
        Some(vaddr_file_off(segs, symtab)? as usize)
    } else {
        None
    };
    // Граница .dynsym — nchain из DT_HASH. Без таблицы символьную релокацию
    // не резолвим: обходить .dynsym без границы небезопасно. RELATIVE-only
    // без DT_HASH по-прежнему принимается.
    let nchain = if hash_addr != 0 {
        let hoff = vaddr_file_off(segs, hash_addr)? as usize;
        if hoff.checked_add(8)? > elf.len() {
            return None;
        }
        let n = rd32(elf, hoff + 4);
        if n == 0 || n > 1 << 20 {
            return None;
        }
        n
    } else {
        0
    };
    let dynsym = DynSym {
        symtab: symtab_off,
        syment,
        strtab: strtab_off,
        nchain,
    };
    let mut tables: Vec<(u64, u64)> = Vec::new();
    if saw_rela && rela_sz != 0 {
        if rela_ent != 24 || rela_sz % 24 != 0 {
            return None;
        }
        tables.push((rela_addr, rela_sz));
    }
    if jmprel != 0 {
        if pltrel != DT_RELA || pltrelsz == 0 || pltrelsz % 24 != 0 {
            return None;
        }
        tables.push((jmprel, pltrelsz));
    }
    let total: u64 = tables.iter().map(|(_, sz)| *sz).fold(0, |a, b| a.saturating_add(b));
    if total > 8192 * 24 {
        return None;
    }
    let mut out = Vec::new();
    for (addr, sz) in tables {
        let start = vaddr_file_off(segs, addr)? as usize;
        let end = start.checked_add(sz as usize)?;
        if end > elf.len() {
            return None;
        }
        let mut at = start;
        while at + 24 <= end {
            let offset = rd64(elf, at);
            let info = rd64(elf, at + 8);
            let mut addend = rd64(elf, at + 16);
            let typ = info & 0xffff_ffff;
            at += 24;
            if typ == 0 {
                continue;
            }
            if typ == R_GLOB_DAT || typ == R_JUMP_SLOT {
                // S, не S+A.
                addend = 0;
            }
            let rel = match typ {
                R_RELATIVE => RelaRel {
                    offset,
                    addend,
                    sym: None,
                    def_bias: None,
                    ext: None,
                },
                R_X86_64_64 | R_GLOB_DAT | R_JUMP_SLOT => {
                    let local = resolve_local(
                        elf,
                        symtab_off?,
                        syment,
                        strtab_off?,
                        nchain,
                        info >> 32,
                    )?;
                    match local {
                        LocalSym::Own(v) => RelaRel {
                            offset,
                            addend,
                            sym: Some(v),
                            def_bias: None,
                            ext: None,
                        },
                        LocalSym::Abs(v) => RelaRel {
                            offset,
                            addend,
                            sym: Some(v),
                            def_bias: Some(0),
                            ext: None,
                        },
                        LocalSym::Ext { name, weak } => RelaRel {
                            offset,
                            addend,
                            sym: None,
                            def_bias: None,
                            ext: Some(ExtSym { name, weak }),
                        },
                    }
                }
                _ => return None,
            };
            out.push(rel);
        }
    }
    Some(ParsedDyn {
        rels: out,
        needed,
        dynsym,
    })
}

fn vaddr_file_off(segs: &[LoadSeg], vaddr: u64) -> Option<u64> {
    for seg in segs {
        if vaddr >= seg.vaddr && vaddr - seg.vaddr < seg.file_size {
            return Some(seg.offset + (vaddr - seg.vaddr));
        }
    }
    None
}

fn load_bias(img: &ElfParsed, interpreter: bool) -> u64 {
    if img.kind == ElfKind::Exec {
        return 0;
    }
    let min_v = img.segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    let base: u64 = if interpreter { 0x800000 } else { 0x400000 };
    base.wrapping_sub(min_v & !0xFFF)
}

fn seg_span(seg: &LoadSeg, bias: u64) -> Option<(u64, u64)> {
    if seg.mem_size == 0 {
        return None;
    }
    let start = seg.vaddr.checked_add(bias)?;
    let end = start.checked_add(seg.mem_size)?;
    Some((start, end))
}

fn ranges_hit(a: &[LoadSeg], ab: u64, b: &[LoadSeg], bb: u64) -> bool {
    for sa in a {
        let Some((a0, a1)) = seg_span(sa, ab) else { continue };
        for sb in b {
            let Some((b0, b1)) = seg_span(sb, bb) else { continue };
            if a0 < b1 && b0 < a1 {
                return true;
            }
        }
    }
    false
}

fn hits_stack(segs: &[LoadSeg], bias: u64) -> bool {
    let stack0 = USER_STACK_TOP - USER_STACK_SIZE;
    for seg in segs {
        let Some((a0, a1)) = seg_span(seg, bias) else { continue };
        if a0 < USER_STACK_TOP && stack0 < a1 {
            return true;
        }
    }
    false
}

/// Сколько объектов в одной загрузке, считая программу и интерпретатор.
const MAX_LINK: usize = 16;
/// Первая база ET_DYN из DT_NEEDED. Ниже — программа и интерпретатор, выше — brk.
const LIB_BASE: u64 = 0x0200_0000;
const LIB_STEP: u64 = 0x20_0000;

enum PlaceRole {
    Main,
    Interp,
    Lib,
}

struct LinkObj {
    bytes: Vec<u8>,
    parsed: ElfParsed,
    bias: u64,
    /// 0 — программа и её DT_NEEDED. 1 — интерпретатор и его DT_NEEDED.
    group: u8,
    path: Option<String>,
}

struct Linked {
    objs: Vec<LinkObj>,
    interp_index: Option<usize>,
}

/// Абсолютный DT_NEEDED берётся как есть. Имя без слэша — `/lib/<имя>`.
/// Относительный путь со слэшем не ищем: RPATH и LD_LIBRARY_PATH нет.
fn needed_path(spec: &str) -> Option<String> {
    if spec.is_empty() || spec.len() > 200 || spec.as_bytes().contains(&0) {
        return None;
    }
    if spec.starts_with('/') {
        return crate::fs::resolve("/", spec);
    }
    if spec.starts_with('.') || spec.contains('/') {
        return None;
    }
    let mut path = String::from("/lib/");
    path.push_str(spec);
    crate::fs::resolve("/", &path)
}

fn reserved_hit(segs: &[LoadSeg], bias: u64) -> bool {
    if hits_stack(segs, bias) {
        return true;
    }
    let thread_end = THREAD_STACK_BASE + THREAD_STACK_SIZE * MAX_THREADS_PER_PROC;
    let regions = [
        (BRK_BASE, BRK_MAX),
        (MMAP_BASE, MMAP_TOP),
        (THREAD_STACK_BASE, thread_end),
    ];
    for seg in segs {
        let Some((a0, a1)) = seg_span(seg, bias) else {
            continue;
        };
        for (b0, b1) in regions {
            if a0 < b1 && b0 < a1 {
                return true;
            }
        }
    }
    false
}

fn overlaps_any(img: &ElfParsed, bias: u64, objs: &[LinkObj]) -> bool {
    if reserved_hit(&img.segments, bias) {
        return true;
    }
    objs.iter()
        .any(|o| ranges_hit(&img.segments, bias, &o.parsed.segments, o.bias))
}

fn bias_at(img: &ElfParsed, base: u64) -> u64 {
    let min_v = img.segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    base.wrapping_sub(min_v & !0xFFF)
}

fn place(img: &ElfParsed, role: PlaceRole, objs: &[LinkObj]) -> Option<u64> {
    match role {
        PlaceRole::Main => {
            let bias = load_bias(img, false);
            if overlaps_any(img, bias, objs) {
                None
            } else {
                Some(bias)
            }
        }
        PlaceRole::Interp => {
            let bias = load_bias(img, true);
            if overlaps_any(img, bias, objs) {
                None
            } else {
                Some(bias)
            }
        }
        PlaceRole::Lib => {
            if img.kind == ElfKind::Exec {
                if overlaps_any(img, 0, objs) {
                    return None;
                }
                return Some(0);
            }
            let mut base = LIB_BASE;
            while base < BRK_BASE {
                let bias = bias_at(img, base);
                if !overlaps_any(img, bias, objs) {
                    return Some(bias);
                }
                base = base.saturating_add(LIB_STEP);
            }
            None
        }
    }
}

fn load_needed<F>(objs: &mut Vec<LinkObj>, seen: &mut Vec<String>, start: usize, fetch: &mut F, group: u8) -> bool
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let mut queue = alloc::vec![start];
    let mut head = 0;
    while head < queue.len() {
        let index = queue[head];
        head += 1;
        let needed = objs[index].parsed.needed.clone();
        for spec in needed {
            let Some(path) = needed_path(&spec) else {
                serial_println!("[task] DT_NEEDED path rejected: {}", spec);
                return false;
            };
            if seen.iter().any(|have| have == &path) {
                continue;
            }
            if objs.len() >= MAX_LINK {
                serial_println!("[task] DT_NEEDED cap {}", MAX_LINK);
                return false;
            }
            let Some(bytes) = fetch(&path) else {
                serial_println!("[task] DT_NEEDED missing {}", path);
                return false;
            };
            let Some(parsed) = parse_elf64(&bytes) else {
                serial_println!("[task] DT_NEEDED bad ELF {}", path);
                return false;
            };
            if parsed.interp.is_some() {
                serial_println!("[task] DT_NEEDED has PT_INTERP {}", path);
                return false;
            }
            let Some(bias) = place(&parsed, PlaceRole::Lib, objs) else {
                serial_println!("[task] DT_NEEDED no room {}", path);
                return false;
            };
            serial_println!("[task] DT_NEEDED {} bias {:#x}", path, bias);
            seen.push(path.clone());
            objs.push(LinkObj {
                bytes,
                parsed,
                bias,
                group,
                path: Some(path),
            });
            queue.push(objs.len() - 1);
        }
    }
    true
}

enum Hit {
    Found { value: u64, bias: u64 },
    Bad,
}

/// Определённый глобальный или слабый символ. Локальные пропускаются.
/// SHN_COMMON и обрезанная таблица — ошибка, не «символа нет».
fn defined(obj: &LinkObj, name: &[u8]) -> Result<Option<(u64, u64, u8)>, ()> {
    let dynsym = &obj.parsed.dynsym;
    let (Some(symtab), Some(strtab)) = (dynsym.symtab, dynsym.strtab) else {
        return Ok(None);
    };
    if dynsym.nchain == 0 || dynsym.syment < 24 {
        return Ok(None);
    }
    let elf = obj.bytes.as_slice();
    let mut weak: Option<(u64, u64)> = None;
    for i in 0..dynsym.nchain {
        let step = (i as usize).checked_mul(dynsym.syment as usize).ok_or(())?;
        let ent = symtab.checked_add(step).ok_or(())?;
        if ent.checked_add(24).ok_or(())? > elf.len() {
            return Err(());
        }
        let shndx = rd16(elf, ent + 6);
        if shndx == 0 {
            continue;
        }
        let bind = elf[ent + 4] >> 4;
        if bind == 0 {
            continue;
        }
        let other = match sym_name(elf, strtab, rd32(elf, ent) as usize) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(()) => return Err(()),
        };
        if other != name {
            continue;
        }
        if shndx == 0xfff2 || shndx == 0xffff {
            return Err(());
        }
        let value = rd64(elf, ent + 8);
        let bias = if shndx == 0xfff1 { 0 } else { obj.bias };
        if bind == 2 {
            if weak.is_none() {
                weak = Some((value, bias));
            }
            continue;
        }
        return Ok(Some((value, bias, bind)));
    }
    Ok(weak.map(|(value, bias)| (value, bias, 2)))
}

fn lookup(objs: &[LinkObj], group: u8, name: &[u8]) -> Option<Hit> {
    let mut weak: Option<(u64, u64)> = None;
    let passes: &[u8] = if group == 0 { &[0] } else { &[1, 0] };
    for pass in passes {
        for obj in objs.iter().filter(|obj| obj.group == *pass) {
            match defined(obj, name) {
                Ok(None) => {}
                Ok(Some((value, bias, 2))) => {
                    if weak.is_none() {
                        weak = Some((value, bias));
                    }
                }
                Ok(Some((value, bias, _))) => {
                    return Some(Hit::Found { value, bias });
                }
                Err(()) => return Some(Hit::Bad),
            }
        }
    }
    weak.map(|(value, bias)| Hit::Found { value, bias })
}

fn bind_all(objs: &mut [LinkObj]) -> bool {
    for i in 0..objs.len() {
        for r in 0..objs[i].parsed.relative.len() {
            let Some(ext) = objs[i].parsed.relative[r].ext.clone() else {
                continue;
            };
            let group = objs[i].group;
            let shown = core::str::from_utf8(&ext.name).unwrap_or("?");
            match lookup(objs, group, &ext.name) {
                Some(Hit::Found { value, bias }) => {
                    let rel = &mut objs[i].parsed.relative[r];
                    rel.sym = Some(value);
                    rel.def_bias = Some(bias);
                    rel.ext = None;
                }
                Some(Hit::Bad) => {
                    serial_println!("[task] bad dynsym while resolving {}", shown);
                    return false;
                }
                None => {
                    if ext.weak {
                        let rel = &mut objs[i].parsed.relative[r];
                        rel.sym = Some(0);
                        rel.def_bias = Some(0);
                        rel.ext = None;
                    } else {
                        serial_println!("[task] undefined symbol {}", shown);
                        return false;
                    }
                }
            }
        }
    }
    true
}

fn link_with<F>(main_bytes: &[u8], mut fetch: F) -> Option<Linked>
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let parsed = match parse_elf64(main_bytes) {
        Some(parsed) => parsed,
        None => {
            serial_println!("[task] bad ELF image (need ET_EXEC/ET_DYN x86_64)");
            return None;
        }
    };
    let Some(bias) = place(&parsed, PlaceRole::Main, &[]) else {
        serial_println!("[task] ELF overlaps the stack or the heap");
        return None;
    };
    let interp = parsed.interp.clone();
    let mut objs = Vec::new();
    objs.push(LinkObj {
        bytes: Vec::from(main_bytes),
        parsed,
        bias,
        group: 0,
        path: None,
    });
    let mut seen = Vec::new();
    if !load_needed(&mut objs, &mut seen, 0, &mut fetch, 0) {
        return None;
    }
    let mut interp_index = None;
    if let Some(path) = interp {
        let Some(canon) = crate::fs::resolve("/", &path) else {
            serial_println!("[task] PT_INTERP path too long: {}", path);
            return None;
        };
        if seen.iter().any(|have| have == &canon) {
            serial_println!("[task] PT_INTERP {} is already a DT_NEEDED", canon);
            return None;
        }
        if objs.len() >= MAX_LINK {
            serial_println!("[task] DT_NEEDED cap {}", MAX_LINK);
            return None;
        }
        let Some(bytes) = fetch(&canon) else {
            serial_println!("[task] PT_INTERP missing {}", canon);
            return None;
        };
        let Some(parsed) = parse_elf64(&bytes) else {
            serial_println!("[task] PT_INTERP bad ELF {}", canon);
            return None;
        };
        if parsed.interp.is_some() {
            serial_println!("[task] nested PT_INTERP refused");
            return None;
        }
        let Some(ibias) = place(&parsed, PlaceRole::Interp, &objs) else {
            serial_println!("[task] PT_INTERP overlaps the program or the stack");
            return None;
        };
        seen.push(canon.clone());
        objs.push(LinkObj {
            bytes,
            parsed,
            bias: ibias,
            group: 1,
            path: Some(canon),
        });
        let index = objs.len() - 1;
        interp_index = Some(index);
        if !load_needed(&mut objs, &mut seen, index, &mut fetch, 1) {
            return None;
        }
    }
    if !bind_all(&mut objs) {
        return None;
    }
    Some(Linked { objs, interp_index })
}

fn link_program(bytes: &[u8]) -> Option<Linked> {
    link_with(bytes, |path| crate::fs::read_canon(path))
}

// ---- Адресное пространство ----

/// Состояние userspace-части адресного пространства. l4 — физический фрейм
/// корневой таблицы. Данные (brk/mmap) мутируются под своим мьютексом;
/// маппинг выполняется через physmap (виден при любом CR3).
pub struct AddressSpace {
    pub l4: PhysFrame,
    pub brk_base: u64,
    pub brk: u64,
    pub mmap_next: u64,
    pub thread_stacks: u64,
}

impl AddressSpace {
    pub fn new_empty(frame_allocator: &mut BootInfoFrameAllocator) -> Option<Arc<Mutex<Self>>> {
        let l4 = alloc_l4(frame_allocator)?;
        Some(Arc::new(Mutex::new(AddressSpace {
            l4,
            brk_base: BRK_BASE,
            brk: BRK_BASE,
            mmap_next: MMAP_BASE,
            thread_stacks: 0,
        })))
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        let l4 = self.l4;
        // Не держим этот кадр как CR3: execve переключает CR3 до drop.
        x86_64::instructions::interrupts::without_interrupts(|| {
            let _gap = IrqGap::enter();
            crate::memory::with_frame_allocator(|fa| free_user_space(l4, fa));
        });
    }
}

/// Освобождает только пользовательское поддерево L4[0] и сам кадр L4.
/// Записи L4[1..] — общие таблицы ядра, их кадры не наши.
fn free_user_space(l4: PhysFrame, fa: &mut BootInfoFrameAllocator) {
    let l4_ptr = (phys_offset() + l4.start_address().as_u64()).as_mut_ptr::<PageTable>();
    let child = unsafe {
        let table = &mut *l4_ptr;
        let entry = &table[0];
        // У записи L4 бит 7 — не PS. Каталог пользователя освобождаем целиком.
        let child = if entry.flags().contains(PageTableFlags::PRESENT) {
            PhysFrame::from_start_address(entry.addr()).ok()
        } else {
            None
        };
        table[0].set_unused();
        child
    };
    if let Some(l3) = child {
        free_table(l3, 3, fa);
    }
    fa.deallocate_frame(l4);
}

fn free_table(frame: PhysFrame, level: u8, fa: &mut BootInfoFrameAllocator) {
    // По одному слоту, не массивом на 512. Массив не влезает в kernel-стек
    // (64 КиБ): проба стека в free_table давала double fault.
    // Куча тут тоже нельзя: аллокатор кадров уже занят.
    let ptr = (phys_offset() + frame.start_address().as_u64()).as_mut_ptr::<PageTable>();
    for i in 0..512 {
        let child = unsafe {
            let table = &*ptr;
            let entry = &table[i];
            // В PTE (level == 1) бит 7 — это PAT, не размер страницы.
            // PS (huge) стоит только в каталогах, level > 1.
            let huge = level > 1 && entry.flags().contains(PageTableFlags::HUGE_PAGE);
            if entry.flags().contains(PageTableFlags::PRESENT) && !huge {
                PhysFrame::from_start_address(entry.addr()).ok()
            } else {
                None
            }
        };
        let Some(kid) = child else { continue };
        if level > 1 {
            free_table(kid, level - 1, fa);
        } else {
            fa.deallocate_frame(kid);
        }
    }
    fa.deallocate_frame(frame);
}

fn phys_offset() -> VirtAddr {
    VirtAddr::new(crate::PHYS_OFFSET.load(Ordering::Relaxed))
}

/// Прочитать байты пользователя через physmap. Виртуальный адрес задачи
/// не разыменовывается: нет ядра #PF на несмапленной странице и нет чтения
/// памяти ядра по адресу из syscall.
pub fn user_read(addr: u64, dst: &mut [u8]) -> bool {
    user_copy(addr, dst.as_mut_ptr(), dst.len(), false)
}

/// Записать байты в память задачи через physmap. Страница должна быть
/// present, user и writable. Иначе `false` (для syscall это `EFAULT`).
pub fn user_write(addr: u64, src: &[u8]) -> bool {
    user_copy(addr, src.as_ptr() as *mut u8, src.len(), true)
}

fn user_copy(addr: u64, buf: *mut u8, len: usize, write: bool) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = addr.checked_add(len as u64) else {
        return false;
    };
    if addr < 0x1000 || end > USER_TOP {
        return false;
    }
    let mut done = 0usize;
    while done < len {
        let at = addr + done as u64;
        let Some(phys) = translate_user(at, write) else {
            return false;
        };
        let page_off = (at & 0xFFF) as usize;
        let n = (4096 - page_off).min(len - done);
        let mapped = (crate::PHYS_OFFSET.load(Ordering::Relaxed) + phys) as *mut u8;
        unsafe {
            if write {
                core::ptr::copy_nonoverlapping(buf.add(done), mapped, n);
            } else {
                core::ptr::copy_nonoverlapping(mapped, buf.add(done), n);
            }
        }
        done += n;
    }
    true
}

fn translate_user(addr: u64, write: bool) -> Option<u64> {
    let (mut frame, _) = Cr3::read();
    let off = crate::PHYS_OFFSET.load(Ordering::Relaxed);
    for level in 0..4 {
        let table = unsafe {
            &*((off.wrapping_add(frame.start_address().as_u64())) as *const PageTable)
        };
        let shift = 39 - level * 9;
        let idx = ((addr >> shift) & 0x1ff) as usize;
        let entry = &table[idx];
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT)
            || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            return None;
        }
        if write && !flags.contains(PageTableFlags::WRITABLE) {
            return None;
        }
        // PDPTE/PDE: бит 7 = PS. В конечном PTE тот же бит — PAT, не huge.
        if (level == 1 || level == 2) && flags.contains(PageTableFlags::HUGE_PAGE) {
            return None;
        }
        let next = PhysFrame::from_start_address(entry.addr()).ok()?;
        if level == 3 {
            return Some(next.start_address().as_u64() + (addr & 0xfff));
        }
        frame = next;
    }
    None
}

/// Свежая L4-таблица: kernel-маппинги (индексы 1..512) копируются,
/// entry 0 пуст под пользовательские страницы.
fn alloc_l4(frame_allocator: &mut BootInfoFrameAllocator) -> Option<PhysFrame> {
    let l4_frame = frame_allocator.allocate_frame()?;
    let l4_virt = phys_offset() + l4_frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(l4_virt.as_mut_ptr::<u8>(), 0, 4096) };
    let l4_table = unsafe { &mut *(l4_virt.as_mut_ptr::<PageTable>()) };
    let kernel_l4 = unsafe { active_level_4_table(phys_offset()) };
    for i in 1..512 {
        let e = &kernel_l4[i];
        l4_table[i].set_addr(e.addr(), e.flags());
    }
    Some(l4_frame)
}

unsafe fn mapper_for(l4: PhysFrame) -> OffsetPageTable<'static> {
    let l4_virt = phys_offset() + l4.start_address().as_u64();
    OffsetPageTable::new(&mut *(l4_virt.as_mut_ptr::<PageTable>()), phys_offset())
}

fn map_zeroed(
    l4: PhysFrame,
    page: Page<Size4KiB>,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    let frame_virt = phys_offset() + frame.start_address().as_u64();
    unsafe { core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096) };
    let mut mapper = unsafe { mapper_for(l4) };
    unsafe { mapper.map_to(page, frame, flags, frame_allocator)?.flush() };
    Ok(())
}

/// Маппит диапазон страниц [start, end) нулями (end — адрес ПОСЛЕДНЕГО байта).
fn map_range_zeroed(
    l4: PhysFrame,
    start: VirtAddr,
    end_inclusive: VirtAddr,
    frame_allocator: &mut BootInfoFrameAllocator,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    let first = Page::<Size4KiB>::containing_address(start);
    let last = Page::<Size4KiB>::containing_address(end_inclusive);
    for page in Page::range_inclusive(first, last) {
        map_zeroed(l4, page, frame_allocator, flags)?;
    }
    Ok(())
}

const USER_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits() | PageTableFlags::USER_ACCESSIBLE.bits(),
);

/// Глубокая копия userspace-части АП (L4[0] целиком): все таблицы и страницы.
/// Только 4K-страницы (huge pages мы никогда не создаём).
fn copy_user_space(
    src_l4: PhysFrame,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<PhysFrame, MapToError<Size4KiB>> {
    fn copy_table(
        src_frame: PhysFrame,
        level: u8,
        frame_allocator: &mut BootInfoFrameAllocator,
    ) -> Result<PhysFrame, MapToError<Size4KiB>> {
        let dst_frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let src_virt = (phys_offset() + src_frame.start_address().as_u64()).as_mut_ptr::<PageTable>();
        let dst_virt = (phys_offset() + dst_frame.start_address().as_u64()).as_mut_ptr::<PageTable>();
        unsafe { core::ptr::write_bytes(dst_virt as *mut u8, 0, 4096) };
        let src_table = unsafe { &*src_virt };
        let dst_table = unsafe { &mut *dst_virt };
        for i in 0..512 {
            let e = &src_table[i];
            if !e.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            if level > 1 && e.flags().contains(PageTableFlags::HUGE_PAGE) {
                serial_println!("[task] copy_user_space: huge page unsupported");
                return Err(MapToError::FrameAllocationFailed);
            }
            if level == 1 {
                // Страница 4K: новый фрейм + копия данных.
                let new_page = frame_allocator
                    .allocate_frame()
                    .ok_or(MapToError::FrameAllocationFailed)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (phys_offset() + e.addr().as_u64()).as_mut_ptr::<u8>(),
                        (phys_offset() + new_page.start_address().as_u64()).as_mut_ptr::<u8>(),
                        4096,
                    );
                }
                dst_table[i].set_addr(new_page.start_address(), e.flags());
            } else {
                let child = PhysFrame::from_start_address(e.addr())
                    .map_err(|_| MapToError::FrameAllocationFailed)?;
                let new_child = copy_table(child, level - 1, frame_allocator)?;
                dst_table[i].set_addr(new_child.start_address(), e.flags());
            }
        }
        Ok(dst_frame)
    }

    let new_l4 = alloc_l4(frame_allocator).ok_or(MapToError::FrameAllocationFailed)?;
    let src_l4_virt = phys_offset() + src_l4.start_address().as_u64();
    let src_l4_table = unsafe { &*(src_l4_virt.as_mut_ptr::<PageTable>()) };
    let e0 = &src_l4_table[0];
    if e0.flags().contains(PageTableFlags::PRESENT) {
        let src_l3 = PhysFrame::from_start_address(e0.addr())
            .map_err(|_| MapToError::FrameAllocationFailed)?;
        let new_l3 = copy_table(src_l3, 3, frame_allocator)?;
        let new_l4_virt = phys_offset() + new_l4.start_address().as_u64();
        let new_l4_table = unsafe { &mut *(new_l4_virt.as_mut_ptr::<PageTable>()) };
        new_l4_table[0].set_addr(new_l3.start_address(), e0.flags());
    }
    Ok(new_l4)
}

/// Писать байты в user-память АП `l4` через physmap.
///
/// `translate_addr` уже возвращает физический адрес байта, а не базы
/// страницы. Смещение прибавлять второй раз нельзя: запись уезжала в
/// следующий физический кадр (страница ELF сразу за вершиной стека) и
/// затирала GOT парой auxv `AT_BASE, 0`.
fn write_user(l4: PhysFrame, addr: u64, data: &[u8]) -> Result<(), MapToError<Size4KiB>> {
    let mapper = unsafe { mapper_for(l4) };
    let mut done = 0usize;
    while done < data.len() {
        let a = addr + done as u64;
        let phys = mapper
            .translate_addr(VirtAddr::new(a))
            .ok_or(MapToError::FrameAllocationFailed)?;
        let page_off = (a & 0xFFF) as usize;
        let n = (4096 - page_off).min(data.len() - done);
        let dst = (phys_offset().as_u64() + phys.as_u64()) as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(done), dst, n) };
        done += n;
    }
    Ok(())
}

// ---- Задачи ----

/// Учётные данные. Отдельного fsuid нет: в `/proc/self/status` он равен euid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cred {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
}

impl Cred {
    pub const fn root() -> Self {
        Self {
            uid: 0,
            euid: 0,
            suid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
        }
    }

    /// Как Linux `setuid`: root пишет ruid, euid и suid. Иначе меняется только
    /// euid, и только если новый id уже есть среди ruid, euid, suid.
    pub fn set_uid(&mut self, uid: u32) -> bool {
        if self.euid == 0 {
            self.uid = uid;
            self.euid = uid;
            self.suid = uid;
            return true;
        }
        if uid == self.uid || uid == self.euid || uid == self.suid {
            self.euid = uid;
            return true;
        }
        false
    }

    pub fn set_gid(&mut self, gid: u32) -> bool {
        if self.egid == 0 {
            self.gid = gid;
            self.egid = gid;
            self.sgid = gid;
            return true;
        }
        if gid == self.gid || gid == self.egid || gid == self.sgid {
            self.egid = gid;
            return true;
        }
        false
    }
}

/// Strict пускает только read, write, rt_sigreturn и exit. `exit_group` (231) нет.
pub fn strict_permits(nr: u64) -> bool {
    matches!(nr, 0 | 1 | 15 | 60)
}

/// Каталог и umask. `CLONE_FS` делит эту структуру, обычный fork копирует.
/// umask хранится и наследуется. `mkdir` и создание нового файла срезают им биты.
pub struct FsCtx {
    pub cwd: String,
    pub umask: u32,
}

impl FsCtx {
    fn at_root() -> Self {
        Self {
            cwd: String::from("/"),
            umask: 0o022,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Exited,
}

pub struct Task {
    pub tid: u64,
    pub aspace: Arc<Mutex<AddressSpace>>,
    /// Кэш l4 (== aspace.lock().l4; продублирован для планировщика).
    pub cr3: PhysFrame,
    /// Сохранённое значение kernel rsp (контекст для переключения).
    pub kernel_rsp: u64,
    /// Вершина kernel-стека: для TSS (прерывания из ring 3) и syscall.
    pub kstack_top: u64,
    /// База kernel-стека. Drop возвращает эти 64 КиБ в кучу.
    /// Ноль — стека нет (не освобождать).
    kstack_base: u64,
    pub state: TaskState,
    pub exit_code: i64,
    /// Ненулевой номер: смерть от сигнала. `wait` пишет его в младшие 7 бит
    /// (`WIFSIGNALED`). Ноль — обычный `exit`, статус `WIFEXITED`.
    pub term_sig: u8,
    /// Слот родителя (-1 = родитель не отслеживается).
    pub parent: isize,
    /// Поток `CLONE_VM`. Такой exit не шлёт родителю `SIGCHLD`.
    thread: bool,
    /// FS BASE (TLS) — восстанавливается планировщиком.
    pub fs_base: u64,
    /// Пользовательский GS. В ядре он лежит в `KERNEL_GS_BASE`.
    pub gs_base: u64,
    /// CPU, на котором задача стоит сейчас.
    pub cpu: u32,
    /// Разрешённые CPU, если `affinity_set`. Бит `n` — CPU `n`.
    pub cpu_mask: u64,
    /// `true` — маску задал `sched_setaffinity`. Задачу можно исполнять на
    /// любом поднятом бите и переносить только внутри маски.
    /// `false` — ядро само выбирает CPU и может воровать задачу.
    pub affinity_set: bool,
    /// Кто сейчас её исполняет. -1 — никто.
    pub on_cpu: i8,
    /// Адрес для CLONE_CHILD_CLEARTID: при exit записать 0 и разбудить futex.
    pub clear_tid: u64,
    /// Пользовательская область rseq. Ноль — не зарегистрирована.
    pub rseq: u64,
    pub rseq_sig: u32,
    /// Обработчики сигналов 1–31. Потомок наследует маску и обработчики,
    /// но не ожидающие биты. execve сбрасывает всё в SIG_DFL.
    pub signals: crate::signal::Signals,
    pub name: [u8; 24],
    pub fds: Arc<Mutex<Vec<Option<crate::linux::Fd>>>>,
    /// `CLONE_FS` держит один и тот же `Arc`. fork без этого флага копирует.
    pub fsctx: Arc<Mutex<FsCtx>>,
    pub cred: Cred,
    /// 0 — выключен, 1 — `SECCOMP_MODE_STRICT`. Фильтра BPF нет.
    pub seccomp: u8,
    /// Сохранённые xmm/x87. Пустой образ = чистый FPU при первом входе.
    fx: crate::fpu::FxState,
}

static TASKS: Mutex<[Option<Task>; MAX_TASKS]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);
static TASK_COUNT: AtomicUsize = AtomicUsize::new(0);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);
/// Индекс задачи на каждом CPU. -1 — простой или ядро до первого переключения.
static CPU_CUR: [AtomicIsize; crate::cpu::MAX_CPUS] = [
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
    AtomicIsize::new(-1),
];
static IDLE_RSP: [AtomicU64; crate::cpu::MAX_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static SCHED_INITED: AtomicBool = AtomicBool::new(false);
/// tid PID1 (init.elf, а при его отсутствии — шелл). -1 — не назначен.
/// Именно по tid, а не по «Runnable без родителя»: init может спать в
/// wait4 на своём CPU, когда сирота рождается на AP.
static INIT_TID: AtomicI64 = AtomicI64::new(-1);

/// Syscall входит с `sti`, поэтому лок берём при выключенных прерываниях
/// на этом CPU. Спинлок сериализует CPU, пока секция не ждёт другой CPU
/// и не берёт `TASKS` повторно.
fn with_tasks<R>(f: impl FnOnce(&mut [Option<Task>; MAX_TASKS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut TASKS.lock()))
}

/// User-программы, собранные крейтом `user` (build.sh собирает их до ядра).
/// После монтирования FS копируются в /bin и запускаются оттуда по пути.
static SHELL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shell.elf"));
static HELLO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"));
static COUNTER_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/counter.elf"));
static FIZZ_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fizzbuzz.elf"));
static THREADS_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/threads.elf"));
static SIGNAL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/signal.elf"));
static TICK_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tick.elf"));
static INTR_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/intr.elf"));
static EPOLL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/epoll.elf"));
static INTERP_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/interp.elf"));
static DYN_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dyn.elf"));
static DSYM_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dsym.elf"));
static CRED_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cred.elf"));
static SECCOMP_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp.elf"));
static INIT_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/init.elf"));
static FS_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fs.elf"));
static TCP_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tcp.elf"));
static SEEK_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seek.elf"));
static PROC_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proc.elf"));
static MODE_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mode.elf"));
static SMP_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/smp.elf"));

/// Инициализация: программы уже лежат в ext2-образе. Если файла нет
/// (recovery-ramdisk) или размер другой — записываем. Потом PID1.
pub fn init() {
    const BINS: [(&str, &[u8]); 21] = [
        ("/bin/shell.elf", SHELL_ELF),
        ("/bin/hello.elf", HELLO_ELF),
        ("/bin/counter.elf", COUNTER_ELF),
        ("/bin/fizzbuzz.elf", FIZZ_ELF),
        ("/bin/threads.elf", THREADS_ELF),
        ("/bin/signal.elf", SIGNAL_ELF),
        ("/bin/tick.elf", TICK_ELF),
        ("/bin/intr.elf", INTR_ELF),
        ("/bin/epoll.elf", EPOLL_ELF),
        ("/bin/interp.elf", INTERP_ELF),
        ("/bin/dyn.elf", DYN_ELF),
        ("/bin/dsym.elf", DSYM_ELF),
        ("/bin/cred.elf", CRED_ELF),
        ("/bin/seccomp.elf", SECCOMP_ELF),
        ("/bin/init.elf", INIT_ELF),
        ("/bin/fs.elf", FS_ELF),
        ("/bin/tcp.elf", TCP_ELF),
        ("/bin/seek.elf", SEEK_ELF),
        ("/bin/proc.elf", PROC_ELF),
        ("/bin/mode.elf", MODE_ELF),
        ("/bin/smp.elf", SMP_ELF),
    ];
    for (name, elf) in BINS {
        if elf.is_empty() {
            continue;
        }
        // На ext2 бинарники уже в образе. Перезапись только если размер другой.
        if crate::fs::size_of(name) != elf.len() as isize {
            crate::fs::write_path(name.as_bytes(), elf);
        }
    }

    // PID1 — init. Он поднимает шелл и забирает осиротевших. Если файла нет, шелл сам PID1.
    let spawned = spawn_path("/bin/init.elf");
    let (spawned, what) = if spawned == u64::MAX {
        (spawn_path("/bin/shell.elf"), "shell")
    } else {
        (spawned, "init")
    };
    match spawned {
        s if s != u64::MAX => {
            INIT_TID.store(s as i64, Ordering::Release);
            SCHED_INITED.store(true, Ordering::Release);
            serial_println!(
                "[task] {} spawned (tid {}), round-robin on {}",
                what,
                s,
                if crate::apic::timer_armed() {
                    "lapic"
                } else {
                    "PIT"
                }
            );
        }
        _ => serial_println!("[task] failed to spawn init and shell"),
    }
}

fn default_fds() -> Arc<Mutex<Vec<Option<crate::linux::Fd>>>> {
    Arc::new(Mutex::new(alloc::vec![
        Some(crate::linux::Fd::console(false)),
        Some(crate::linux::Fd::console(true)),
        Some(crate::linux::Fd::console(true)),
    ]))
}

fn alloc_slot(tasks: &mut [Option<Task>; MAX_TASKS]) -> Option<usize> {
    let count = TASK_COUNT.load(Ordering::Acquire);
    for i in 0..count.min(MAX_TASKS) {
        let free = match &tasks[i] {
            None => true,
            Some(t) => t.state == TaskState::Exited,
        };
        if free {
            return Some(i);
        }
    }
    if count < MAX_TASKS {
        return Some(count);
    }
    None
}

/// Создать задачу из ELF-файла в ramdisk'е (путь, напр. "/bin/hello.elf").
/// Возвращает tid или u64::MAX.
pub fn spawn_path(name: &str) -> u64 {
    let Some(elf) = crate::fs::read_canon(name) else {
        serial_println!("[task] spawn_path: no such file: {}", name);
        return u64::MAX;
    };
    let argv = alloc::vec![String::from(name)];
    x86_64::instructions::interrupts::without_interrupts(|| {
        let slot = with_tasks(|tasks| alloc_slot(tasks));
        let Some(slot) = slot else {
            return u64::MAX;
        };
        let built = crate::memory::with_frame_allocator(|fa| build_task(&elf, &argv, &[], name, fa));
        match built {
            Ok(t) => {
                let old = with_tasks(|tasks| {
                    let old = tasks[slot].replace(t);
                    let count = TASK_COUNT.load(Ordering::Acquire);
                    TASK_COUNT.store(count.max(slot + 1), Ordering::Release);
                    old
                });
                drop(old);
                serial_println!("[task] spawned {} in slot {}", name, slot);
                NEXT_TID.load(Ordering::Relaxed) - 1
            }
            Err(e) => {
                serial_println!("[task] spawn {} failed: {:?}", name, e);
                u64::MAX
            }
        }
    })
}

/// Собрать задачу из ELF-образа в свежем АП.
fn build_task(
    elf_bytes: &[u8],
    argv: &[String],
    envp: &[String],
    name: &str,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<Task, MapToError<Size4KiB>> {
    let aspace = match AddressSpace::new_empty(frame_allocator) {
        Some(a) => a,
        None => return Err(MapToError::FrameAllocationFailed),
    };
    let l4 = aspace.lock().l4;

    // Main-стек (маппим до загрузки ELF: строим argv на нём).
    let stack_start = VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE);
    map_range_zeroed(
        l4,
        stack_start,
        VirtAddr::new(USER_STACK_TOP - 1),
        frame_allocator,
        USER_FLAGS,
    )?;

    let img = load_elf_image(
        l4,
        elf_bytes,
        argv,
        envp,
        USER_STACK_TOP,
        frame_allocator,
        Cred::root(),
    )?;
    finish_task(aspace, img, name)
}

fn map_and_copy(
    l4: PhysFrame,
    elf_bytes: &[u8],
    segments: &[LoadSeg],
    bias: u64,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<(), MapToError<Size4KiB>> {
    let mut mapped_pages: Vec<u64> = Vec::new();
    for seg in segments {
        if seg.mem_size == 0 {
            continue;
        }
        let seg_va = seg
            .vaddr
            .checked_add(bias)
            .ok_or(MapToError::FrameAllocationFailed)?;
        let seg_end = seg_va
            .checked_add(seg.mem_size)
            .ok_or(MapToError::FrameAllocationFailed)?;
        if seg_va < 0x1000 || seg_end > USER_TOP {
            return Err(MapToError::FrameAllocationFailed);
        }
        let first_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_va));
        let last_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_end - 1));
        for page in Page::range_inclusive(first_page, last_page) {
            let start = page.start_address().as_u64();
            if mapped_pages.contains(&start) {
                continue;
            }
            map_zeroed(l4, page, frame_allocator, USER_FLAGS)?;
            mapped_pages.push(start);
        }
    }
    let mut mapper = unsafe { mapper_for(l4) };
    for seg in segments {
        if seg.file_size == 0 || seg.offset as usize + seg.file_size as usize > elf_bytes.len() {
            continue;
        }
        let data = &elf_bytes[seg.offset as usize..(seg.offset + seg.file_size) as usize];
        let seg_va = seg.vaddr + bias;
        let seg_end = seg_va + seg.mem_size;
        if seg.mem_size == 0 {
            continue;
        }
        let first_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_va));
        let last_page = Page::<Size4KiB>::containing_address(VirtAddr::new(seg_end - 1));
        for page in Page::range_inclusive(first_page, last_page) {
            let page_start = page.start_address().as_u64();
            let frame_phys = mapper
                .translate_addr(page.start_address())
                .ok_or(MapToError::FrameAllocationFailed)?;
            let frame_virt = phys_offset() + frame_phys.as_u64();
            let copy_start = seg_va.max(page_start);
            let copy_end = (seg_va + data.len() as u64).min(page_start + 4096);
            if copy_start < copy_end {
                let src = &data[(copy_start - seg_va) as usize..(copy_end - seg_va) as usize];
                let dst = (frame_virt.as_u64() + (copy_start - page_start)) as *mut u8;
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
            }
        }
    }
    Ok(())
}

fn apply_relative(l4: PhysFrame, rels: &[RelaRel], bias: u64) -> Result<(), MapToError<Size4KiB>> {
    for rel in rels {
        if rel.ext.is_some() {
            return Err(MapToError::FrameAllocationFailed);
        }
        let addr = rel
            .offset
            .checked_add(bias)
            .ok_or(MapToError::FrameAllocationFailed)?;
        // RELATIVE: B + A, B — база этого объекта.
        // Символ: S + A, S = st_value + база определившего объекта.
        // У своего символа эта база совпадает с B. У чужого — нет.
        let base = if rel.sym.is_none() {
            bias
        } else {
            rel.def_bias.unwrap_or(bias)
        };
        let val = rel.addend.wrapping_add(rel.sym.unwrap_or(0)).wrapping_add(base);
        write_user(l4, addr, &val.to_le_bytes())?;
    }
    Ok(())
}

/// Загрузить ELF в АП l4 и построить начальный стек (argc/argv/envp/auxv).
/// Если есть `PT_INTERP`, вход — в интерпретатор, а `AT_ENTRY` остаётся
/// входом основной программы. Возвращает (entry, user_rsp).
pub fn load_elf_image(
    l4: PhysFrame,
    elf_bytes: &[u8],
    argv: &[String],
    envp: &[String],
    stack_top: u64,
    frame_allocator: &mut BootInfoFrameAllocator,
    cred: Cred,
) -> Result<LoadedImage, MapToError<Size4KiB>> {
    let linked = match link_program(elf_bytes) {
        Some(linked) => linked,
        None => return Err(MapToError::FrameAllocationFailed),
    };
    for obj in &linked.objs {
        map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, frame_allocator)?;
        apply_relative(l4, &obj.parsed.relative, obj.bias)?;
    }
    let main = &linked.objs[0];
    let phdr_vaddr = main.parsed.phdr_vaddr.wrapping_add(main.bias);
    let phnum = main.parsed.phnum;
    let at_entry = main.parsed.entry.wrapping_add(main.bias);
    let (entry, at_base) = if let Some(index) = linked.interp_index {
        let interp = &linked.objs[index];
        let base = if interp.parsed.kind == ElfKind::Dyn {
            interp.bias
        } else {
            0
        };
        serial_println!(
            "[task] PT_INTERP {} entry {:#x} AT_BASE {:#x}",
            interp.path.as_deref().unwrap_or("?"),
            interp.parsed.entry.wrapping_add(interp.bias),
            base
        );
        (interp.parsed.entry.wrapping_add(interp.bias), base)
    } else {
        (at_entry, 0)
    };

    // ---- Начальный стек ----
    // Все строки, потом (выравнивание 16) auxv, envp[], argv[], argc наверху.
    let mut sp = stack_top;
    let mut put = |l4: PhysFrame, bytes: &[u8], sp: &mut u64| -> Result<u64, MapToError<Size4KiB>> {
        *sp -= bytes.len() as u64;
        write_user(l4, *sp, bytes)?;
        Ok(*sp)
    };

    // Случайные 16 байт для AT_RANDOM.
    let seed = NEXT_TID.load(Ordering::Relaxed).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ x86_64::registers::control::Cr2::read().map(|a| a.as_u64()).unwrap_or(0x1234);
    let mut rnd = seed | 1;
    let mut random_bytes = [0u8; 16];
    for b in &mut random_bytes {
        rnd ^= rnd << 13;
        rnd ^= rnd >> 7;
        rnd ^= rnd << 17;
        *b = rnd as u8;
    }
    let random_ptr = put(l4, &random_bytes, &mut sp)?;

    // Строки argv (в обратном порядке записи — порядок указателей
    // восстановлен через argv_ptrs.reverse()).
    let mut argv_ptrs: Vec<u64> = Vec::new();
    for s in argv.iter().rev() {
        let mut bytes = s.clone().into_bytes();
        bytes.push(0);
        let p = put(l4, &bytes, &mut sp)?;
        argv_ptrs.push(p);
    }
    argv_ptrs.reverse();
    // AT_EXECFN указывает на argv[0]\0 (последняя записанная строка).
    let execfn_ptr = argv_ptrs.first().copied().unwrap_or(0);
    let mut envp_ptrs: Vec<u64> = Vec::new();
    for s in envp.iter().rev() {
        let mut bytes = s.clone().into_bytes();
        bytes.push(0);
        let p = put(l4, &bytes, &mut sp)?;
        envp_ptrs.push(p);
    }
    envp_ptrs.reverse();
    // Имя программы для AT_EXECFN: argv[0]\0 — последняя записанная строка.
    let execfn_ptr = argv_ptrs.first().copied().unwrap_or(0);

    sp &= !0xF; // выравнивание до 16 перед массивами указателей

    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_BASE: u64 = 7;
    const AT_FLAGS: u64 = 8;
    const AT_ENTRY: u64 = 9;
    const AT_UID: u64 = 11;
    const AT_EUID: u64 = 12;
    const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14;
    const AT_HWCAP: u64 = 16;
    const AT_CLKTCK: u64 = 17;
    const AT_SECURE: u64 = 23;
    const AT_RANDOM: u64 = 25;
    const AT_HWCAP2: u64 = 26;
    const AT_EXECFN: u64 = 31;

    let auxv: [u64; 46] = [
        AT_PHDR, phdr_vaddr,
        AT_PHENT, 56,
        AT_PHNUM, phnum,
        AT_PAGESZ, 4096,
        AT_BASE, at_base,
        AT_FLAGS, 0,
        AT_ENTRY, at_entry,
        AT_UID, cred.uid as u64,
        AT_EUID, cred.euid as u64,
        AT_GID, cred.gid as u64,
        AT_EGID, cred.egid as u64,
        AT_HWCAP, 0x078B_FBFF,
        AT_HWCAP2, 0,
        AT_CLKTCK, 100,
        AT_SECURE, 0,
        AT_RANDOM, random_ptr,
        AT_EXECFN, execfn_ptr,
        AT_NULL, 0,
        0, 0, // запас
        0, 0,
        0, 0,
        0, 0,
        0, 0,
    ];
    let auxv_len = 18 * 2; // до AT_NULL включительно
    let auxv_bytes: Vec<u8> = auxv[..auxv_len]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    // На входе в _start %rsp обязан быть кратен 16 (psABI): первый call
    // тогда входит в функцию с (%rsp+8) кратным 16. Иначе glibc ловит #GP
    // на выровненных movaps. Все куски ниже кратны 8, так что хватает 0 или 8.
    let vectors = auxv_bytes.len()
        + (envp_ptrs.len() + 1) * 8
        + (argv_ptrs.len() + 1) * 8
        + 8;
    if sp.wrapping_sub(vectors as u64) & 0xF != 0 {
        sp -= 8;
    }
    sp -= auxv_bytes.len() as u64;
    write_user(l4, sp, &auxv_bytes)?;

    let mut push_ptrs = |l4: PhysFrame, ptrs: &[u64], sp: &mut u64| -> Result<(), MapToError<Size4KiB>> {
        let bytes: Vec<u8> = ptrs.iter().chain([0u64].iter()).flat_map(|v| v.to_le_bytes()).collect();
        *sp -= bytes.len() as u64;
        write_user(l4, *sp, &bytes)
    };
    push_ptrs(l4, &envp_ptrs, &mut sp)?;
    push_ptrs(l4, &argv_ptrs, &mut sp)?;
    sp -= 8;
    write_user(l4, sp, &argv.len().to_le_bytes())?;

    Ok(LoadedImage { entry, user_rsp: sp })
}

/// Kernel-стек в куче. База запоминается в задаче и освобождается в Drop.
/// Крутилка раскидки новых задач между равно нагруженными CPU.
static PICK_ROTATE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Начало длинного участка с выключенными прерываниями, по CPU.
static IRQ_OFF_AT: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
/// Сколько тиков LAPIC слиплось в один, пока IF был выключен.
static OWED: [AtomicU32; crate::cpu::MAX_CPUS] = [const { AtomicU32::new(0) }; crate::cpu::MAX_CPUS];

/// Пока жив guard, измеряется участок без прерываний. На drop пропущенные
/// тики (кроме одного, который APIC всё ещё доставит) пишутся в долг:
/// планировщик столько раз не выберет ту же задачу, и `/proc/stat` получит
/// это время как system.
struct IrqGap;

impl IrqGap {
    fn enter() -> Self {
        let me = crate::smp::this_cpu();
        if me < crate::cpu::MAX_CPUS {
            IRQ_OFF_AT[me].store(crate::time::monotonic_ns(), Ordering::Relaxed);
        }
        Self
    }
}

impl Drop for IrqGap {
    fn drop(&mut self) {
        let me = crate::smp::this_cpu();
        if me >= crate::cpu::MAX_CPUS {
            return;
        }
        let start = IRQ_OFF_AT[me].swap(0, Ordering::Relaxed);
        if start == 0 {
            return;
        }
        let dt = crate::time::monotonic_ns().saturating_sub(start);
        let hz = crate::apic::timer_hz().max(1);
        let tick = 1_000_000_000u64 / hz;
        let missed = dt / tick;
        if missed > 1 {
            let extra = (missed - 1).min(32);
            OWED[me].fetch_add(extra as u32, Ordering::Relaxed);
            crate::interrupts::TICKS.fetch_add(extra, Ordering::Relaxed);
            crate::interrupts::PER_CPU_TICKS[me].fetch_add(extra, Ordering::Relaxed);
            crate::interrupts::SYS_TICKS[me].fetch_add(extra, Ordering::Relaxed);
        }
    }
}

/// CPU с наименьшим числом Runnable-задач; равенство — round-robin.
fn pick_cpu() -> u32 {
    let n = crate::smp::cpu_count().max(1);
    let start = (PICK_ROTATE.fetch_add(1, Ordering::Relaxed) as u32) % n;
    let mut best = 0u32;
    let mut best_load = u32::MAX;
    with_tasks(|tasks| {
        for k in 0..n {
            let c = (start + k) % n;
            let load = tasks
                .iter()
                .flatten()
                .filter(|t| t.cpu == c && t.state == TaskState::Runnable)
                .count() as u32;
            if load < best_load {
                best_load = load;
                best = c;
            }
        }
    });
    best
}

fn alloc_kernel_stack() -> (u64, u64) {
    let kstack: Box<[u8]> = vec![0u8; KERNEL_STACK_SIZE].into_boxed_slice();
    let base = kstack.as_ptr() as u64;
    let top = base + KERNEL_STACK_SIZE as u64;
    core::mem::forget(kstack);
    (base, top)
}

impl Drop for Task {
    fn drop(&mut self) {
        if self.kstack_base == 0 {
            return;
        }
        let ptr = self.kstack_base as *mut u8;
        self.kstack_base = 0;
        unsafe {
            drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                ptr,
                KERNEL_STACK_SIZE,
            )));
        }
    }
}

/// Завершает создание задачи: kernel-стек + начальный iret-фрейм.
fn finish_task(
    aspace: Arc<Mutex<AddressSpace>>,
    img: LoadedImage,
    name: &str,
) -> Result<Task, MapToError<Size4KiB>> {
    let l4 = aspace.lock().l4;
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Kernel-стек задачи (в kernel-адресном пространстве, виден при любом CR3).
    let (kstack_base, kstack_top) = alloc_kernel_stack();

    // Начальный «фрейм прерывания» на kernel-стеке: iretq в ring 3.
    // Порядок слотов совпадает с pop-последовательностью timer_entry.
    // ВАЖНО: фрейм лежит на 2 глубже вершины — первое же аппаратное
    // прерывание (CPU iret-фрейм + 15 пушей timer_entry) затирает верхние
    // ~160 байт стека; kernel_rsp должен указывать на нетронутую область.
    const GPRS: usize = 15;
    let rsp = kstack_top - 2 * (GPRS as u64 + 5) * 8;
    let (user_data, user_code) = gdt::user_segments();
    let mut name_buf = [0u8; 24];
    let nb = name.as_bytes();
    let n = nb.len().min(23);
    name_buf[..n].copy_from_slice(&nb[..n]);
    unsafe {
        let f = rsp as *mut u64;
        // GPR-слоты (15 штук) — нули; потом iret-фрейм.
        core::ptr::write(f.add(GPRS + 0), img.entry); // rip
        core::ptr::write(f.add(GPRS + 1), u64::from(user_code.0)); // cs (0x30|3)
        core::ptr::write(f.add(GPRS + 2), 0x202); // rflags: IF
        core::ptr::write(f.add(GPRS + 3), img.user_rsp); // user rsp
        core::ptr::write(f.add(GPRS + 4), u64::from(user_data.0)); // ss (0x28|3)
    }

    Ok(Task {
        tid,
        aspace,
        cr3: l4,
        kernel_rsp: rsp,
        kstack_top,
        kstack_base,
        state: TaskState::Runnable,
        exit_code: 0,
        term_sig: 0,
        parent: -1,
        thread: false,
        fs_base: 0,
        gs_base: 0,
        cpu: pick_cpu(),
        cpu_mask: 0,
        affinity_set: false,
        on_cpu: -1,
        clear_tid: 0,
        rseq: 0,
        rseq_sig: 0,
        signals: crate::signal::Signals::new(),
        name: name_buf,
        fds: default_fds(),
        fsctx: Arc::new(Mutex::new(FsCtx::at_root())),
        cred: Cred::root(),
        seccomp: 0,
        fx: crate::fpu::FxState::new(),
    })
}

// ---- clone / fork / execve / wait (вызываются из linux.rs) ----

/// Номер текущего слота (для отладки).
pub fn current_slot() -> isize {
    CPU_CUR[crate::smp::this_cpu()].load(Ordering::Relaxed)
}

pub fn current_tid() -> u64 {
    let cur = current_slot();
    if cur < 0 {
        return 0;
    }
    with_tasks(|tasks| tasks[cur as usize].as_ref().map(|t| t.tid).unwrap_or(0))
}

/// Рабочий каталог. Без задачи — `/`.
pub fn current_cwd() -> String {
    with_current_task(|t| t.fsctx.lock().cwd.clone()).unwrap_or_else(|| String::from("/"))
}

pub fn set_cwd(path: String) {
    let _ = with_current_task(|t| t.fsctx.lock().cwd = path);
}

/// Ставит umask и возвращает прежний. Биты выше 0o777 отбрасываются.
pub fn swap_umask(next: u32) -> u32 {
    with_current_task(|t| {
        let mut g = t.fsctx.lock();
        let old = g.umask;
        g.umask = next & 0o777;
        old
    })
    .unwrap_or(0o022)
}

/// Текущий umask. Без задачи — 022, как у новой `FsCtx`.
pub fn current_umask() -> u32 {
    with_current_task(|t| t.fsctx.lock().umask).unwrap_or(0o022)
}

/// tid родителя. У init и без задачи — 0. Отдельного пространства gettid нет:
/// `gettid` возвращает тот же номер, что `getpid`.
pub fn current_ppid() -> u64 {
    let cur = current_slot();
    if cur < 0 {
        return 0;
    }
    with_tasks(|tasks| {
        let Some(t) = tasks[cur as usize].as_ref() else {
            return 0;
        };
        if t.parent < 0 {
            return 0;
        }
        tasks[t.parent as usize]
            .as_ref()
            .map(|p| p.tid)
            .unwrap_or(0)
    })
}

fn cred_field(f: impl FnOnce(&Cred) -> u32) -> u64 {
    with_current_task(|t| f(&t.cred) as u64).unwrap_or(0)
}

pub fn cred_ruid() -> u64 {
    cred_field(|c| c.uid)
}
pub fn cred_euid() -> u64 {
    cred_field(|c| c.euid)
}
pub fn cred_rgid() -> u64 {
    cred_field(|c| c.gid)
}
pub fn cred_egid() -> u64 {
    cred_field(|c| c.egid)
}

pub fn cred_setuid(uid: u32) -> u64 {
    match with_current_task(|t| t.cred.set_uid(uid)) {
        Some(true) => 0,
        _ => crate::linux::EPERM,
    }
}

pub fn cred_setgid(gid: u32) -> u64 {
    match with_current_task(|t| t.cred.set_gid(gid)) {
        Some(true) => 0,
        _ => crate::linux::EPERM,
    }
}

/// Уже strict и номер не из четвёрки read/write/rt_sigreturn/exit.
pub fn seccomp_kills(nr: u64) -> bool {
    let mode = with_current_task(|t| t.seccomp).unwrap_or(0);
    mode == 1 && !strict_permits(nr)
}

pub fn sys_prctl(opt: u64, arg2: u64) -> u64 {
    const PR_GET_SECCOMP: u64 = 21;
    const PR_SET_SECCOMP: u64 = 22;
    match opt {
        PR_GET_SECCOMP => with_current_task(|t| t.seccomp as u64).unwrap_or(0),
        PR_SET_SECCOMP => set_seccomp_mode(arg2),
        _ => 0,
    }
}

/// `seccomp(2)`. op 0 — strict. op 1 (фильтр) — `ENOSYS`, BPF нет.
pub fn sys_seccomp(op: u64, flags: u64) -> u64 {
    if op == 1 {
        return crate::linux::ENOSYS;
    }
    if op != 0 || flags != 0 {
        return crate::linux::EINVAL;
    }
    set_seccomp_mode(1)
}

fn set_seccomp_mode(mode: u64) -> u64 {
    if mode != 1 {
        return crate::linux::EINVAL;
    }
    match with_current_task(|t| {
        if t.seccomp != 0 {
            return false;
        }
        t.seccomp = 1;
        true
    }) {
        Some(true) => 0,
        _ => crate::linux::EINVAL,
    }
}

pub fn proc_self_status() -> String {
    let cur = current_slot();
    if cur < 0 {
        return format_status("kernel", 0, 0, &Cred::root(), 0, "S");
    }
    with_tasks(|tasks| match tasks[cur as usize].as_ref() {
        Some(_) => status_at(tasks, cur as usize),
        None => format_status("kernel", 0, 0, &Cred::root(), 0, "S"),
    })
}

/// Живые и ещё не собранные задачи. Для каталога `/proc`.
pub fn proc_tids() -> alloc::vec::Vec<u64> {
    with_tasks(|tasks| tasks.iter().flatten().map(|t| t.tid).collect())
}

pub fn proc_alive(tid: u64) -> bool {
    with_tasks(|tasks| tasks.iter().flatten().any(|t| t.tid == tid))
}

pub fn proc_status(tid: u64) -> Option<String> {
    with_tasks(|tasks| {
        let idx = tasks.iter().position(|slot| {
            slot.as_ref().map(|t| t.tid == tid).unwrap_or(false)
        })?;
        Some(status_at(tasks, idx))
    })
}

/// Имя, с которым задача вошла в exec. Полного argv нет: в `cmdline` лежит путь и NUL.
pub fn proc_cmdline(tid: u64) -> Option<String> {
    with_tasks(|tasks| {
        let t = tasks.iter().flatten().find(|t| t.tid == tid)?;
        let mut s = String::from(cstr_name(&t.name));
        s.push('\0');
        Some(s)
    })
}

pub fn proc_self_cmdline() -> String {
    let cur = current_slot();
    if cur < 0 {
        return String::from("kernel\0");
    }
    with_tasks(|tasks| {
        let Some(t) = tasks[cur as usize].as_ref() else {
            return String::from("kernel\0");
        };
        let mut s = String::from(cstr_name(&t.name));
        s.push('\0');
        s
    })
}

fn status_at(tasks: &[Option<Task>; MAX_TASKS], idx: usize) -> String {
    let t = tasks[idx].as_ref().unwrap();
    let mut raw = [0u8; 24];
    let name_len = cstr_name(&t.name).len().min(raw.len());
    raw[..name_len].copy_from_slice(&t.name[..name_len]);
    let tid = t.tid;
    let cred = t.cred;
    let seccomp = t.seccomp;
    let parent = t.parent;
    let state = match t.state {
        TaskState::Runnable => "R",
        TaskState::Exited => "Z",
    };
    let ppid = if parent >= 0 {
        tasks[parent as usize]
            .as_ref()
            .map(|p| p.tid)
            .unwrap_or(0)
    } else {
        0
    };
    let name = core::str::from_utf8(&raw[..name_len]).unwrap_or("?");
    format_status(name, tid, ppid, &cred, seccomp, state)
}

fn cstr_name(name: &[u8]) -> &str {
    let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    core::str::from_utf8(&name[..n]).unwrap_or("?")
}

fn format_status(name: &str, pid: u64, ppid: u64, c: &Cred, seccomp: u8, state: &str) -> String {
    format!(
        "Name:\t{name}\nState:\t{state}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nSeccomp:\t{seccomp}\n",
        c.uid, c.euid, c.suid, c.euid, c.gid, c.egid, c.sgid, c.egid,
    )
}

/// Сколько tid выдано и сколько задач сейчас `Runnable`.
/// Для `/proc/stat`: это не jiffies и не число процессов Linux.
pub fn proc_counts() -> (u64, u64) {
    let created = NEXT_TID.load(Ordering::Relaxed).saturating_sub(1);
    let running = with_tasks(|tasks| {
        tasks
            .iter()
            .flatten()
            .filter(|t| matches!(t.state, TaskState::Runnable))
            .count() as u64
    });
    (created, running)
}

/// Доступ к текущей задаче под TASKS-локом.
pub fn with_current_task<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let cur = current_slot();
    if cur < 0 {
        return None;
    }
    with_tasks(|tasks| tasks[cur as usize].as_mut().map(f))
}

/// Доступ к любой задаче по tid.
pub fn with_task<R>(tid: u64, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    with_tasks(|tasks| tasks.iter_mut().flatten().find(|t| t.tid == tid).map(f))
}

/// Найти завершившегося потомка tid'а (parent == tid). Возвращает
/// (child_tid, exit_code) и освобождает слот.
pub fn reap_child(parent_tid: u64, want: u64) -> Option<(u64, i64, u8)> {
    let taken = with_tasks(|tasks| {
        let count = TASK_COUNT.load(Ordering::Acquire);
        let mut found = None;
        for i in 0..count.min(MAX_TASKS) {
            let matched = match &tasks[i] {
                Some(t) if t.state == TaskState::Exited => {
                    let parent_ok = t.parent >= 0
                        && tasks
                            .get(t.parent as usize)
                            .and_then(|p| p.as_ref())
                            .map(|p| p.tid)
                            == Some(parent_tid);
                    parent_ok && (want == 0 || want == u64::MAX || t.tid == want)
                }
                _ => false,
            };
            if matched {
                found = tasks[i].take();
                break;
            }
        }
        found
    });
    taken.map(|t| {
        let result = (t.tid, t.exit_code, t.term_sig);
        drop(t);
        result
    })
}

/// Смерть от сигнала: `wait` увидит `WIFSIGNALED`, код в журнале — `128+sig`.
pub fn note_term_sig(sig: u32) {
    if sig == 0 || sig >= 128 {
        return;
    }
    let _ = with_current_task(|t| t.term_sig = sig as u8);
}

/// Количество живых потомков (для wait4 ECHILD).
pub fn has_children(parent_tid: u64) -> bool {
    with_tasks(|tasks| {
        tasks.iter().flatten().any(|t| {
        t.parent >= 0
            && tasks[t.parent as usize]
                .as_ref()
                .map(|p| p.tid)
                    .unwrap_or(u64::MAX)
                    == parent_tid
        })
    })
}

/// Создать поток/процесс (syscall clone). `frame` — сохранённый фрейм
/// родителя на его kernel-стеке (см. syscall::FRAME).
pub fn sys_clone(
    flags: u64,
    child_stack: u64,
    _ptid: u64,
    ctid: u64,
    tls: u64,
    frame: *const u64,
) -> u64 {
    const CLONE_VM: u64 = 0x100;
    const CLONE_FS: u64 = 0x200;
    const CLONE_FILES: u64 = 0x400;
    const CLONE_SETTLS: u64 = 0x80000;
    const CLONE_CHILD_CLEARTID: u64 = 0x200000;

    x86_64::instructions::interrupts::without_interrupts(|| {
        let _gap = IrqGap::enter();
        let cur = current_slot();
        if cur < 0 {
            return u64::MAX;
        }
        let slot = with_tasks(|tasks| alloc_slot(tasks));
        let Some(slot) = slot else {
            return u64::MAX;
        };

        let (
            parent_as,
            parent_cr3,
            parent_fs,
            parent_fsctx,
            parent_cwd,
            parent_umask,
            parent_fds,
            parent_name,
            parent_signals,
            parent_tid,
            parent_cred,
            parent_seccomp,
            parent_cpu,
            parent_cpu_mask,
            parent_affinity_set,
        ) = with_tasks(|tasks| {
            let p = tasks[cur as usize].as_ref().expect("current task vanished");
            let parent_fsctx = p.fsctx.clone();
            // Один lock. Два `lock()` в одном выражении не отпускают guard и
            // на spin::Mutex встают навсегда.
            let (parent_cwd, parent_umask) = {
                let g = parent_fsctx.lock();
                (g.cwd.clone(), g.umask)
            };
            (
                p.aspace.clone(),
                p.cr3,
                p.fs_base,
                parent_fsctx,
                parent_cwd,
                parent_umask,
                p.fds.clone(),
                p.name,
                p.signals.for_child(),
                p.tid,
                p.cred,
                p.seccomp,
                p.cpu,
                p.cpu_mask,
                p.affinity_set,
            )
        });

        // Унаследованная привязка уважается; свободный ребёнок уходит на
        // сейчас наименее загруженный CPU.
        let child_cpu = if parent_affinity_set {
            parent_cpu
        } else {
            pick_cpu()
        };

        let child_as = if flags & CLONE_VM != 0 {
            parent_as.clone()
        } else {
            // fork: глубокая копия userspace.
            let copied = crate::memory::with_frame_allocator(|fa| {
                copy_user_space(parent_cr3, fa).and_then(|l4| {
                    let (brk_base, brk, mmap_next, thread_stacks) = {
                        let a = parent_as.lock();
                        (a.brk_base, a.brk, a.mmap_next, a.thread_stacks)
                    };
                    Ok(Arc::new(Mutex::new(AddressSpace {
                        l4,
                        brk_base,
                        brk,
                        mmap_next,
                        thread_stacks,
                    })))
                })
            });
            match copied {
                Ok(a) => a,
                Err(_) => return u64::MAX,
            }
        };

        let child_tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
        let child_l4 = child_as.lock().l4;

        // Kernel-стек ребёнка + контекст: копия фрейма родителя с rax=0.
        // Фрейм — на 2 глубже вершины: верхние ~160 байт стека затирает
        // первое же аппаратное прерывание (см. finish_task).
        let (kstack_base, kstack_top) = alloc_kernel_stack();
        let rsp = kstack_top - 2 * (15u64 + 5) * 8;
        let (user_data, user_code) = gdt::user_segments();
        unsafe {
            // Перекладка регистров: фрейм родителя в раскладке syscall_entry
            // (порядок push'ей entry), а timer_entry восстанавливает регистры
            // в СВОЁМ порядке (pop r15..rax). Слоты 0..5 совпадают, дальше —
            // явный remap. rax ребёнка = 0 (возврат из clone/fork).
            let f = rsp as *mut u64;
            *f.add(0) = *frame.add(0); // r15
            *f.add(1) = *frame.add(1); // r14
            *f.add(2) = *frame.add(2); // r13
            *f.add(3) = *frame.add(3); // r12
            *f.add(4) = *frame.add(4); // rbp
            *f.add(5) = *frame.add(5); // rbx
            *f.add(6) = *frame.add(12); // r11
            *f.add(7) = *frame.add(14); // r10 = user rsp
            *f.add(8) = *frame.add(6); // r9
            *f.add(9) = *frame.add(7); // r8
            *f.add(10) = *frame.add(10); // rdi
            *f.add(11) = *frame.add(9); // rsi
            *f.add(12) = *frame.add(8); // rdx
            *f.add(13) = *frame.add(13); // rcx
            *f.add(14) = 0; // rax: ребёнок получает 0 из clone
            let user_rsp = if flags & CLONE_VM != 0 && child_stack != 0 {
                child_stack // поток: свой стек
            } else {
                *frame.add(FRAME::RSP) // fork: общая копия стека родителя
            };
            let rip = *frame.add(FRAME::RIP);
            let rflags = *frame.add(FRAME::RFLAGS) | 0x200; // IF
            core::ptr::write(f.add(15), rip);
            core::ptr::write(f.add(16), u64::from(user_code.0));
            core::ptr::write(f.add(17), rflags);
            core::ptr::write(f.add(18), user_rsp);
            core::ptr::write(f.add(19), u64::from(user_data.0));
        }

        let fds = if flags & CLONE_FILES != 0 {
            parent_fds
        } else {
            let cloned: Vec<Option<crate::linux::Fd>> = parent_fds
                .lock()
                .iter()
                .map(|f| f.as_ref().map(|f| f.clone_fd()))
                .collect();
            Arc::new(Mutex::new(cloned))
        };

        let mut task = Task {
            tid: child_tid,
            aspace: child_as,
            cr3: child_l4,
            kernel_rsp: rsp,
            kstack_top,
            kstack_base,
            state: TaskState::Runnable,
            exit_code: 0,
            term_sig: 0,
            parent: cur as isize,
            thread: flags & CLONE_VM != 0,
            fs_base: if flags & CLONE_SETTLS != 0 { tls } else { parent_fs },
            gs_base: crate::cpu::read_user_gs(),
            cpu: child_cpu,
            cpu_mask: parent_cpu_mask,
            affinity_set: parent_affinity_set,
            on_cpu: -1,
            clear_tid: if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 },
            rseq: 0,
            rseq_sig: 0,
            signals: parent_signals,
            name: parent_name,
            fds,
            fsctx: if flags & CLONE_FS != 0 {
                parent_fsctx
            } else {
                Arc::new(Mutex::new(FsCtx {
                    cwd: parent_cwd,
                    umask: parent_umask,
                }))
            },
            cred: parent_cred,
            seccomp: parent_seccomp,
            fx: crate::fpu::FxState::new(),
        };
        // Ребёнок должен увидеть те же xmm, что и родитель в точке clone.
        crate::fpu::save(&mut task.fx);
        unsafe {
            let f = rsp as *const u64;
            crate::serial_println!(
                "[clone] child frame: rip={:#x} rsp={:#x} rflags={:#x} rax={:#x}",
                *f.add(15), *f.add(18), *f.add(17), *f.add(14)
            );
        }
        let _ = parent_tid;

        let old = with_tasks(|tasks| {
            let old = tasks[slot].replace(task);
            let count = TASK_COUNT.load(Ordering::Acquire);
            TASK_COUNT.store(count.max(slot + 1), Ordering::Release);
            old
        });
        drop(old);
        crate::serial_println!(
            "[clone] parent slot {} → child tid {} slot {} flags {:#x} cr3 {:?}",
            cur, child_tid, slot, flags, child_l4
        );
        child_tid
    })
}

/// Заменить образ текущей задачи (syscall execve).
/// path/argv/envp — указатели в user-памяти. Возвращает errno (-Exxx
/// как u64) или 0; при 0 фрейм syscall уже переписан под новый образ —
/// возврата в старый код не происходит.
pub fn sys_execve(path_ptr: u64, argv_ptr: u64, envp_ptr: u64, frame: *mut u64) -> u64 {
    use crate::linux::{E2BIG, EFAULT, EIO, ENOENT, ENOEXEC};

    // 1) Скопировать argv/envp в kernel до размонтирования старого АП.
    let argv = match copy_ptr_array(argv_ptr, 32) {
        Some(v) => v,
        None => return EFAULT,
    };
    let envp = match copy_ptr_array(envp_ptr, 64) {
        Some(v) => v,
        None => return EFAULT,
    };
    let path = match copy_user_cstr(path_ptr, 256) {
        Some(p) => p,
        None => return EFAULT,
    };
    crate::serial_println!("[execve] tid {} path '{}'", current_tid(), path);

    // 2) Разрешить путь и прочитать ELF.
    let canon = {
        let cwd = current_cwd();
        match crate::fs::resolve(&cwd, &path) {
            Some(c) => c,
            None => return E2BIG,
        }
    };
    let elf = match crate::fs::read_canon(&canon) {
        Some(e) => e,
        None => {
            crate::serial_println!("[execve] '{}' not found (canon '{}')", path, canon);
            return ENOENT;
        }
    };
    // execve не сбрасывает uid и seccomp. Снимок до разбора ELF: TASKS там не держим.
    let cred = with_current_task(|t| t.cred).unwrap_or(Cred::root());

    // 3) Новое АП + загрузка.
    let built = crate::memory::with_frame_allocator(|fa| {
        let aspace = match AddressSpace::new_empty(fa) {
            Some(a) => a,
            None => return Err(MapToError::FrameAllocationFailed),
        };
        let l4 = aspace.lock().l4;
        map_range_zeroed(
            l4,
            VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE),
            VirtAddr::new(USER_STACK_TOP - 1),
            fa,
            USER_FLAGS,
        )?;
        let argv_full = if argv.is_empty() {
            alloc::vec![canon.clone()]
        } else {
            argv
        };
        let img = load_elf_image(l4, &elf, &argv_full, &envp, USER_STACK_TOP, fa, cred)?;
        Ok((aspace, img))
    });
    let (aspace, img) = match built {
        Ok(v) => v,
        Err(_) => return ENOEXEC,
    };

    // 4) Переключиться на новое АП и переписать фрейм syscall:
    //    sysret уйдёт в точку входа нового образа.
    //    CR3 меняется ДО drop старого АП: иначе освободим таблицу,
    //    на которую ещё указывает CR3.
    let l4 = aspace.lock().l4;
    let Some(old) = with_current_task(|t| {
        let old = core::mem::replace(&mut t.aspace, aspace);
        t.cr3 = l4;
        t.fs_base = 0;
        t.rseq = 0;
        t.rseq_sig = 0;
        t.signals = crate::signal::Signals::new();
        let nb = canon.as_bytes();
        let n = nb.len().min(23);
        t.name = [0u8; 24];
        t.name[..n].copy_from_slice(&nb[..n]);
        // Старые xmm предыдущего образа новому процессу не принадлежат.
        crate::fpu::forget(&mut t.fx);
        old
    }) else {
        return ENOEXEC;
    };
    crate::fpu::reset_cpu();
    unsafe {
        Cr3::write(l4, Cr3Flags::empty());
        let f = frame;
        // ELF_PLAT_INIT: на входе в _start регистры нулевые. Иначе glibc
        // принимает rdx за rtld_fini и на exit зовёт мусор (часто адрес стека).
        *f.add(FRAME::R15) = 0;
        *f.add(FRAME::R14) = 0;
        *f.add(FRAME::R13) = 0;
        *f.add(FRAME::R12) = 0;
        *f.add(FRAME::RBP) = 0;
        *f.add(FRAME::RBX) = 0;
        *f.add(FRAME::R9) = 0;
        *f.add(FRAME::R8) = 0;
        *f.add(FRAME::RDX) = 0;
        *f.add(FRAME::RSI) = 0;
        *f.add(FRAME::RDI) = 0;
        *f.add(FRAME::RAX) = 0;
        *f.add(FRAME::RFLAGS) = 0x202;
        *f.add(FRAME::RIP) = img.entry;
        *f.add(FRAME::RSP) = img.user_rsp;
    }
    drop(old);
    0
}

pub fn copy_user_cstr(ptr: u64, max: usize) -> Option<String> {
    if ptr == 0 {
        return Some(String::new());
    }
    // Не читать дальше текущей страницы, пока не встретился NUL.
    // Аргументы exec лежат сразу под USER_STACK_TOP: чтение «с запасом»
    // за NUL попадает в несмапленную страницу и даёт ложный EFAULT.
    let mut bytes = Vec::new();
    let mut off = 0usize;
    while off < max {
        let at = ptr + off as u64;
        let page_left = 4096 - (at & 0xFFF) as usize;
        let n = (max - off).min(page_left).min(256);
        let mut chunk = [0u8; 256];
        if !user_read(at, &mut chunk[..n]) {
            return None;
        }
        if let Some(i) = chunk[..n].iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..i]);
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk[..n]);
        off += n;
    }
    None
}

fn copy_ptr_array(ptr: u64, max: usize) -> Option<Vec<String>> {
    if ptr == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..max {
        let mut raw = [0u8; 8];
        if !user_read(ptr + (i as u64) * 8, &mut raw) {
            return None;
        }
        let p = u64::from_le_bytes(raw);
        if p == 0 {
            return Some(out);
        }
        out.push(copy_user_cstr(p, 1024)?);
    }
    None // нет завершающего NULL
}

/// sys_brk: вернуть/установить brk текущей задачи. addr=0 — запрос.
pub fn sys_brk(addr: u64) -> u64 {
    let cur = current_slot();
    if cur < 0 {
        return 0;
    }
    // brk в shared АП: мутируем под локом АП.
    let (l4, brk_base, old_brk);
    let aspace = with_tasks(|tasks| tasks[cur as usize].as_ref().unwrap().aspace.clone());
    {
        let mut a = aspace.lock();
        l4 = a.l4;
        brk_base = a.brk_base;
        old_brk = a.brk;
        if addr == 0 {
            return old_brk;
        }
        if addr < brk_base || addr > BRK_MAX {
            return old_brk;
        }
        a.brk = addr;
    }
    // Маппим недостающие страницы (сжатие не демаппим — фреймы текут).
    if addr > old_brk {
        let grow_start = (old_brk + 0xFFF) & !0xFFF;
        let grow_end = addr & !0xFFF;
        if grow_end >= grow_start {
            let r = crate::memory::with_frame_allocator(|fa| {
                map_range_zeroed(
                    l4,
                    VirtAddr::new(grow_start),
                    VirtAddr::new(grow_end),
                    fa,
                    USER_FLAGS,
                )
            });
            if r.is_err() {
                let mut a = aspace.lock();
                a.brk = old_brk;
                return old_brk;
            }
        }
    }
    addr
}

/// sys_mmap: анонимные приватные маппинги из бамп-региона АП.
pub fn sys_mmap(addr: u64, len: u64, _prot: u64, flags: u64, _fd: u64, _off: u64) -> u64 {
    use crate::linux::{ENOMEM, ENODEV};
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_PRIVATE: u64 = 0x2;
    const MAP_FIXED: u64 = 0x10;
    if len == 0 || len > 256 * 1024 * 1024 {
        return ENOMEM;
    }
    if flags & MAP_ANONYMOUS == 0 {
        // Маппинг файлов пока не поддержан: busybox обходится без него.
        return ENODEV;
    }
    if flags & MAP_PRIVATE == 0 {
        return ENODEV;
    }
    let cur = current_slot();
    if cur < 0 {
        return ENOMEM;
    }
    let aspace = with_tasks(|tasks| tasks[cur as usize].as_ref().unwrap().aspace.clone());
    let pages = (len + 0xFFF) / 0x1000;
    let base = {
        let mut a = aspace.lock();
        let base = if MAP_FIXED != 0 && addr != 0 && (flags & MAP_FIXED) != 0 {
            addr & !0xFFF
        } else {
            a.mmap_next
        };
        a.mmap_next = base + pages * 0x1000;
        base
    };
    if base + pages * 0x1000 > MMAP_TOP {
        return ENOMEM;
    }
    let l4 = aspace.lock().l4;
    let r = crate::memory::with_frame_allocator(|fa| {
        map_range_zeroed(
            l4,
            VirtAddr::new(base),
            VirtAddr::new(base + pages * 0x1000 - 1),
            fa,
            USER_FLAGS,
        )
    });
    match r {
        Ok(()) => base,
        Err(_) => ENOMEM,
    }
}

fn slot_of(tasks: &[Option<Task>; MAX_TASKS], pid: u64) -> Option<usize> {
    if pid == 0 {
        let cur = current_slot();
        if cur < 0 {
            None
        } else {
            Some(cur as usize)
        }
    } else {
        tasks.iter().position(|slot| {
            slot.as_ref()
                .map(|t| t.tid == pid && t.state == TaskState::Runnable)
                .unwrap_or(false)
        })
    }
}

/// `sched_setaffinity`. Маска целиком: задача может стоять на любом поднятом
/// бите. Текущий CPU сохраняется, если он в маске. Перенос на другой —
/// на тике из ring 3, без IPI из-под `TASKS`.
pub fn sys_sched_setaffinity(pid: u64, len: u64, mask_ptr: u64) -> u64 {
    if len == 0 || len > 128 || mask_ptr == 0 {
        return crate::linux::EINVAL;
    }
    let n = (len as usize).min(8);
    let mut raw = [0u8; 8];
    if !user_read(mask_ptr, &mut raw[..n]) {
        return crate::linux::EFAULT;
    }
    let mask = u64::from_le_bytes(raw);
    if mask == 0 {
        return crate::linux::EINVAL;
    }
    let online = crate::smp::cpu_count().max(1).min(64);
    let mut allow = 0u64;
    for b in 0..online {
        if mask & (1u64 << b) != 0 {
            allow |= 1u64 << b;
        }
    }
    if allow == 0 {
        return crate::linux::EINVAL;
    }
    with_tasks(|tasks| {
        let Some(idx) = slot_of(tasks, pid) else {
            return crate::linux::ESRCH;
        };
        let Some(t) = tasks[idx].as_mut() else {
            return crate::linux::ESRCH;
        };
        if t.cpu >= online || allow & (1u64 << t.cpu) == 0 {
            t.cpu = allow.trailing_zeros();
        }
        t.cpu_mask = allow;
        t.affinity_set = true;
        0
    })
}

/// `sched_getaffinity`. Возвращает 8. Явная маска — как её задали.
/// Без неё — все поднятые CPU.
pub fn sys_sched_getaffinity(pid: u64, len: u64, mask_ptr: u64) -> u64 {
    if len == 0 || mask_ptr == 0 {
        return crate::linux::EINVAL;
    }
    let mask = with_tasks(|tasks| {
        let idx = slot_of(tasks, pid)?;
        tasks[idx].as_ref().map(|t| {
            if t.affinity_set {
                t.cpu_mask
            } else {
                let n = crate::smp::cpu_count().max(1).min(64);
                (1u64 << n) - 1
            }
        })
    });
    let Some(mask) = mask else {
        return crate::linux::ESRCH;
    };
    let n = (len as usize).min(128);
    let mut tmp = [0u8; 128];
    tmp[..8].copy_from_slice(&mask.to_le_bytes());
    if !user_write(mask_ptr, &tmp[..n]) {
        return crate::linux::EFAULT;
    }
    8
}

/// `getcpu`. Пишет CPU, на котором выполнен этот syscall, не поле affinity.
pub fn sys_getcpu(cpu_ptr: u64, node_ptr: u64) -> u64 {
    let cpu = crate::smp::this_cpu() as u32;
    if cpu_ptr != 0 && !user_write(cpu_ptr, &cpu.to_le_bytes()) {
        return crate::linux::EFAULT;
    }
    if node_ptr != 0 && !user_write(node_ptr, &0u32.to_le_bytes()) {
        return crate::linux::EFAULT;
    }
    0
}

/// sys_arch_prctl: установить/прочитать FS BASE текущей задачи.
pub fn sys_arch_prctl(code: u64, addr: u64) -> u64 {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_GET_GS: u64 = 0x1004;
    match code {
        ARCH_SET_FS => {
            with_current_task(|t| t.fs_base = addr);
            unsafe { Msr::new(0xC000_0100).write(addr) };
            0
        }
        ARCH_GET_FS => with_current_task(|t| t.fs_base).unwrap_or(0),
        ARCH_SET_GS => {
            // Мы уже в syscall: swapgs сделан, пользовательский GS — KERNEL_GS_BASE.
            with_current_task(|t| t.gs_base = addr);
            crate::cpu::write_user_gs(addr);
            0
        }
        ARCH_GET_GS => crate::cpu::read_user_gs(),
        _ => crate::linux::EINVAL,
    }
}

/// Выделить стек для нового потока в общем АП. Возвращает вершину стека.
pub fn alloc_thread_stack() -> Option<u64> {
    let cur = current_slot();
    if cur < 0 {
        return None;
    }
    let aspace = with_tasks(|tasks| tasks[cur as usize].as_ref().map(|t| t.aspace.clone()))?;
    let (l4, idx) = {
        let mut a = aspace.lock();
        if a.thread_stacks >= MAX_THREADS_PER_PROC {
            return None;
        }
        let idx = a.thread_stacks;
        a.thread_stacks += 1;
        (a.l4, idx)
    };
    let top = THREAD_STACK_BASE + idx * THREAD_STACK_SIZE + THREAD_STACK_SIZE / 2;
    let base = top - THREAD_STACK_SIZE / 2;
    let r = crate::memory::with_frame_allocator(|fa| {
        map_range_zeroed(
            l4,
            VirtAddr::new(base),
            VirtAddr::new(top - 1),
            fa,
            USER_FLAGS,
        )
    });
    r.ok().map(|_| top)
}

/// Книги смерти задачи в слоте (строго под локом TASKS): дети → PID1 по tid,
/// SIGCHLD родителю или init, cleartid + futex wake. Состояние и код выхода
/// не трогает — это выбирает вызывающий (exit от задачи, kill от планировщика).
fn death_books(tasks: &mut [Option<Task>; MAX_TASKS], slot: usize) {
    let cur = slot as isize;
    let cur_tid = tasks[slot].as_ref().map(|t| t.tid).unwrap_or(0);
    let init_tid = INIT_TID.load(Ordering::Relaxed);
    // Смерть PID1: репарентить и reap'ать больше некому. Честная
    // паника, а не тихий раскол, на который потом встанут cgroups.
    if init_tid >= 0 && cur_tid as i64 == init_tid {
        serial_println!("[task] PID1 (tid {}) exited — system halt", cur_tid);
        panic!("PID1 exited");
    }
    // Детей отдаём PID1 по tid. Поиск по «Runnable без родителя»
    // снят: init может спать в wait4 на своём CPU, когда сирота
    // рождается на AP, — тогда сирота оставалась с parent = -1,
    // её зомби никто не reap'ал, слот тек.
    let mut init_slot = -1isize;
    if init_tid >= 0 {
        for (i, t) in tasks.iter().enumerate() {
            if i == slot {
                continue;
            }
            if let Some(t) = t.as_ref() {
                if t.tid as i64 == init_tid {
                    init_slot = i as isize;
                    break;
                }
            }
        }
    }
    let mut zombie = false;
    for t in tasks.iter_mut().flatten() {
        if t.parent == cur {
            t.parent = init_slot;
            if t.state == TaskState::Exited {
                zombie = true;
            }
        }
    }
    // raise только OR'ит pending — безопасно ставить спящей задаче:
    // доставка всё равно на её тике или syscall.
    if zombie && init_slot >= 0 {
        if let Some(p) = tasks[init_slot as usize].as_mut() {
            p.signals.raise(17);
        }
    }
    let mut parent = -1isize;
    let mut thread = true;
    if let Some(t) = tasks[slot].as_mut() {
        // CLONE_CHILD_CLEARTID: pthread join ждёт обнуления.
        if t.clear_tid != 0 {
            let zero = 0u32.to_le_bytes();
            let addr = t.clear_tid;
            let _ = user_write(addr, &zero);
            crate::linux::futex_wake(addr, 1);
        }
        parent = t.parent;
        thread = t.thread;
    }
    if !thread && parent >= 0 {
        if let Some(p) = tasks[parent as usize].as_mut() {
            p.signals.raise(17);
        }
    }
}

/// Пометить текущую задачу завершённой. Планировщик больше в неё не вернётся.
pub fn exit_current() {
    with_tasks(|tasks| {
        let cur = current_slot();
        if cur >= 0 {
            death_books(tasks, cur as usize);
            if let Some(t) = tasks[cur as usize].as_mut() {
                t.state = TaskState::Exited;
            }
        }
    });
}

/// Убить текущую задачу сигналом из контекста тика: книги + Exited, без
/// hlt-цикла sys_exit (IF в обработчике выключен — CPU встал бы навсегда).
/// iret в ring 3 случится ещё раз, но schedule слот больше не выберет.
pub fn kill_current_signal(code: u64) {
    with_tasks(|tasks| {
        let cur = current_slot();
        if cur >= 0 {
            if let Some(t) = tasks[cur as usize].as_mut() {
                t.exit_code = code as i64;
                if (128..192).contains(&code) {
                    t.term_sig = (code - 128) as u8;
                }
            }
            death_books(tasks, cur as usize);
            if let Some(t) = tasks[cur as usize].as_mut() {
                t.state = TaskState::Exited;
            }
        }
    });
}

/// Убить задачу в слоте сигналом: код 128+sig, книги, Exited. Под локом TASKS.
fn kill_slot(tasks: &mut [Option<Task>; MAX_TASKS], slot: usize, sig: u32) {
    if let Some(t) = tasks[slot].as_mut() {
        t.exit_code = 128 + sig as i64;
        t.term_sig = sig as u8;
    }
    death_books(tasks, slot);
    if let Some(t) = tasks[slot].as_mut() {
        t.state = TaskState::Exited;
    }
}

/// sys_exit: код выхода → exit_code, дальше как exit_current.
pub fn sys_exit(code: u64) -> ! {
    with_current_task(|t| t.exit_code = code as i64);
    exit_current();
    serial_println!(
        "[task] tid {} exited with code {}",
        current_tid(),
        code as i64
    );
    // Планировщик больше не выберет эту задачу; тикаем hlt до конца таймсов.
    loop {
        x86_64::instructions::hlt();
    }
}

// ---- Планировщик ----

/// Дамп задач (serial + экран) для команды `ps`.
pub fn debug_dump() {
    with_tasks(|tasks| {
    let count = TASK_COUNT.load(Ordering::Acquire);
    crate::serial_println!("  TID  SLOT STATE   PARENT NAME");
    crate::framebuffer::_print_screen(core::format_args!(
        "  TID  SLOT STATE   PARENT NAME\n"
    ));
    for i in 0..count.min(MAX_TASKS) {
        if let Some(t) = &tasks[i] {
            let state = match t.state {
                TaskState::Runnable => "run ",
                TaskState::Exited => "dead",
            };
            let name = core::str::from_utf8(&t.name).unwrap_or("?");
            crate::serial_println!(
                "  {:>3}  {:>4} {} {:>6} {}",
                t.tid,
                i,
                state,
                t.parent,
                name
            );
            crate::framebuffer::_print_screen(core::format_args!(
                "  {:>3}  {:>4} {} {:>6} {}\n",
                t.tid,
                i,
                state,
                t.parent,
                name
            ));
        }
    }
    });
}

/// Переключение контекста из обработчика таймера (вызывается из asm).
/// Принимает rsp текущего контекста, возвращает rsp следующего.
#[no_mangle]
extern "C" fn timer_switch(current_rsp: u64) -> u64 {
    crate::interrupts::TICKS.fetch_add(1, Ordering::Relaxed);
    account_tick(current_rsp);
    unsafe {
        crate::interrupts::PICS
            .lock()
            .notify_end_of_interrupt(crate::interrupts::InterruptIndex::Timer.as_u8());
    }
    schedule(current_rsp)
}

#[no_mangle]
extern "C" fn lapic_timer_switch(current_rsp: u64) -> u64 {
    crate::interrupts::TICKS.fetch_add(1, Ordering::Relaxed);
    let me = crate::smp::this_cpu();
    if me < crate::cpu::MAX_CPUS {
        crate::interrupts::PER_CPU_TICKS[me].fetch_add(1, Ordering::Relaxed);
    }
    account_tick(current_rsp);
    crate::apic::eoi();
    schedule(current_rsp)
}

/// `rseq` (syscall 334). Длина 32, выравнивание 32. Регистрация на задачу.
/// Вытеснение из ring 3 переносит rip на abort, если подпись на месте.
pub fn sys_rseq(addr: u64, len: u64, flags: u64, sig: u64) -> u64 {
    const UNREGISTER: u64 = 1;
    if flags & !UNREGISTER != 0 || len != 32 {
        return crate::linux::EINVAL;
    }
    if flags & UNREGISTER != 0 {
        return match with_current_task(|t| {
            if t.rseq != addr || u64::from(t.rseq_sig) != sig {
                crate::linux::EINVAL
            } else {
                t.rseq = 0;
                t.rseq_sig = 0;
                0
            }
        }) {
            Some(rc) => rc,
            None => crate::linux::EINVAL,
        };
    }
    if addr == 0 || addr % 32 != 0 {
        return crate::linux::EINVAL;
    }
    let registered = with_current_task(|t| {
        if t.rseq != 0 {
            return false;
        }
        t.rseq = addr;
        t.rseq_sig = sig as u32;
        true
    });
    match registered {
        Some(true) => {
            let ids = [0u8; 8];
            if !user_write(addr, &ids) {
                let _ = with_current_task(|t| {
                    t.rseq = 0;
                    t.rseq_sig = 0;
                });
                return crate::linux::EFAULT;
            }
            0
        }
        Some(false) => crate::linux::EBUSY,
        None => crate::linux::EINVAL,
    }
}

/// Общая часть обрыва rseq-критической секции: `ip` внутри `[start,
/// start+post)` и abort-заглушка с подписью на месте. Обнуляет cs-указатель
/// и возвращает abort-ip. `flags & 1` (NO_RESTART_ON_PREEMPT) отменяет
/// обрыв при вытеснении; syscall-обрыв флага не уважает — Linux-семантика.
fn rseq_try_abort(slot: usize, ip: u64, honor_no_restart: bool) -> Option<u64> {
    let (addr, sig) = match with_tasks(|tasks| {
        tasks
            .get(slot)
            .and_then(|t| t.as_ref())
            .map(|t| (t.rseq, t.rseq_sig))
    }) {
        Some((addr, sig)) if addr != 0 => (addr, sig),
        _ => return None,
    };
    let zeros = 0u32.to_le_bytes();
    let mut ids = [0u8; 8];
    ids[..4].copy_from_slice(&zeros);
    ids[4..].copy_from_slice(&zeros);
    let _ = user_write(addr, &ids);

    let mut cs_ptr_raw = [0u8; 8];
    if !user_read(addr + 8, &mut cs_ptr_raw) {
        return None;
    }
    let cs_ptr = u64::from_le_bytes(cs_ptr_raw);
    if cs_ptr == 0 {
        return None;
    }
    let mut cs = [0u8; 32];
    if !user_read(cs_ptr, &mut cs) {
        return None;
    }
    let flags = u32::from_le_bytes([cs[4], cs[5], cs[6], cs[7]]);
    let mut start_raw = [0u8; 8];
    start_raw.copy_from_slice(&cs[8..16]);
    let mut post_raw = [0u8; 8];
    post_raw.copy_from_slice(&cs[16..24]);
    let mut abort_raw = [0u8; 8];
    abort_raw.copy_from_slice(&cs[24..32]);
    let start = u64::from_le_bytes(start_raw);
    let post = u64::from_le_bytes(post_raw);
    let abort = u64::from_le_bytes(abort_raw);
    let in_cs = post > 0 && ip >= start && ip.wrapping_sub(start) < post;
    let no_restart = flags & 1 != 0;
    if !in_cs || (honor_no_restart && no_restart) {
        // Не в критической секции: только сброс cs-указателя (как раньше).
        let z = 0u64.to_le_bytes();
        let _ = user_write(addr + 8, &z);
        return None;
    }
    if abort < 4 {
        return None;
    }
    let mut mark = [0u8; 4];
    if !user_read(abort - 4, &mut mark) || u32::from_le_bytes(mark) != sig {
        return None;
    }
    let z = 0u64.to_le_bytes();
    let _ = user_write(addr + 8, &z);
    Some(abort)
}

fn rseq_preempt(slot: usize, kernel_rsp: u64) {
    let Some(ip) = timer_user_rip(kernel_rsp) else {
        return;
    };
    if let Some(abort) = rseq_try_abort(slot, ip, true) {
        unsafe {
            core::ptr::write_unaligned((kernel_rsp + 120) as *mut u64, abort);
        }
    }
}

/// Обрыв критической секции на входе в syscall: rip в syscall-фрейме
/// переносится на abort-обработчик. Linux-семантика: syscall из cs
/// перезапускает последовательность.
pub fn rseq_syscall_abort(frame: *mut u64) {
    let slot = current_slot();
    if slot < 0 {
        return;
    }
    let ip = unsafe { core::ptr::read_unaligned(frame.add(FRAME::RIP)) };
    if let Some(abort) = rseq_try_abort(slot as usize, ip, false) {
        unsafe {
            core::ptr::write_unaligned(frame.add(FRAME::RIP), abort);
        }
    }
}

/// Тик относится к задаче, которая его застала: ring 3 — user, ядро — system,
/// пустой CPU — idle.
fn account_tick(kernel_rsp: u64) {
    let me = crate::smp::this_cpu();
    if me >= crate::cpu::MAX_CPUS {
        return;
    }
    if CPU_CUR[me].load(Ordering::Relaxed) < 0 {
        crate::interrupts::IDLE_TICKS[me].fetch_add(1, Ordering::Relaxed);
    } else if frame_is_user(kernel_rsp) {
        crate::interrupts::USER_TICKS[me].fetch_add(1, Ordering::Relaxed);
    } else {
        crate::interrupts::SYS_TICKS[me].fetch_add(1, Ordering::Relaxed);
    }
}

fn frame_is_user(kernel_rsp: u64) -> bool {
    let cs = unsafe { core::ptr::read_unaligned((kernel_rsp + 128) as *const u64) };
    cs & 3 == 3
}

fn timer_user_rip(kernel_rsp: u64) -> Option<u64> {
    if !frame_is_user(kernel_rsp) {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned((kernel_rsp + 120) as *const u64) })
}

enum Switch {
    Run {
        rsp: u64,
        kstack: u64,
        cr3: PhysFrame,
        fs: u64,
        /// `None` — та же задача, `KERNEL_GS_BASE` не трогаем.
        gs: Option<u64>,
    },
    Idle {
        rsp: u64,
    },
}

fn leave_cpu(task: &mut Task, me: u32) {
    crate::fpu::save(&mut task.fx);
    task.gs_base = crate::cpu::read_user_gs();
    if task.on_cpu == me as i8 {
        task.on_cpu = -1;
    }
}

fn schedule(current_rsp: u64) -> u64 {
    if !SCHED_INITED.load(Ordering::Acquire) {
        return current_rsp;
    }
    let count = TASK_COUNT.load(Ordering::Acquire);
    if count == 0 {
        return current_rsp;
    }
    let me = crate::smp::this_cpu();
    if me >= crate::cpu::MAX_CPUS {
        return current_rsp;
    }
    let prev = CPU_CUR[me].load(Ordering::Relaxed);
    if prev >= 0 {
        rseq_preempt(prev as usize, current_rsp);
    }
    let from_user = frame_is_user(current_rsp);
    let punish = me < crate::cpu::MAX_CPUS && OWED[me].load(Ordering::Relaxed) > 0;

    let decision = with_tasks(|tasks| {
        if prev < 0 {
            IDLE_RSP[me].store(current_rsp, Ordering::Relaxed);
        }
        let mut pinned = false;
        if prev >= 0 {
            if let Some(t) = tasks[prev as usize].as_mut() {
                t.kernel_rsp = current_rsp;
                let dead = t.state != TaskState::Runnable;
                let migrate = from_user && t.cpu != me as u32;
                if dead || migrate {
                    leave_cpu(t, me as u32);
                } else if !from_user && t.cpu != me as u32 {
                    // Кадр ядра нельзя отдать другому CPU: у syscall и iret разные кадры.
                    pinned = true;
                    t.on_cpu = me as i8;
                }
            }
        }

        let n = TASK_COUNT.load(Ordering::Acquire).min(tasks.len());
        let next = if pinned {
            Some(prev as usize)
        } else if n == 0 {
            None
        } else {
            let mut found = None;
            for k in 1..=n {
                let i = if prev < 0 {
                    (k - 1) % n
                } else {
                    (prev as usize + k) % n
                };
                let Some(t) = tasks[i].as_ref() else {
                    continue;
                };
                if t.state != TaskState::Runnable {
                    continue;
                }
                // Смертельный сигнал (SIGKILL / default-fatal) не ждёт
                // syscall: задача умирает до выбора, слот reap'ает родитель.
                if let Some(sig) = t.signals.fatal_pending() {
                    kill_slot(tasks, i, sig);
                    continue;
                }
                if t.on_cpu >= 0 && t.on_cpu != me as i8 {
                    continue;
                }
                if punish && prev >= 0 && i == prev as usize {
                    continue;
                }
                let here = me as u32;
                let fits = if t.affinity_set {
                    here < 64
                        && t.cpu_mask & (1u64 << here) != 0
                        && (t.cpu == here || t.on_cpu < 0)
                } else {
                    t.cpu == here
                };
                if !fits {
                    continue;
                }
                if t.affinity_set && t.cpu != here {
                    if let Some(slot) = tasks[i].as_mut() {
                        slot.cpu = here;
                    }
                }
                found = Some(i);
                break;
            }
            // Локальных нет — берём свободную задачу или привязанную, чья
            // маска разрешает этот CPU. Кадр в ядре чужого CPU не трогаем.
            if found.is_none() {
                for i in 0..n {
                    let Some(t) = tasks[i].as_ref() else {
                        continue;
                    };
                    if t.state != TaskState::Runnable || t.on_cpu >= 0 {
                        continue;
                    }
                    if punish && prev >= 0 && i == prev as usize {
                        continue;
                    }
                    let here = me as u32;
                    if t.affinity_set && (here >= 64 || t.cpu_mask & (1u64 << here) == 0) {
                        continue;
                    }
                    tasks[i].as_mut().expect("checked").cpu = here;
                    found = Some(i);
                    break;
                }
            }
            if found.is_none() && prev >= 0 {
                if let Some(t) = tasks[prev as usize].as_ref() {
                    if t.state == TaskState::Runnable
                        && (t.on_cpu < 0 || t.on_cpu == me as i8)
                        && t.cpu == me as u32
                    {
                        found = Some(prev as usize);
                    }
                }
            }
            if punish {
                let v = OWED[me].load(Ordering::Relaxed);
                if v > 0 {
                    OWED[me].store(v - 1, Ordering::Relaxed);
                }
            }
            found
        };

        if let Some(next) = next {
            let switching = prev < 0 || prev as usize != next;
            if switching && prev >= 0 {
                if let Some(t) = tasks[prev as usize].as_mut() {
                    if t.on_cpu == me as i8 {
                        leave_cpu(t, me as u32);
                    }
                }
            }
            if switching {
                if let Some(t) = tasks[next].as_ref() {
                    crate::fpu::restore(&t.fx);
                }
            }
            if let Some(t) = tasks[next].as_mut() {
                t.on_cpu = me as i8;
            }
            CPU_CUR[me].store(next as isize, Ordering::Relaxed);
            let task = tasks[next].as_ref().expect("runnable task disappeared");
            Switch::Run {
                rsp: task.kernel_rsp,
                kstack: task.kstack_top,
                cr3: task.cr3,
                fs: task.fs_base,
                gs: if switching {
                    Some(task.gs_base)
                } else {
                    None
                },
            }
        } else {
            if prev >= 0 {
                if let Some(t) = tasks[prev as usize].as_mut() {
                    if t.on_cpu == me as i8 {
                        leave_cpu(t, me as u32);
                    }
                }
            }
            CPU_CUR[me].store(-1, Ordering::Relaxed);
            let idle = IDLE_RSP[me].load(Ordering::Relaxed);
            Switch::Idle {
                rsp: if idle == 0 { current_rsp } else { idle },
            }
        }
    });

    match decision {
        Switch::Run {
            rsp,
            kstack,
            cr3,
            fs,
            gs,
        } => {
            unsafe { Cr3::write(cr3, Cr3Flags::empty()) };
            unsafe { Msr::new(0xC000_0100).write(fs) };
            if let Some(gs) = gs {
                crate::cpu::write_user_gs(gs);
            }
            gdt::set_kernel_stack(VirtAddr::new(kstack));
            syscall::set_current_kstack(kstack);
            // Кадр next — тот, в который iret. TASKS здесь не держим.
            crate::signal::deliver_timer(rsp);
            rsp
        }
        Switch::Idle { rsp } => {
            let kcr3 = crate::smp::kernel_cr3(me);
            if kcr3 != 0 {
                if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(kcr3)) {
                    unsafe { Cr3::write(frame, Cr3Flags::empty()) };
                }
            }
            let top = if me == 0 {
                syscall::boot_kstack_top()
            } else {
                crate::smp::idle_kstack(me)
            };
            if top != 0 {
                gdt::set_kernel_stack(VirtAddr::new(top));
            }
            syscall::set_current_kstack(if me == 0 { 0 } else { top });
            rsp
        }
    }
}

core::arch::global_asm!(r#"
    .text
    .global timer_entry
timer_entry:
    # В 64-битном кадре CS всегда на [rsp+8]. swapgs только из ring 3.
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    # Тот же контракт, что у syscall_entry: перед call выровнять rsp вниз
    # до 16, чтобы Rust вошёл с rsp ≡ 8 (mod 16). Сохранённый контекст — rbx,
    # он callee-saved и не входит в выравнивание.
    mov rbx, rsp
    mov rdi, rbx
    and rsp, -16
    call timer_switch
    mov rsp, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    test byte ptr [rsp+8], 3
    jz 2f
    swapgs
2:
    iretq

    .global lapic_timer_entry
lapic_timer_entry:
    test byte ptr [rsp+8], 3
    jz 3f
    swapgs
3:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    mov rdi, rbx
    and rsp, -16
    call lapic_timer_switch
    mov rsp, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    test byte ptr [rsp+8], 3
    jz 4f
    swapgs
4:
    iretq
"#);

extern "C" {
    fn timer_entry();
    fn lapic_timer_entry();
}

/// Адрес asm-обработчика таймера PIT (для регистрации в IDT).
pub fn timer_handler_addr() -> u64 {
    let f: unsafe extern "C" fn() = timer_entry;
    f as u64
}

/// Адрес asm-обработчика таймера локального APIC.
pub fn lapic_timer_handler_addr() -> u64 {
    let f: unsafe extern "C" fn() = lapic_timer_entry;
    f as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn dsym_reloc_resolves_exported_symbol() {
        serial_print!("test dsym_reloc_resolves_exported_symbol... ");
        let img = parse_elf64(DSYM_ELF).expect("dsym.elf");
        assert!(img.kind == ElfKind::Dyn);
        assert_eq!(img.relative.len(), 1);
        let r = &img.relative[0];
        // R_X86_64_64 на exported_fn: [slot] = S(0x1234) + A(0x10) + bias.
        assert_eq!(r.offset, 0x210);
        assert_eq!(r.addend, 0x10);
        assert_eq!(r.sym, Some(0x1234));
        assert!(r.def_bias.is_none());
        assert!(r.ext.is_none());
        assert_eq!(load_bias(&img, false), 0x400000);
        serial_println!("[ok]");
    }

    #[test_case]
    fn pt_interp_names_the_interpreter() {
        serial_print!("test pt_interp_names_the_interpreter... ");
        let main = parse_elf64(DYN_ELF).expect("dyn.elf");
        assert_eq!(main.interp.as_deref(), Some("/bin/interp.elf"));
        assert!(main.kind == ElfKind::Exec);
        assert_eq!(main.entry, 0x4000c0);
        assert!(main.relative.is_empty());
        let interp = parse_elf64(INTERP_ELF).expect("interp.elf");
        assert!(interp.interp.is_none());
        assert_eq!(interp.entry, 0x800078);
        assert_eq!(load_bias(&interp, true), 0);
        serial_println!("[ok]");
    }

    #[test_case]
    fn cred_drops_and_strict_is_four_syscalls() {
        serial_print!("test cred_drops_and_strict_is_four_syscalls... ");
        let mut c = Cred::root();
        assert!(c.set_uid(1000));
        assert_eq!((c.uid, c.euid, c.suid), (1000, 1000, 1000));
        assert!(!c.set_uid(0));
        assert_eq!(c.euid, 1000);
        c.suid = 7;
        assert!(c.set_uid(7));
        assert_eq!((c.uid, c.euid, c.suid), (1000, 7, 7));
        assert!(c.set_gid(50));
        assert_eq!((c.gid, c.egid, c.sgid), (50, 50, 50));
        assert!(!c.set_gid(0));
        assert!(strict_permits(0) && strict_permits(1));
        assert!(strict_permits(15) && strict_permits(60));
        assert!(!strict_permits(39));
        assert!(!strict_permits(157));
        assert!(!strict_permits(231));
        assert!(!strict_permits(317));
        assert_eq!(sys_seccomp(1, 0), crate::linux::ENOSYS);
        assert_eq!(sys_seccomp(0, 1), crate::linux::EINVAL);
        assert_eq!(set_seccomp_mode(2), crate::linux::EINVAL);
        assert_eq!(set_seccomp_mode(1), crate::linux::EINVAL);
        assert!(!seccomp_kills(39));
        assert_eq!(current_ppid(), 0);
        let st = proc_self_status();
        assert!(st.contains("Name:\tkernel\n"));
        assert!(st.contains("Pid:\t0\n"));
        assert!(st.contains("Uid:\t0\t0\t0\t0\n"));
        assert!(st.contains("Gid:\t0\t0\t0\t0\n"));
        assert!(st.contains("Seccomp:\t0\n"));
        serial_println!("[ok]");
    }

    #[test_case]
    fn clone_fs_shares_cwd_fork_copies() {
        serial_print!("test clone_fs_shares_cwd_fork_copies... ");
        let shared = Arc::new(Mutex::new(FsCtx::at_root()));
        let alias = shared.clone();
        shared.lock().cwd = String::from("/bin");
        assert_eq!(alias.lock().cwd, "/bin");
        let (cwd, umask) = {
            let g = shared.lock();
            (g.cwd.clone(), g.umask)
        };
        let copied = Arc::new(Mutex::new(FsCtx { cwd, umask }));
        shared.lock().cwd = String::from("/");
        shared.lock().umask = 0o077;
        assert_eq!(copied.lock().cwd, "/bin");
        assert_eq!(copied.lock().umask, 0o022);
        assert_eq!(alias.lock().cwd, "/");
        assert_eq!(alias.lock().umask, 0o077);
        assert_eq!(current_cwd(), "/");
        assert_eq!(swap_umask(0o777), 0o022);
        serial_println!("[ok]");
    }

    #[test_case]
    fn rseq_needs_a_task() {
        serial_print!("test rseq_needs_a_task... ");
        assert_eq!(
            sys_rseq(0x1000, 32, 0, 0),
            crate::linux::EINVAL,
            "rseq without a task"
        );
        serial_println!("[ok]");
    }

    #[test_case]
    fn user_pointer_rejects_kernel_and_holes() {
        serial_print!("test user_pointer_rejects_kernel_and_holes... ");
        let mut buf = [0u8; 16];
        assert!(!user_read(0, &mut buf));
        assert!(!user_read(0x4444_4444_0000, &mut buf));
        assert!(!user_read(0x2000, &mut buf));
        assert!(!user_read(0xFFFF_FFF0, &mut buf));
        assert!(!user_write(0x4444_4444_0000, &[1, 2, 3, 4]));
        assert!(!user_write(0x2000, &[1, 2, 3, 4]));
        assert!(copy_user_cstr(0x4444_4444_0000, 32).is_none());
        serial_println!("[ok]");
    }

    /// NUL в последних байтах страницы. Следующая страница не user.
    /// Раньше чтение фиксированными 64 байтами перешагивало границу и
    /// отказывало, хотя строка целиком лежала в смапленной странице.
    #[test_case]
    fn user_cstr_stops_at_nul_on_page_edge() {
        serial_print!("test user_cstr_stops_at_nul_on_page_edge... ");
        const PAGE: u64 = 0x7FFF_F000;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(PAGE));
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE;
        let phys_off = VirtAddr::new(crate::PHYS_OFFSET.load(Ordering::Relaxed));
        let frame = crate::memory::with_frame_allocator(|fa| {
            let mut mapper = unsafe { crate::memory::init(phys_off) };
            let frame = fa.allocate_frame().expect("frame");
            unsafe {
                mapper
                    .map_to(page, frame, flags, fa)
                    .expect("map page edge")
                    .flush();
            }
            let dst = (phys_off.as_u64() + frame.start_address().as_u64()) as *mut u8;
            unsafe {
                core::ptr::write_bytes(dst, 0xA5, 4096);
                *dst.add(4093) = b'o';
                *dst.add(4094) = b'k';
                *dst.add(4095) = 0;
            }
            frame
        });
        match copy_user_cstr(PAGE + 4093, 32) {
            Some(s) => assert_eq!(s.as_str(), "ok"),
            None => panic!("cstr at page edge"),
        }
        let mut spill = [0u8; 8];
        assert!(!user_read(PAGE + 4092, &mut spill));
        crate::memory::with_frame_allocator(|fa| {
            let mut mapper = unsafe { crate::memory::init(phys_off) };
            let (got, flush) = mapper.unmap(page).expect("unmap");
            flush.flush();
            assert_eq!(got.start_address(), frame.start_address());
            fa.deallocate_frame(got);
        });
        serial_println!("[ok]");
    }

    /// Собрать ET_DYN: строки с 0x100, .dynsym с 0x200, .dynamic с 0x300,
    /// .hash с 0x3C0, релокации с 0x440. `syms` — (имя, shndx, st_value, st_info).
    /// Индекс символа в релокации — номер в этой таблице, с 1.
    fn craft_dyn(
        needed: &[&str],
        syms: &[(&str, u16, u64, u8)],
        rels: &[(u64, u64, u64, u64)],
        jmprel: bool,
        dt_rel: bool,
        interp: Option<&str>,
    ) -> Vec<u8> {
        let mut strings = alloc::vec![0u8];
        let mut needed_at = Vec::new();
        for name in needed {
            needed_at.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut sym_at = Vec::new();
        for (name, _, _, _) in syms {
            sym_at.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        assert!(strings.len() <= 0x100, "dynstr overlaps symtab");

        let mut symtab = alloc::vec![0u8; 24];
        for i in 0..syms.len() {
            let (_, shndx, value, info) = syms[i];
            symtab.extend_from_slice(&sym_at[i].to_le_bytes());
            symtab.push(info);
            symtab.push(0);
            symtab.extend_from_slice(&shndx.to_le_bytes());
            symtab.extend_from_slice(&value.to_le_bytes());
            symtab.extend_from_slice(&0u64.to_le_bytes());
        }
        assert!(0x200 + symtab.len() <= 0x300, "dynsym overlaps dynamic");

        let mut tags: Vec<(u64, u64)> = Vec::new();
        for at in &needed_at {
            tags.push((1, *at));
        }
        tags.push((5, 0x100));
        tags.push((6, 0x200));
        tags.push((11, 24));
        if !syms.is_empty() || !rels.is_empty() {
            tags.push((4, 0x3C0));
        }
        if !rels.is_empty() && !jmprel {
            tags.push((7, 0x440));
            tags.push((8, (rels.len() * 24) as u64));
            tags.push((9, 24));
        }
        if !rels.is_empty() && jmprel {
            tags.push((23, 0x440));
            tags.push((2, (rels.len() * 24) as u64));
            tags.push((20, 7));
        }
        if dt_rel {
            tags.push((17, 1));
            tags.push((18, 8));
        }
        tags.push((0, 0));
        let mut dynamic = Vec::new();
        for (tag, val) in tags {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&val.to_le_bytes());
        }
        assert!(0x300 + dynamic.len() <= 0x3C0, "dynamic overlaps hash");

        let nchain = 1 + syms.len();
        let mut hash = Vec::new();
        hash.extend_from_slice(&1u32.to_le_bytes());
        hash.extend_from_slice(&(nchain as u32).to_le_bytes());
        hash.extend_from_slice(&1u32.to_le_bytes());
        for _ in 0..nchain {
            hash.extend_from_slice(&0u32.to_le_bytes());
        }

        let mut rela = Vec::new();
        for (off, typ, idx, addend) in rels {
            rela.extend_from_slice(&off.to_le_bytes());
            rela.extend_from_slice(&((idx << 32) | typ).to_le_bytes());
            rela.extend_from_slice(&addend.to_le_bytes());
        }

        let mut elf = alloc::vec![0u8; 0x100];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        let phnum: u16 = if interp.is_some() { 3 } else { 2 };
        elf[56..58].copy_from_slice(&phnum.to_le_bytes());

        let put_phdr = |elf: &mut Vec<u8>, at: usize, typ: u32, flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64| {
            let p = &mut elf[at..at + 56];
            p[0..4].copy_from_slice(&typ.to_le_bytes());
            p[4..8].copy_from_slice(&flags.to_le_bytes());
            p[8..16].copy_from_slice(&off.to_le_bytes());
            p[16..24].copy_from_slice(&vaddr.to_le_bytes());
            p[24..32].copy_from_slice(&vaddr.to_le_bytes());
            p[32..40].copy_from_slice(&filesz.to_le_bytes());
            p[40..48].copy_from_slice(&memsz.to_le_bytes());
            p[48..56].copy_from_slice(&align.to_le_bytes());
        };
        put_phdr(&mut elf, 0x40, 1, 7, 0, 0, 0, 0, 0x1000);
        put_phdr(&mut elf, 0x78, 2, 6, 0x300, 0x300, dynamic.len() as u64, dynamic.len() as u64, 8);
        if let Some(path) = interp {
            let bytes = path.as_bytes();
            assert!(bytes.len() < 120);
            let mut raw = bytes.to_vec();
            raw.push(0);
            elf.resize(0xF0 + raw.len(), 0);
            elf[0xF0..0xF0 + raw.len()].copy_from_slice(&raw);
            put_phdr(&mut elf, 0xB0, 3, 4, 0xF0, 0xF0, raw.len() as u64, raw.len() as u64, 1);
        }

        let place = |elf: &mut Vec<u8>, at: usize, data: &[u8]| {
            if elf.len() < at + data.len() {
                elf.resize(at + data.len(), 0);
            }
            elf[at..at + data.len()].copy_from_slice(data);
        };
        place(&mut elf, 0x100, &strings);
        place(&mut elf, 0x200, &symtab);
        place(&mut elf, 0x300, &dynamic);
        if !syms.is_empty() || !rels.is_empty() {
            place(&mut elf, 0x3C0, &hash);
        }
        if !rela.is_empty() {
            place(&mut elf, 0x440, &rela);
        }
        let len = elf.len() as u64;
        elf[0x40 + 32..0x40 + 40].copy_from_slice(&len.to_le_bytes());
        elf[0x40 + 40..0x40 + 48].copy_from_slice(&len.to_le_bytes());
        elf
    }

    #[test_case]
    fn dt_needed_binds_with_the_defining_bias() {
        serial_print!("test dt_needed_binds_with_the_defining_bias... ");
        let libapp = craft_dyn(&[/*no needed*/], &[("add", 1, 0x100, 0x12)], &[], false, false, None);
        let libld = craft_dyn(&[], &[("add", 1, 0x999, 0x12)], &[], false, false, None);
        // ld.so: свой UNDEF add должен найтись в libld, не в libapp.
        let ld = craft_dyn(
            &["libld.so"],
            &[("add", 0, 0, 0x10)],
            &[(0x480, 1, 1, 3)],
            false,
            false,
            None,
        );
        let main = craft_dyn(
            &["libapp.so"],
            &[("add", 0, 0, 0x10)],
            &[(0x480, 7, 1, 5)],
            true,
            false,
            Some("/bin/ld.so"),
        );
        let linked = link_with(main.as_slice(), |path| match path {
            "/lib/libapp.so" => Some(libapp.clone()),
            "/lib/libld.so" => Some(libld.clone()),
            "/bin/ld.so" => Some(ld.clone()),
            _ => None,
        })
        .expect("link");
        assert_eq!(linked.objs.len(), 4);
        assert_eq!(linked.interp_index, Some(2));
        assert_eq!(linked.objs[0].bias, 0x400000);
        assert_eq!(linked.objs[1].path.as_deref(), Some("/lib/libapp.so"));
        assert_eq!(linked.objs[1].bias, 0x0200_0000);
        assert_eq!(linked.objs[2].bias, 0x800000);
        assert_eq!(linked.objs[3].path.as_deref(), Some("/lib/libld.so"));
        assert_eq!(linked.objs[3].bias, 0x0220_0000);
        let app = &linked.objs[0].parsed.relative[0];
        assert_eq!(app.addend, 0, "JUMP_SLOT drops the addend");
        assert_eq!(app.sym, Some(0x100));
        assert_eq!(app.def_bias, Some(0x0200_0000));
        assert!(app.ext.is_none());
        let loader = &linked.objs[2].parsed.relative[0];
        assert_eq!(loader.addend, 3);
        assert_eq!(loader.sym, Some(0x999));
        assert_eq!(loader.def_bias, Some(0x0220_0000));
        serial_println!("[ok]");
    }

    #[test_case]
    fn weak_symbol_missing_is_zero_strong_refuses() {
        serial_print!("test weak_symbol_missing_is_zero_strong_refuses... ");
        let strong = craft_dyn(&[], &[("missing", 0, 0, 0x10)], &[(0x480, 1, 1, 0)], false, false, None);
        assert!(link_with(strong.as_slice(), |_| None).is_none());
        let weak = craft_dyn(&[], &[("missing", 0, 0, 0x20)], &[(0x480, 1, 1, 4)], false, false, None);
        let linked = link_with(weak.as_slice(), |_| None).expect("weak");
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0));
        assert_eq!(rel.def_bias, Some(0));
        assert_eq!(rel.addend, 4);
        assert!(rel.ext.is_none());
        serial_println!("[ok]");
    }

    #[test_case]
    fn dt_needed_cycle_loads_each_library_once() {
        serial_print!("test dt_needed_cycle_loads_each_library_once... ");
        let main = craft_dyn(&["liba.so"], &[], &[], false, false, None);
        let linked = link_with(main.as_slice(), |path| match path {
            "/lib/liba.so" => Some(craft_dyn(&["libb.so"], &[], &[], false, false, None)),
            "/lib/libb.so" => Some(craft_dyn(&["liba.so"], &[], &[], false, false, None)),
            _ => None,
        })
        .expect("cycle");
        assert_eq!(linked.objs.len(), 3);
        assert_eq!(linked.objs[1].path.as_deref(), Some("/lib/liba.so"));
        assert_eq!(linked.objs[2].path.as_deref(), Some("/lib/libb.so"));
        serial_println!("[ok]");
    }

    #[test_case]
    fn dt_rel_is_refused() {
        serial_print!("test dt_rel_is_refused... ");
        let elf = craft_dyn(&[], &[], &[], false, true, None);
        assert!(parse_elf64(&elf).is_none());
        serial_println!("[ok]");
    }

    #[test_case]
    fn apply_relative_uses_the_defining_bias() {
        serial_print!("test apply_relative_uses_the_defining_bias... ");
        // AddressSpace::drop сам берёт аллокатор кадров. Внутри with_frame_allocator
        // это повторный захват и зависание, поэтому таблицу освобождаем здесь.
        let (sym, relative) = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(0x2000_0000));
            map_zeroed(l4, page, fa, USER_FLAGS).expect("map");
            let rels = alloc::vec![
                RelaRel {
                    offset: 0,
                    addend: 0x20,
                    sym: Some(0x100),
                    def_bias: Some(0x400000),
                    ext: None,
                },
                RelaRel {
                    offset: 8,
                    addend: 5,
                    sym: None,
                    def_bias: None,
                    ext: None,
                },
            ];
            apply_relative(l4, &rels, 0x2000_0000).expect("apply");
            let mapper = unsafe { mapper_for(l4) };
            let phys = mapper
                .translate_addr(VirtAddr::new(0x2000_0000))
                .expect("phys");
            let ptr = (phys_offset().as_u64() + phys.as_u64()) as *const u8;
            let mut buf = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 16) };
            free_user_space(l4, fa);
            let sym = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            let relative = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            (sym, relative)
        });
        assert_eq!(sym, 0x100 + 0x20 + 0x400000);
        assert_eq!(relative, 5 + 0x2000_0000);
        serial_println!("[ok]");
    }
}
