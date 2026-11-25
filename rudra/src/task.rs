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
//!   0xA0000         страница ленивого PLT-резолвера
//!   0xA1000         старт GNU IFUNC: резолверы, затем прыжок на вход
//!   0xA2000         таблица этих вызовов (две страницы)
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
    pub lazy: Option<LazyBind>,
}

/// Слоты, которые первый вызов дописывает сам. Таблица общая у потоков
/// одного АП и у fork: пишется пользовательский GOT, не эта таблица.
pub struct LazyBind {
    slots: Vec<Vec<LazySlot>>,
}

struct LazySlot {
    arg: u64,
    got: u64,
    value: Option<u64>,
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
    /// st_value до базы определившего объекта. None — `R_X86_64_RELATIVE`,
    /// `R_X86_64_IRELATIVE` (резолвер — addend) или ещё не связанный
    /// внешний символ.
    sym: Option<u64>,
    /// База объекта, который определил символ. None — применить базу того
    /// объекта, в котором лежит релокация (свой символ или RELATIVE).
    def_bias: Option<u64>,
    /// Внешний символ: в этом объекте его нет, его закроет связь DT_NEEDED.
    ext: Option<ExtSym>,
    /// Байтовое смещение в `DT_JMPREL`, которое ленивый PLT кладёт на стек.
    jmprel_off: Option<u64>,
    /// Слот не писать при загрузке. Адрес запишет резолвер на первом вызове.
    defer: bool,
    /// Сильного символа нет. Загрузка жива, вызов убивает процесс.
    missing: bool,
    /// Вызвать резолвер и записать возврат. IRELATIVE: резолвер — `addend`
    /// плюс база этого объекта, к возврату ничего не прибавляется. Символ
    /// `STT_GNU_IFUNC`: резолвер — `st_value` плюс база определения, к
    /// возврату прибавляется `addend` (у `GLOB_DAT` и `JUMP_SLOT` он уже 0).
    ifunc: bool,
    /// `R_X86_64_COPY`: байты определения другого объекта пишутся в этот слот
    /// после обычных релокаций. Addend не используется. Ленивым слот не бывает.
    copy: bool,
    /// `st_size` символа в этом объекте. У COPY это размер слота назначения.
    ref_size: u64,
    /// `st_size` источника COPY. Ноль, пока связь не нашла определение.
    src_size: u64,
    /// Определение `STB_GLOBAL` или `STB_WEAK` с `STV_DEFAULT`. На связи его
    /// перехватывает более ранний объект. Локальный, скрытый и защищённый —
    /// None, они остаются в этом объекте.
    preempt: Option<ExtSym>,
}

#[derive(Clone)]
struct ExtSym {
    name: Vec<u8>,
    weak: bool,
    /// Имя версии из `DT_VERNEED`. None — ссылка без версии.
    ver: Option<Vec<u8>>,
    /// Файл из той же записи: сверяется с `DT_SONAME` или именем файла.
    file: Option<Vec<u8>>,
}

struct SymVer {
    name: Option<Vec<u8>>,
    hidden: bool,
    file: Option<Vec<u8>>,
    ver_weak: bool,
}

struct DynSym {
    symtab: Option<usize>,
    syment: u64,
    strtab: Option<usize>,
    nchain: u64,
    /// Параллельно `.dynsym`. Пусто — версий нет, поиск прежний.
    vers: Vec<SymVer>,
    soname: Option<Vec<u8>>,
}

impl DynSym {
    const fn none() -> Self {
        Self {
            symtab: None,
            syment: 24,
            strtab: None,
            nchain: 0,
            vers: Vec::new(),
            soname: None,
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
    /// `DT_RPATH`. None — тега нет. Пустой вектор — тег есть, каталогов нет.
    rpath: Option<Vec<String>>,
    /// `DT_RUNPATH`. Если тег есть, `DT_RPATH` этого объекта не используется.
    runpath: Option<Vec<String>>,
    /// `DT_PLTGOT`. Без него `JUMP_SLOT` связывается сразу.
    pltgot: Option<u64>,
    /// `DF_BIND_NOW` или `DF_1_NOW`: `JUMP_SLOT` этого объекта сразу.
    bind_now: bool,
    /// Слова `DT_RELR`. Пусто — тега нет.
    relr: Vec<u64>,
}

struct ParsedDyn {
    rels: Vec<RelaRel>,
    needed: Vec<String>,
    dynsym: DynSym,
    rpath: Option<Vec<String>>,
    runpath: Option<Vec<String>>,
    pltgot: Option<u64>,
    bind_now: bool,
    relr: Vec<u64>,
}

enum LocalSym {
    /// st_value, к нему прибавится база этого объекта.
    Own(u64),
    /// SHN_ABS: значение уже абсолютное, базу не прибавлять.
    Abs(u64),
    /// `STT_GNU_IFUNC`. st_value — адрес резолвера, база этого объекта.
    Ifunc(u64),
    /// `STT_GNU_IFUNC` и `SHN_ABS`: адрес резолвера уже абсолютный.
    IfuncAbs(u64),
    Ext {
        name: Vec<u8>,
        weak: bool,
        ver: Option<Vec<u8>>,
        file: Option<Vec<u8>>,
    },
}

/// Тип символа GNU IFUNC в младших четырёх битах `st_info`.
const STT_GNU_IFUNC: u8 = 10;

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
/// Релокации: `R_X86_64_RELATIVE`, `R_X86_64_64`, `R_X86_64_COPY`,
/// `R_X86_64_GLOB_DAT` и `R_X86_64_JUMP_SLOT` (в `DT_RELA` и в `DT_JMPREL`,
/// если `DT_PLTREL` — RELA). Локальный, скрытый и защищённый символ этого
/// объекта берётся сразу. Глобальный с видимостью по умолчанию на связи
/// ищется снова: более ранний объект в поиске перехватывает его.
/// `SHN_UNDEF` ищется здесь же по имени, иначе остаётся внешним до связи
/// `DT_NEEDED`.
/// Граница `.dynsym` — `nchain` из `DT_HASH`, а если его нет — число символов
/// из `DT_GNU_HASH`. Без обеих таблиц символьная релокация отвергается.
/// Версия символа — `DT_VERSYM` и имя из `DT_VERDEF` или `DT_VERNEED`.
/// `DT_REL` — те же типы, что `DT_RELA`, шаг 16: addend уже лежит в слоте.
/// `R_X86_64_IRELATIVE` и определённый
/// `STT_GNU_IFUNC` (в `R_X86_64_64`, `GLOB_DAT`, `JUMP_SLOT`) не пишутся
/// здесь: их резолвер вызовет стартовая страница до входа в программу.
/// `R_X86_64_COPY` копирует байты после обычных релокаций и до IFUNC.
/// `DT_RELR`: к уже лежащему слову прибавляется база. Чётная запись — адрес,
/// нечётная — битовая карта следующих 63 слотов. Прочие типы — отказ.
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
    let (relative, needed, dynsym, rpath, runpath, pltgot, bind_now, relr) = match dyn_span {
        Some((start, end)) => {
            let parsed = parse_relative(elf, &segs, &elf[start..end])?;
            (
                parsed.rels,
                parsed.needed,
                parsed.dynsym,
                parsed.rpath,
                parsed.runpath,
                parsed.pltgot,
                parsed.bind_now,
                parsed.relr,
            )
        }
        None => (Vec::new(), Vec::new(), DynSym::none(), None, None, None, false, Vec::new()),
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
        rpath,
        runpath,
        pltgot,
        bind_now,
        relr,
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
    let ifunc = elf[ent + 4] & 0xf == STT_GNU_IFUNC;
    if ifunc {
        return if shndx == 0xfff1 {
            Some(LocalSym::IfuncAbs(val))
        } else {
            Some(LocalSym::Ifunc(val))
        };
    }
    if shndx == 0xfff1 {
        Some(LocalSym::Abs(val))
    } else {
        Some(LocalSym::Own(val))
    }
}

/// Имя определения, которое более ранний объект может перехватить.
/// `STB_LOCAL`, пустое имя и видимость кроме `STV_DEFAULT` остаются местными.
/// Кривая запись версии тоже: символ не перехватывается, разбор жив.
/// `file` пуст: поиск не запирается на `DT_SONAME` этого объекта.
fn preempt_name(
    elf: &[u8],
    ent: usize,
    idx: u64,
    strtab: usize,
    vers: &[SymVer],
) -> Option<ExtSym> {
    let bind = elf[ent + 4] >> 4;
    if bind != 1 && bind != 2 {
        return None;
    }
    if elf[ent + 5] & 3 != 0 {
        return None;
    }
    let name = match sym_name(elf, strtab, rd32(elf, ent) as usize) {
        Ok(Some(n)) if !n.is_empty() && n.len() <= 256 => n,
        _ => return None,
    };
    let ver = if vers.is_empty() {
        None
    } else {
        vers.get(idx as usize)?.name.clone()
    };
    Some(ExtSym {
        name: name.to_vec(),
        weak: bind == 2,
        ver,
        file: None,
    })
}

/// Символ по индексу внутри этого объекта. Определённый — его st_value.
/// Второй элемент — имя для перехвата, и только у выбранного определения,
/// не у индекса релокации. SHN_UNDEF ищется по имени среди определённых.
/// Если здесь его нет, это внешний символ: связь с DT_NEEDED закроет его позже.
fn resolve_local(
    elf: &[u8],
    symtab: usize,
    syment: u64,
    strtab: usize,
    nchain: u64,
    vers: &[SymVer],
    idx: u64,
) -> Option<(LocalSym, Option<ExtSym>)> {
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
        let sym = local_defined(elf, ent, shndx)?;
        let pre = preempt_name(elf, ent, idx, strtab, vers);
        return Some((sym, pre));
    }
    let name = match sym_name(elf, strtab, rd32(elf, ent) as usize) {
        Ok(Some(n)) => n,
        _ => return None,
    };
    let want_name = if vers.is_empty() {
        None
    } else {
        vers.get(idx as usize)?.name.as_deref()
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
        if other == name && ver_accepts(vers, i, want_name) {
            let sym = local_defined(elf, e, sx)?;
            let pre = preempt_name(elf, e, i, strtab, vers);
            return Some((sym, pre));
        }
    }
    if name.len() > 256 {
        return None;
    }
    let (ver, file, ver_weak) = if vers.is_empty() {
        (None, None, false)
    } else {
        let v = vers.get(idx as usize)?;
        (v.name.clone(), v.file.clone(), v.ver_weak)
    };
    Some((
        LocalSym::Ext {
            name: name.to_vec(),
            weak: bind == 2 || ver_weak,
            ver,
            file,
        },
        None,
    ))
}

fn ver_accepts(vers: &[SymVer], idx: u64, want: Option<&[u8]>) -> bool {
    if vers.is_empty() {
        return want.is_none();
    }
    match vers.get(idx as usize) {
        Some(def) => match want {
            None => !def.hidden,
            Some(name) => def.name.as_deref() == Some(name),
        },
        None => false,
    }
}

/// Сколько записей в `.dynsym` по `DT_GNU_HASH` (ELF64, bloom по 8 байт).
/// Пустые bucket'ы дают границу `symoffset`. Цепочка идёт, пока младший бит
/// слова хеша не равен 1. Старший bucket — не последний символ: цепочка,
/// начавшаяся раньше, может быть длиннее. Обрезанная или зацикленная таблица
/// — `None`, а не догадка.
fn gnu_hash_nchain(elf: &[u8], off: usize) -> Option<u64> {
    const CAP: u64 = 1 << 20;
    if off.checked_add(16)? > elf.len() {
        return None;
    }
    let nbuckets = rd32(elf, off);
    let symoffset = rd32(elf, off + 4);
    let bloom_size = rd32(elf, off + 8);
    if nbuckets > CAP || symoffset > CAP || bloom_size > CAP {
        return None;
    }
    let bloom_bytes = (bloom_size as usize).checked_mul(8)?;
    let buckets_at = off.checked_add(16)?.checked_add(bloom_bytes)?;
    let buckets_bytes = (nbuckets as usize).checked_mul(4)?;
    let chain_at = buckets_at.checked_add(buckets_bytes)?;
    if chain_at > elf.len() {
        return None;
    }
    if nbuckets == 0 {
        return Some(symoffset);
    }
    let mut last = symoffset;
    let mut saw = false;
    for i in 0..nbuckets as usize {
        let bucket = rd32(elf, buckets_at + i * 4);
        if bucket == 0 {
            continue;
        }
        if bucket < symoffset || bucket > CAP {
            return None;
        }
        saw = true;
        let mut idx = bucket;
        loop {
            if idx > last {
                last = idx;
            }
            let chain_index = (idx - symoffset) as usize;
            let at = chain_at.checked_add(chain_index.checked_mul(4)?)?;
            if at.checked_add(4)? > elf.len() {
                return None;
            }
            if rd32(elf, at) & 1 != 0 {
                break;
            }
            idx += 1;
            if idx > CAP {
                return None;
            }
        }
    }
    if !saw {
        return Some(symoffset);
    }
    let count = last.checked_add(1)?;
    if count > CAP {
        None
    } else {
        Some(count)
    }
}

struct VerDefEnt {
    ndx: u16,
    name: Vec<u8>,
}

struct VerNeedEnt {
    ndx: u16,
    name: Vec<u8>,
    file: Vec<u8>,
    weak: bool,
}

fn cstr_vec(elf: &[u8], strtab: usize, off: usize) -> Option<Vec<u8>> {
    match sym_name(elf, strtab, off) {
        Ok(Some(n)) if !n.is_empty() && n.len() <= 256 => Some(n.to_vec()),
        _ => None,
    }
}

/// `DT_VERSYM` плюс имена из `DT_VERDEF` (определённый) и `DT_VERNEED`
/// (неопределённый). Кривая таблица — `None`, а не «версий нет».
fn parse_symvers(
    elf: &[u8],
    segs: &[LoadSeg],
    symtab: Option<usize>,
    syment: u64,
    strtab: Option<usize>,
    nchain: u64,
    versym_addr: u64,
    verdef_addr: u64,
    verdefnum: u64,
    verneed_addr: u64,
    verneednum: u64,
) -> Option<Vec<SymVer>> {
    let any = versym_addr != 0
        || verdef_addr != 0
        || verneed_addr != 0
        || verdefnum != 0
        || verneednum != 0;
    if !any {
        return Some(Vec::new());
    }
    if versym_addr == 0 || nchain == 0 || syment < 24 {
        return None;
    }
    if verdefnum > 64 || verneednum > 64 {
        return None;
    }
    if (verdef_addr == 0) != (verdefnum == 0) || (verneed_addr == 0) != (verneednum == 0) {
        return None;
    }
    let symtab = symtab?;
    let strtab = strtab?;
    let mut defs: Vec<VerDefEnt> = Vec::new();
    if verdefnum != 0 {
        let mut at = vaddr_file_off(segs, verdef_addr)? as usize;
        for n in 0..verdefnum {
            if at.checked_add(20)? > elf.len() {
                return None;
            }
            let version = rd16(elf, at);
            let ndx = rd16(elf, at + 4) as u16;
            let cnt = rd16(elf, at + 6);
            let aux = rd32(elf, at + 12) as usize;
            let next = rd32(elf, at + 16) as usize;
            if version != 1 || cnt == 0 || aux < 20 {
                return None;
            }
            let aux_at = at.checked_add(aux)?;
            if aux_at.checked_add(8)? > elf.len() {
                return None;
            }
            if ndx >= 2 {
                if defs.iter().any(|d| d.ndx == ndx) {
                    return None;
                }
                let name = cstr_vec(elf, strtab, rd32(elf, aux_at) as usize)?;
                defs.push(VerDefEnt { ndx, name });
            }
            if n + 1 == verdefnum {
                break;
            }
            if next == 0 {
                return None;
            }
            let next_at = at.checked_add(next)?;
            if next_at <= at {
                return None;
            }
            at = next_at;
        }
    }
    let mut needs: Vec<VerNeedEnt> = Vec::new();
    if verneednum != 0 {
        let mut at = vaddr_file_off(segs, verneed_addr)? as usize;
        for n in 0..verneednum {
            if at.checked_add(16)? > elf.len() {
                return None;
            }
            let version = rd16(elf, at);
            let cnt = rd16(elf, at + 2);
            let file_off = rd32(elf, at + 4) as usize;
            let aux = rd32(elf, at + 8) as usize;
            let next = rd32(elf, at + 12) as usize;
            if version != 1 || cnt == 0 || cnt > 64 || aux < 16 {
                return None;
            }
            let file = cstr_vec(elf, strtab, file_off)?;
            let mut aux_at = at.checked_add(aux)?;
            for k in 0..cnt {
                if aux_at.checked_add(16)? > elf.len() {
                    return None;
                }
                let flags = rd16(elf, aux_at + 4);
                let other = rd16(elf, aux_at + 6) as u16;
                let name_off = rd32(elf, aux_at + 8) as usize;
                let vnext = rd32(elf, aux_at + 12) as usize;
                if other < 2 || needs.iter().any(|v| v.ndx == other) {
                    return None;
                }
                let name = cstr_vec(elf, strtab, name_off)?;
                needs.push(VerNeedEnt {
                    ndx: other,
                    name,
                    file: file.clone(),
                    weak: flags & 2 != 0,
                });
                if k + 1 == cnt {
                    break;
                }
                if vnext == 0 {
                    return None;
                }
                let next_aux = aux_at.checked_add(vnext)?;
                if next_aux <= aux_at {
                    return None;
                }
                aux_at = next_aux;
            }
            if n + 1 == verneednum {
                break;
            }
            if next == 0 {
                return None;
            }
            let next_at = at.checked_add(next)?;
            if next_at <= at {
                return None;
            }
            at = next_at;
        }
    }
    let vs = vaddr_file_off(segs, versym_addr)? as usize;
    let nbytes = (nchain as usize).checked_mul(2)?;
    if vs.checked_add(nbytes)? > elf.len() {
        return None;
    }
    let mut vers = Vec::new();
    for i in 0..nchain as usize {
        let raw = rd16(elf, vs + i * 2) as u16;
        let hidden = raw & 0x8000 != 0;
        let ndx = raw & 0x7fff;
        let step = i.checked_mul(syment as usize)?;
        let ent = symtab.checked_add(step)?;
        if ent.checked_add(8)? > elf.len() {
            return None;
        }
        let shndx = rd16(elf, ent + 6);
        if ndx < 2 {
            vers.push(SymVer {
                name: None,
                hidden,
                file: None,
                ver_weak: false,
            });
            continue;
        }
        if shndx == 0 {
            let need = needs.iter().find(|v| v.ndx == ndx)?;
            vers.push(SymVer {
                name: Some(need.name.clone()),
                hidden,
                file: Some(need.file.clone()),
                ver_weak: need.weak,
            });
        } else {
            let def = defs.iter().find(|d| d.ndx == ndx)?;
            vers.push(SymVer {
                name: Some(def.name.clone()),
                hidden,
                file: None,
                ver_weak: false,
            });
        }
    }
    Some(vers)
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
    const DT_RELENT: u64 = 19;
    const DT_PLTREL: u64 = 20;
    const DT_JMPREL: u64 = 23;
    const DT_SONAME: u64 = 14;
    const DT_PLTGOT: u64 = 3;
    const DT_RPATH: u64 = 15;
    const DT_RUNPATH: u64 = 29;
    const DT_FLAGS: u64 = 30;
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    const DT_GNU_HASH: u64 = 0x6fff_fef5;
    const DT_VERSYM: u64 = 0x6fff_fff0;
    const DT_VERDEF: u64 = 0x6fff_fffc;
    const DT_VERDEFNUM: u64 = 0x6fff_fffd;
    const DT_VERNEED: u64 = 0x6fff_fffe;
    const DT_VERNEEDNUM: u64 = 0x6fff_ffff;
    const DT_RELRSZ: u64 = 35;
    const DT_RELR: u64 = 36;
    const DT_RELRENT: u64 = 37;
    const R_X86_64_64: u64 = 1;
    const R_COPY: u64 = 5;
    const R_GLOB_DAT: u64 = 6;
    const R_JUMP_SLOT: u64 = 7;
    const R_RELATIVE: u64 = 8;
    const R_IRELATIVE: u64 = 37;
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
    let mut gnu_addr = 0u64;
    let mut versym_addr = 0u64;
    let mut verdef_addr = 0u64;
    let mut verdefnum = 0u64;
    let mut verneed_addr = 0u64;
    let mut verneednum = 0u64;
    let mut soname_off: Option<u64> = None;
    let mut rpath_off: Option<u64> = None;
    let mut runpath_off: Option<u64> = None;
    let mut pltgot: Option<u64> = None;
    let mut flags = 0u64;
    let mut flags_1 = 0u64;
    let mut rel_addr = 0u64;
    let mut rel_sz = 0u64;
    let mut rel_ent = 16u64;
    let mut saw_relent = false;
    let mut jmprel = 0u64;
    let mut pltrelsz = 0u64;
    let mut pltrel = 0u64;
    let mut relr_addr = 0u64;
    let mut relr_sz = 0u64;
    let mut relrent = 0u64;
    let mut saw_relrent = false;
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
        } else if tag == DT_GNU_HASH {
            gnu_addr = val;
        } else if tag == DT_SONAME {
            soname_off = Some(val);
        } else if tag == DT_RPATH {
            rpath_off = Some(val);
        } else if tag == DT_RUNPATH {
            runpath_off = Some(val);
        } else if tag == DT_PLTGOT {
            pltgot = Some(val);
        } else if tag == DT_FLAGS {
            flags |= val;
        } else if tag == DT_FLAGS_1 {
            flags_1 |= val;
        } else if tag == DT_VERSYM {
            versym_addr = val;
        } else if tag == DT_VERDEF {
            verdef_addr = val;
        } else if tag == DT_VERDEFNUM {
            verdefnum = val;
        } else if tag == DT_VERNEED {
            verneed_addr = val;
        } else if tag == DT_VERNEEDNUM {
            verneednum = val;
        } else if tag == DT_REL {
            rel_addr = val;
        } else if tag == DT_RELSZ {
            rel_sz = val;
        } else if tag == DT_RELENT {
            rel_ent = val;
            saw_relent = true;
        } else if tag == DT_PLTREL {
            pltrel = val;
        } else if tag == DT_JMPREL {
            jmprel = val;
        } else if tag == DT_RELR {
            relr_addr = val;
        } else if tag == DT_RELRSZ {
            relr_sz = val;
        } else if tag == DT_RELRENT {
            relrent = val;
            saw_relrent = true;
        }
    }
    // DT_REL: шаг 16, addend в слоте. Один из адреса и размера — отказ.
    if saw_relent && rel_ent != 16 {
        return None;
    }
    if (rel_addr == 0) != (rel_sz == 0) || (rel_sz != 0 && rel_sz % 16 != 0) {
        return None;
    }
    if jmprel != 0 && pltrel != DT_RELA && pltrel != DT_REL {
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
    // Граница .dynsym. DT_HASH даёт nchain сразу. Иначе считаем символы по
    // DT_GNU_HASH: обход всех цепочек, не «максимальный bucket». Без обеих
    // таблиц символьную релокацию не резолвим. RELATIVE-only без хеша
    // по-прежнему принимается. Кривой GNU hash отвергает образ.
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
    } else if gnu_addr != 0 {
        let hoff = vaddr_file_off(segs, gnu_addr)? as usize;
        gnu_hash_nchain(elf, hoff)?
    } else {
        0
    };
    let soname = match soname_off {
        Some(off) => {
            let base = strtab_off?;
            Some(cstr_vec(elf, base, off as usize)?)
        }
        None => None,
    };
    let rpath = path_dirs(elf, strtab_off, rpath_off)?;
    let runpath = path_dirs(elf, strtab_off, runpath_off)?;
    let vers = parse_symvers(
        elf,
        segs,
        symtab_off,
        syment,
        strtab_off,
        nchain,
        versym_addr,
        verdef_addr,
        verdefnum,
        verneed_addr,
        verneednum,
    )?;
    let mut tables: Vec<(u64, u64, u64)> = Vec::new();
    if rel_sz != 0 {
        tables.push((rel_addr, rel_sz, 16));
    }
    if saw_rela && rela_sz != 0 {
        if rela_ent != 24 || rela_sz % 24 != 0 {
            return None;
        }
        tables.push((rela_addr, rela_sz, 24));
    }
    if jmprel != 0 {
        let stride = if pltrel == DT_REL { 16 } else { 24 };
        if pltrelsz == 0 || pltrelsz % stride != 0 {
            return None;
        }
        tables.push((jmprel, pltrelsz, stride));
    }
    let total: u64 = tables.iter().map(|(_, sz, _)| *sz).fold(0, |a, b| a.saturating_add(b));
    if total > 8192 * 24 {
        return None;
    }
    let mut out = Vec::new();
    for (addr, sz, stride) in tables {
        let start = vaddr_file_off(segs, addr)? as usize;
        let end = start.checked_add(sz as usize)?;
        if end > elf.len() {
            return None;
        }
        let step = stride as usize;
        let from_jmp = jmprel != 0 && addr == jmprel;
        let mut jmp_at = 0u64;
        let mut at = start;
        while at + step <= end {
            let entry_off = jmp_at;
            if from_jmp {
                jmp_at += stride;
            }
            let offset = rd64(elf, at);
            let info = rd64(elf, at + 8);
            let mut addend = if stride == 24 {
                rd64(elf, at + 16)
            } else {
                rel_place_addend(elf, segs, offset)?
            };
            let typ = info & 0xffff_ffff;
            at += step;
            if typ == 0 {
                continue;
            }
            if typ == R_GLOB_DAT || typ == R_JUMP_SLOT {
                // S, не S+A.
                addend = 0;
            }
            let jmprel_off = if from_jmp && typ == R_JUMP_SLOT {
                Some(entry_off)
            } else {
                None
            };
            let rel = match typ {
                R_RELATIVE => RelaRel {
                    offset,
                    addend,
                    sym: None,
                    def_bias: None,
                    ext: None,
                    jmprel_off,
                    defer: false,
                    missing: false,
                    ifunc: false,
                    copy: false,
                    ref_size: 0,
                    src_size: 0,
                    preempt: None,
                },
                R_IRELATIVE => RelaRel {
                    offset,
                    addend,
                    sym: None,
                    def_bias: None,
                    ext: None,
                    jmprel_off: None,
                    defer: false,
                    missing: false,
                    ifunc: true,
                    copy: false,
                    ref_size: 0,
                    src_size: 0,
                    preempt: None,
                },
                R_COPY => {
                    // Источник ищется в других объектах. Своё определение
                    // здесь не подставляется: копия читала бы саму себя.
                    // Слот не ленивый, даже если релокация лежит в DT_JMPREL.
                    let idx = info >> 32;
                    if syment < 24 || idx == 0 || idx >= nchain {
                        return None;
                    }
                    let step = (idx as usize).checked_mul(syment as usize)?;
                    let ent = symtab_off?.checked_add(step)?;
                    if ent.checked_add(24)? > elf.len() {
                        return None;
                    }
                    let name = match sym_name(elf, strtab_off?, rd32(elf, ent) as usize) {
                        Ok(Some(n)) if !n.is_empty() && n.len() <= 256 => n.to_vec(),
                        _ => return None,
                    };
                    let bind = elf[ent + 4] >> 4;
                    let (ver, file, ver_weak) = if vers.is_empty() {
                        (None, None, false)
                    } else {
                        let v = vers.get(idx as usize)?;
                        (v.name.clone(), v.file.clone(), v.ver_weak)
                    };
                    RelaRel {
                        offset,
                        addend: 0,
                        sym: None,
                        def_bias: None,
                        ext: Some(ExtSym {
                            name,
                            weak: bind == 2 || ver_weak,
                            ver,
                            file,
                        }),
                        jmprel_off: None,
                        defer: false,
                        missing: false,
                        ifunc: false,
                        copy: true,
                        ref_size: rd64(elf, ent + 16),
                        src_size: 0,
                        preempt: None,
                    }
                }
                R_X86_64_64 | R_GLOB_DAT | R_JUMP_SLOT => {
                    let (local, preempt) = resolve_local(
                        elf,
                        symtab_off?,
                        syment,
                        strtab_off?,
                        nchain,
                        &vers,
                        info >> 32,
                    )?;
                    match local {
                        LocalSym::Ifunc(v) => RelaRel {
                            offset,
                            addend,
                            sym: Some(v),
                            def_bias: None,
                            ext: None,
                            jmprel_off: None,
                            defer: false,
                            missing: false,
                            ifunc: true,
                            copy: false,
                            ref_size: 0,
                            src_size: 0,
                            preempt,
                        },
                        LocalSym::IfuncAbs(v) => RelaRel {
                            offset,
                            addend,
                            sym: Some(v),
                            def_bias: Some(0),
                            ext: None,
                            jmprel_off: None,
                            defer: false,
                            missing: false,
                            ifunc: true,
                            copy: false,
                            ref_size: 0,
                            src_size: 0,
                            preempt,
                        },
                        LocalSym::Own(v) => RelaRel {
                            offset,
                            addend,
                            sym: Some(v),
                            def_bias: None,
                            ext: None,
                            jmprel_off,
                            defer: false,
                            missing: false,
                            ifunc: false,
                            copy: false,
                            ref_size: 0,
                            src_size: 0,
                            preempt,
                        },
                        LocalSym::Abs(v) => RelaRel {
                            offset,
                            addend,
                            sym: Some(v),
                            def_bias: Some(0),
                            ext: None,
                            jmprel_off,
                            defer: false,
                            missing: false,
                            ifunc: false,
                            copy: false,
                            ref_size: 0,
                            src_size: 0,
                            preempt: None,
                        },
                        LocalSym::Ext { name, weak, ver, file } => RelaRel {
                            offset,
                            addend,
                            sym: None,
                            def_bias: None,
                            ext: Some(ExtSym { name, weak, ver, file }),
                            jmprel_off,
                            defer: false,
                            missing: false,
                            ifunc: false,
                            copy: false,
                            ref_size: 0,
                            src_size: 0,
                            preempt: None,
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
        dynsym: DynSym {
            symtab: symtab_off,
            syment,
            strtab: strtab_off,
            nchain,
            vers,
            soname,
        },
        rpath,
        runpath,
        pltgot,
        bind_now: flags & DF_BIND_NOW != 0 || flags_1 & DF_1_NOW != 0,
        relr: read_relr(elf, segs, relr_addr, relr_sz, relrent, saw_relrent)?,
    })
}

/// Слово целиком лежит в `PT_LOAD` и выровнено на 8. Дырка memsz — тоже слот:
/// там ноль, база прибавляется к нулю.
fn word_in_seg(segs: &[LoadSeg], place: u64) -> bool {
    if place & 7 != 0 {
        return false;
    }
    segs.iter().any(|s| {
        let Some(end) = s.vaddr.checked_add(s.mem_size) else {
            return false;
        };
        let Some(word_end) = place.checked_add(8) else {
            return false;
        };
        place >= s.vaddr && word_end <= end
    })
}

/// Обход `DT_RELR`, как glibc `ELF_DYNAMIC_DO_RELR`. Чётное слово — адрес,
/// курсор встаёт на следующее. Нечётное — младший бит маркер, остальные 63
/// бита отмечают слоты по 8 байт, затем курсор перешагивает все 63.
/// Битмап до первого адреса — отказ. `visit` ложен — отказ.
fn walk_relr(entries: &[u64], mut visit: impl FnMut(u64) -> bool) -> bool {
    let mut cursor: Option<u64> = None;
    for entry in entries {
        if entry & 1 == 0 {
            if !visit(*entry) {
                return false;
            }
            cursor = match entry.checked_add(8) {
                Some(next) => Some(next),
                None => return false,
            };
        } else {
            let Some(base) = cursor else {
                return false;
            };
            let mut bits = *entry;
            let mut i = 0u64;
            loop {
                bits >>= 1;
                if bits == 0 {
                    break;
                }
                if bits & 1 != 0 {
                    let Some(place) = i.checked_mul(8).and_then(|off| base.checked_add(off)) else {
                        return false;
                    };
                    if !visit(place) {
                        return false;
                    }
                }
                i = match i.checked_add(1) {
                    Some(n) if n <= 63 => n,
                    _ => return false,
                };
            }
            cursor = match base.checked_add(63 * 8) {
                Some(next) => Some(next),
                None => return false,
            };
        }
    }
    true
}

/// Прочитать `DT_RELR`. Оба нуля — таблицы нет. Один нуль, кривой шаг,
/// некратный размер, таблица больше `RELR_MAX` или слот вне сегмента — отказ.
fn read_relr(
    elf: &[u8],
    segs: &[LoadSeg],
    addr: u64,
    sz: u64,
    ent: u64,
    saw_ent: bool,
) -> Option<Vec<u64>> {
    if addr == 0 && sz == 0 {
        return Some(Vec::new());
    }
    if addr == 0 || sz == 0 || sz % 8 != 0 || sz > RELR_MAX {
        return None;
    }
    if saw_ent && ent != 8 {
        return None;
    }
    let start = vaddr_file_off(segs, addr)? as usize;
    let end = start.checked_add(sz as usize)?;
    if end > elf.len() {
        return None;
    }
    let mut entries = Vec::new();
    let mut at = start;
    while at + 8 <= end {
        entries.push(rd64(elf, at));
        at += 8;
    }
    if !walk_relr(&entries, |place| word_in_seg(segs, place)) {
        return None;
    }
    Some(entries)
}

/// Строка `DT_RPATH` или `DT_RUNPATH`: каталоги через `:`.
/// None на входе — тега нет. Пустая строка — тег есть.
fn path_dirs(elf: &[u8], strtab: Option<usize>, off: Option<u64>) -> Option<Option<Vec<String>>> {
    let Some(off) = off else {
        return Some(None);
    };
    let base = strtab?;
    let text = match sym_name(elf, base, off as usize) {
        Ok(Some(raw)) => {
            if raw.len() > 1024 {
                return None;
            }
            core::str::from_utf8(raw).ok()?
        }
        Ok(None) => "",
        Err(()) => return None,
    };
    let mut dirs = Vec::new();
    if !text.is_empty() {
        for part in text.split(':') {
            if part.is_empty() {
                continue;
            }
            if part.len() > 200 || dirs.len() >= 32 {
                return None;
            }
            dirs.push(String::from(part));
        }
    }
    Some(Some(dirs))
}

fn vaddr_file_off(segs: &[LoadSeg], vaddr: u64) -> Option<u64> {
    for seg in segs {
        if vaddr >= seg.vaddr && vaddr - seg.vaddr < seg.file_size {
            return Some(seg.offset + (vaddr - seg.vaddr));
        }
    }
    None
}

/// Addend записи `DT_REL`: восемь байт по адресу слота в файле.
/// Адреса в файле нет — ноль (BSS). Восемь байт не влезают в файл — отказ.
fn rel_place_addend(elf: &[u8], segs: &[LoadSeg], vaddr: u64) -> Option<u64> {
    for seg in segs {
        if vaddr < seg.vaddr || seg.file_size == 0 {
            continue;
        }
        let delta = vaddr - seg.vaddr;
        if delta >= seg.file_size {
            continue;
        }
        if delta.checked_add(8)? > seg.file_size {
            return None;
        }
        let off = (seg.offset.checked_add(delta)?) as usize;
        if off.checked_add(8)? > elf.len() {
            return None;
        }
        return Some(rd64(elf, off));
    }
    Some(0)
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
/// Одна страница кода ленивого резолвера. Её адрес пишется в GOT[2].
const RESOLVE_PAGE: u64 = 0xA_0000;
/// Стартовая страница GNU IFUNC. Процесс входит сюда, резолверы
/// отрабатывают, затем прыжок на настоящий вход.
const IFUNC_PAGE: u64 = 0xA_1000;
/// Таблица вызовов: счётчик, настоящий вход, затем тройки
/// (слот, резолвер, addend). Две страницы, не больше `IFUNC_MAX` записей.
const IFUNC_TABLE: u64 = 0xA_2000;
const IFUNC_MAX: usize = 256;
/// Потолок `min(st_size)` у `R_X86_64_COPY`. Больший из двух размеров не важен.
const COPY_MAX: u64 = 64 * 1024;
/// Потолок таблицы `DT_RELR` в байтах. Тот же, что у суммы `DT_RELA`.
const RELR_MAX: u64 = 8192 * 24;
/// Приватный номер: вход резолвера, не вызов Linux.
pub const DL_FIXUP_NR: u64 = 1024;
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
    /// Кто записал этот объект в `DT_NEEDED`. У программы и интерпретатора нет.
    loaded_by: Option<usize>,
}

struct Linked {
    objs: Vec<LinkObj>,
    interp_index: Option<usize>,
}

/// Каталог файла: `/app/bin/prog` → `/app/bin`, `/prog` → пустая строка.
fn origin_dir(path: Option<&str>) -> Option<String> {
    let path = path?;
    match path.rfind('/') {
        Some(0) | None => Some(String::new()),
        Some(i) => Some(String::from(&path[..i])),
    }
}

/// Длина DST после `$`. `ORIGIN`, `LIB`, `PLATFORM`, в том числе в `${...}`.
fn dst_len(input: &[u8], name: &[u8]) -> Option<usize> {
    let (body, curly) = if input.first() == Some(&b'{') {
        (&input[1..], true)
    } else {
        (input, false)
    };
    if body.len() < name.len() || &body[..name.len()] != name {
        return None;
    }
    let after = &body[name.len()..];
    if curly {
        if after.first() != Some(&b'}') {
            return None;
        }
        return Some(name.len() + 2);
    }
    if let Some(&c) = after.first() {
        if c.is_ascii_alphanumeric() || c == b'_' {
            return None;
        }
    }
    Some(name.len())
}

/// `$ORIGIN` — каталог объекта, `$LIB` — `lib`. `$PLATFORM` отвергает строку.
/// Прочий `$` остаётся как есть.
fn expand_token(raw: &str, origin: Option<&str>) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let rest = &bytes[i + 1..];
        if let Some(n) = dst_len(rest, b"ORIGIN") {
            out.extend_from_slice(origin?.as_bytes());
            i += 1 + n;
        } else if let Some(n) = dst_len(rest, b"LIB") {
            out.extend_from_slice(b"lib");
            i += 1 + n;
        } else if dst_len(rest, b"PLATFORM").is_some() {
            return None;
        } else {
            out.push(b'$');
            i += 1;
        }
    }
    if out.len() > 200 {
        return None;
    }
    core::str::from_utf8(&out).ok().map(String::from)
}

fn expand_dirs(raw: &[String], origin: Option<&str>, cwd: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for dir in raw {
        let expanded = expand_token(dir, origin)?;
        if expanded.is_empty() {
            continue;
        }
        out.push(crate::fs::resolve(cwd, &expanded)?);
    }
    Some(out)
}

/// `DT_RPATH` до `LD_LIBRARY_PATH`. `DT_RUNPATH` того объекта, чей
/// `DT_NEEDED` резолвится, отменяет всякий `DT_RPATH` (сам `DT_RUNPATH`
/// подставляется позже). Иначе — `DT_RPATH` объекта, затем его загрузчиков.
/// `DT_RPATH` библиотеки действует и для зависимостей её зависимостей, даже
/// если у неё самой есть `DT_RUNPATH`: тот смотрит только прямые. `DT_RPATH`
/// программы не используется, если у программы есть `DT_RUNPATH`. Если
/// цепочка загрузчиков до программы не дошла, её `DT_RPATH` добавляется
/// в конце.
fn rpath_dirs(objs: &[LinkObj], index: usize, cwd: &str) -> Option<Vec<String>> {
    if objs[index].parsed.runpath.is_some() {
        return Some(Vec::new());
    }
    let mut dirs = Vec::new();
    let mut cur = Some(index);
    let mut saw_main = false;
    while let Some(i) = cur {
        if i == 0 {
            saw_main = true;
        }
        // У программы с DT_RUNPATH её DT_RPATH выключен целиком.
        if !(i == 0 && objs[0].parsed.runpath.is_some()) {
            if let Some(raw) = &objs[i].parsed.rpath {
                let origin = origin_dir(objs[i].path.as_deref());
                for dir in expand_dirs(raw, origin.as_deref(), cwd)? {
                    dirs.push(dir);
                }
            }
        }
        cur = objs[i].loaded_by;
    }
    if !saw_main && objs[0].parsed.runpath.is_none() {
        if let Some(raw) = &objs[0].parsed.rpath {
            let origin = origin_dir(objs[0].path.as_deref());
            for dir in expand_dirs(raw, origin.as_deref(), cwd)? {
                dirs.push(dir);
            }
        }
    }
    Some(dirs)
}

/// `DT_RUNPATH` только того объекта, чей `DT_NEEDED` резолвится.
fn referring_runpath(objs: &[LinkObj], index: usize, cwd: &str) -> Option<Vec<String>> {
    let Some(raw) = objs[index].parsed.runpath.as_deref() else {
        return Some(Vec::new());
    };
    let origin = origin_dir(objs[index].path.as_deref());
    expand_dirs(raw, origin.as_deref(), cwd)
}

/// `LD_LIBRARY_PATH`: каталоги через `:` или `;`. Переменной нет — пустой
/// список. `$ORIGIN` здесь каталог программы. Кривой список отвергает
/// загрузку.
fn library_path_dirs(raw: Option<&str>, origin: Option<&str>, cwd: &str) -> Option<Vec<String>> {
    let Some(text) = raw else {
        return Some(Vec::new());
    };
    if text.len() > 1024 {
        return None;
    }
    let mut parts = Vec::new();
    if !text.is_empty() {
        let normalized = text.replace(';', ":");
        for part in normalized.split(':') {
            if part.is_empty() {
                continue;
            }
            if part.len() > 200 || parts.len() >= 32 {
                return None;
            }
            parts.push(String::from(part));
        }
    }
    expand_dirs(&parts, origin, cwd)
}

/// Первая `LD_LIBRARY_PATH` в envp. Повтора нет: берётся первая.
fn ld_library_path(envp: &[String]) -> Option<&str> {
    envp.iter()
        .find_map(|ent| ent.strip_prefix("LD_LIBRARY_PATH="))
}

/// Переменная есть — даже пустая. Тогда все `JUMP_SLOT` связываются сразу.
fn ld_bind_now(envp: &[String]) -> bool {
    envp.iter()
        .any(|ent| ent == "LD_BIND_NOW" || ent.starts_with("LD_BIND_NOW="))
}

fn lib_in(dir: &str, name: &str) -> Option<String> {
    let mut path = String::from(dir);
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(name);
    crate::fs::resolve("/", &path)
}

/// Куда пробовать `DT_NEEDED`, по порядку. Имя без слэша — `DT_RPATH`,
/// затем `LD_LIBRARY_PATH`, затем `DT_RUNPATH` этого объекта, затем `/lib`.
/// Путь со слэшем — один файл, от cwd после подстановки.
fn locate_needed(
    objs: &[LinkObj],
    index: usize,
    spec: &str,
    cwd: &str,
    libpath: &[String],
) -> Option<Vec<String>> {
    if spec.is_empty() || spec.len() > 200 || spec.as_bytes().contains(&0) {
        return None;
    }
    let origin = origin_dir(objs[index].path.as_deref());
    let expanded = expand_token(spec, origin.as_deref())?;
    if expanded.is_empty() || expanded.len() > 200 {
        return None;
    }
    if expanded.contains('/') {
        return Some(alloc::vec![crate::fs::resolve(cwd, &expanded)?]);
    }
    if expanded.starts_with('.') {
        return None;
    }
    let mut cands = Vec::new();
    for dir in rpath_dirs(objs, index, cwd)? {
        cands.push(lib_in(&dir, &expanded)?);
    }
    for dir in libpath {
        cands.push(lib_in(dir, &expanded)?);
    }
    for dir in referring_runpath(objs, index, cwd)? {
        cands.push(lib_in(&dir, &expanded)?);
    }
    let mut fallback = String::from("/lib/");
    fallback.push_str(&expanded);
    cands.push(crate::fs::resolve("/", &fallback)?);
    Some(cands)
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
        (RESOLVE_PAGE, RESOLVE_PAGE + 0x1000),
        (IFUNC_PAGE, IFUNC_PAGE + 0x1000),
        (IFUNC_TABLE, IFUNC_TABLE + 0x2000),
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

fn load_needed<F>(
    objs: &mut Vec<LinkObj>,
    seen: &mut Vec<String>,
    start: usize,
    fetch: &mut F,
    group: u8,
    cwd: &str,
    libpath: &[String],
) -> bool
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
            let Some(cands) = locate_needed(objs, index, &spec, cwd, libpath) else {
                serial_println!("[task] DT_NEEDED path rejected: {}", spec);
                return false;
            };
            let mut skip = false;
            let mut chosen: Option<(String, Vec<u8>)> = None;
            for path in cands {
                if seen.iter().any(|have| have == &path) {
                    skip = true;
                    break;
                }
                if objs.len() >= MAX_LINK {
                    serial_println!("[task] DT_NEEDED cap {}", MAX_LINK);
                    return false;
                }
                if let Some(bytes) = fetch(&path) {
                    chosen = Some((path, bytes));
                    break;
                }
            }
            if skip {
                continue;
            }
            let Some((path, bytes)) = chosen else {
                serial_println!("[task] DT_NEEDED missing {}", spec);
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
                loaded_by: Some(index),
            });
            queue.push(objs.len() - 1);
        }
    }
    true
}

enum Hit {
    Found {
        value: u64,
        bias: u64,
        ifunc: bool,
        size: u64,
    },
    Bad,
}

/// `DT_SONAME`, иначе последний компонент пути.
fn object_id(obj: &LinkObj) -> Option<&[u8]> {
    if let Some(soname) = obj.parsed.dynsym.soname.as_deref() {
        return Some(soname);
    }
    let path = obj.path.as_deref()?;
    let bytes = path.as_bytes();
    let tail = match bytes.iter().rposition(|b| *b == b'/') {
        Some(i) => &bytes[i + 1..],
        None => bytes,
    };
    if tail.is_empty() { None } else { Some(tail) }
}

/// Определённый глобальный или слабый символ. Локальные пропускаются.
/// Скрытая версия не годится ссылке без версии. Имя версии и файл должны
/// совпасть. SHN_COMMON и обрезанная таблица — ошибка, не «символа нет».
fn defined(
    obj: &LinkObj,
    name: &[u8],
    ver: Option<&[u8]>,
    file: Option<&[u8]>,
) -> Result<Option<(u64, u64, u8, bool, u64)>, ()> {
    if let Some(want_file) = file {
        match object_id(obj) {
            Some(got) if got == want_file => {}
            _ => return Ok(None),
        }
    }
    let dynsym = &obj.parsed.dynsym;
    let (Some(symtab), Some(strtab)) = (dynsym.symtab, dynsym.strtab) else {
        return Ok(None);
    };
    if dynsym.nchain == 0 || dynsym.syment < 24 {
        return Ok(None);
    }
    let elf = obj.bytes.as_slice();
    let mut weak: Option<(u64, u64, bool, u64)> = None;
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
        if other != name || !ver_accepts(&dynsym.vers, i, ver) {
            continue;
        }
        if shndx == 0xfff2 || shndx == 0xffff {
            return Err(());
        }
        let value = rd64(elf, ent + 8);
        let size = rd64(elf, ent + 16);
        let bias = if shndx == 0xfff1 { 0 } else { obj.bias };
        let ifunc = elf[ent + 4] & 0xf == STT_GNU_IFUNC;
        if bind == 2 {
            if weak.is_none() {
                weak = Some((value, bias, ifunc, size));
            }
            continue;
        }
        return Ok(Some((value, bias, bind, ifunc, size)));
    }
    Ok(weak.map(|(value, bias, ifunc, size)| (value, bias, 2, ifunc, size)))
}

fn lookup(
    objs: &[LinkObj],
    group: u8,
    name: &[u8],
    ver: Option<&[u8]>,
    file: Option<&[u8]>,
    skip: Option<usize>,
) -> Option<Hit> {
    let mut weak: Option<(u64, u64, bool, u64)> = None;
    let passes: &[u8] = if group == 0 { &[0] } else { &[1, 0] };
    for pass in passes {
        for (oi, obj) in objs.iter().enumerate() {
            if obj.group != *pass || skip == Some(oi) {
                continue;
            }
            match defined(obj, name, ver, file) {
                Ok(None) => {}
                Ok(Some((value, bias, 2, ifunc, size))) => {
                    if weak.is_none() {
                        weak = Some((value, bias, ifunc, size));
                    }
                }
                Ok(Some((value, bias, _, ifunc, size))) => {
                    return Some(Hit::Found {
                        value,
                        bias,
                        ifunc,
                        size,
                    });
                }
                Err(()) => return Some(Hit::Bad),
            }
        }
    }
    weak.map(|(value, bias, ifunc, size)| Hit::Found {
        value,
        bias,
        ifunc,
        size,
    })
}

/// `JUMP_SLOT` из `DT_JMPREL` остаётся на первый вызов, если у объекта есть
/// `DT_PLTGOT` и ни объект, ни `LD_BIND_NOW` не просят связать сразу.
fn object_is_lazy(obj: &LinkObj, env_now: bool) -> bool {
    !env_now
        && !obj.parsed.bind_now
        && obj.parsed.pltgot.is_some()
        && obj.parsed.relative.iter().any(|rel| rel.jmprel_off.is_some())
}

fn bind_all(objs: &mut [LinkObj], env_now: bool) -> bool {
    for obj in objs.iter_mut() {
        if object_is_lazy(obj, env_now) {
            for rel in &mut obj.parsed.relative {
                if rel.jmprel_off.is_some() {
                    rel.defer = true;
                }
            }
        }
    }
    for i in 0..objs.len() {
        for r in 0..objs[i].parsed.relative.len() {
            if objs[i].parsed.relative[r].copy {
                let Some(ext) = objs[i].parsed.relative[r].ext.clone() else {
                    serial_println!("[task] COPY undefined");
                    return false;
                };
                let group = objs[i].group;
                let ref_size = objs[i].parsed.relative[r].ref_size;
                let shown = core::str::from_utf8(&ext.name).unwrap_or("?");
                match lookup(
                    objs,
                    group,
                    &ext.name,
                    ext.ver.as_deref(),
                    ext.file.as_deref(),
                    Some(i),
                ) {
                    Some(Hit::Found {
                        value,
                        bias,
                        ifunc,
                        size,
                    }) => {
                        if ifunc {
                            serial_println!("[task] COPY of IFUNC {}", shown);
                            return false;
                        }
                        // Отказ только когда копируется больше потолка.
                        // Огромный второй размер при маленьком минимуме жив.
                        if size.min(ref_size) > COPY_MAX {
                            serial_println!("[task] COPY too large {}", shown);
                            return false;
                        }
                        let rel = &mut objs[i].parsed.relative[r];
                        rel.sym = Some(value);
                        rel.def_bias = Some(bias);
                        rel.src_size = size;
                        rel.ext = None;
                    }
                    Some(Hit::Bad) => {
                        serial_println!("[task] bad dynsym while resolving {}", shown);
                        return false;
                    }
                    None => {
                        // Слабый COPY без источника — тоже отказ, не ноль.
                        serial_println!("[task] COPY undefined {}", shown);
                        return false;
                    }
                }
                continue;
            }
            let Some(ext) = objs[i].parsed.relative[r].ext.clone() else {
                continue;
            };
            let group = objs[i].group;
            let shown = core::str::from_utf8(&ext.name).unwrap_or("?");
            match lookup(
                objs,
                group,
                &ext.name,
                ext.ver.as_deref(),
                ext.file.as_deref(),
                None,
            ) {
                Some(Hit::Found {
                    value,
                    bias,
                    ifunc,
                    size: _,
                }) => {
                    let rel = &mut objs[i].parsed.relative[r];
                    rel.sym = Some(value);
                    rel.def_bias = Some(bias);
                    rel.ext = None;
                    if ifunc {
                        // Адрес — возврат резолвера. Ленивый PLT записал бы
                        // st_value. Слот закроет стартовая страница.
                        rel.ifunc = true;
                        rel.defer = false;
                        rel.jmprel_off = None;
                    }
                }
                Some(Hit::Bad) => {
                    serial_println!("[task] bad dynsym while resolving {}", shown);
                    return false;
                }
                None => {
                    let rel = &mut objs[i].parsed.relative[r];
                    if ext.weak {
                        rel.sym = Some(0);
                        rel.def_bias = Some(0);
                        rel.ext = None;
                    } else if rel.defer {
                        rel.missing = true;
                        serial_println!("[task] lazy undefined {}", shown);
                    } else {
                        serial_println!("[task] undefined symbol {}", shown);
                        return false;
                    }
                }
            }
        }
    }
    // Перехват после внешней связи. Победитель — тот же адрес и тот же
    // IFUNC: поле базы не трогаем, свой символ остаётся со своей базой.
    for i in 0..objs.len() {
        let group = objs[i].group;
        let own_bias = objs[i].bias;
        for r in 0..objs[i].parsed.relative.len() {
            if objs[i].parsed.relative[r].copy {
                continue;
            }
            let Some(pre) = objs[i].parsed.relative[r].preempt.clone() else {
                continue;
            };
            let shown = core::str::from_utf8(&pre.name).unwrap_or("?");
            match lookup(
                objs,
                group,
                &pre.name,
                pre.ver.as_deref(),
                pre.file.as_deref(),
                None,
            ) {
                Some(Hit::Found {
                    value,
                    bias,
                    ifunc,
                    size: _,
                }) => {
                    let rel = &mut objs[i].parsed.relative[r];
                    if rel.sym == Some(value)
                        && rel.def_bias.unwrap_or(own_bias) == bias
                        && rel.ifunc == ifunc
                    {
                        continue;
                    }
                    rel.sym = Some(value);
                    rel.def_bias = Some(bias);
                    if ifunc {
                        rel.ifunc = true;
                        rel.defer = false;
                        rel.jmprel_off = None;
                    } else if rel.ifunc {
                        rel.ifunc = false;
                    }
                }
                Some(Hit::Bad) => {
                    serial_println!("[task] bad dynsym while resolving {}", shown);
                    return false;
                }
                None => {}
            }
        }
    }
    true
}

fn link_with<F>(main_bytes: &[u8], fetch: F) -> Option<Linked>
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    link_at(main_bytes, None, "/", None, false, fetch)
}

fn link_at<F>(
    main_bytes: &[u8],
    origin: Option<&str>,
    cwd: &str,
    libpath: Option<&str>,
    bind_now: bool,
    mut fetch: F,
) -> Option<Linked>
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let main_path = match origin {
        Some(path) => match crate::fs::resolve("/", path) {
            Some(canon) => Some(canon),
            None => {
                serial_println!("[task] bad executable path");
                return None;
            }
        },
        None => None,
    };
    let main_origin = origin_dir(main_path.as_deref());
    let lib_dirs = match library_path_dirs(libpath, main_origin.as_deref(), cwd) {
        Some(dirs) => dirs,
        None => {
            serial_println!("[task] bad LD_LIBRARY_PATH");
            return None;
        }
    };
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
        path: main_path,
        loaded_by: None,
    });
    let mut seen = Vec::new();
    if !load_needed(&mut objs, &mut seen, 0, &mut fetch, 0, cwd, &lib_dirs) {
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
            loaded_by: None,
        });
        let index = objs.len() - 1;
        interp_index = Some(index);
        if !load_needed(&mut objs, &mut seen, index, &mut fetch, 1, cwd, &lib_dirs) {
            return None;
        }
    }
    if !bind_all(&mut objs, bind_now) {
        return None;
    }
    // Резолвер по адресу 0 и слишком длинный список — отказ образа,
    // а не тихий пропуск вызова.
    if ifunc_calls(&objs).is_none() {
        return None;
    }
    Some(Linked { objs, interp_index })
}

fn link_program(bytes: &[u8], origin: &str, cwd: &str, envp: &[String]) -> Option<Linked> {
    link_at(
        bytes,
        Some(origin),
        cwd,
        ld_library_path(envp),
        ld_bind_now(envp),
        |path| crate::fs::read_canon(path),
    )
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
    pub lazy: Option<Arc<LazyBind>>,
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
            lazy: None,
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

/// EFER без NXE: бит NX в PTE — reserved fault. `mprotect` его не ставит.
fn prot_flags(prot: u64) -> PageTableFlags {
    if prot == 0 {
        PageTableFlags::PRESENT
    } else if prot & 2 != 0 {
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
    } else {
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
    }
}

fn align_up_page(x: u64) -> u64 {
    x.saturating_add(0xFFF) & !0xFFF
}

/// Страницы, которые сжатый brk больше не занимает: `[align_up(new), align_up(old))`.
fn brk_free_span(old: u64, new: u64) -> Option<(u64, u64)> {
    if new >= old {
        return None;
    }
    let start = align_up_page(new);
    let end = align_up_page(old);
    if end > start {
        Some((start, end))
    } else {
        None
    }
}

fn pt_ptr(phys: u64) -> *mut PageTable {
    let off = crate::PHYS_OFFSET.load(Ordering::Relaxed);
    off.wrapping_add(phys) as *mut PageTable
}

fn read_pte(table: u64, index: usize) -> (u64, PageTableFlags) {
    let ptr = pt_ptr(table);
    let table = unsafe { &*ptr };
    let entry = &table[index];
    (entry.addr().as_u64(), entry.flags())
}

fn clear_pte(table: u64, index: usize) {
    let ptr = pt_ptr(table);
    unsafe {
        (&mut *ptr)[index].set_unused();
    }
}

fn set_pte_flags(table: u64, index: usize, flags: PageTableFlags) {
    let ptr = pt_ptr(table);
    unsafe {
        (&mut *ptr)[index].set_flags(flags);
    }
}

fn table_any_present(phys: u64) -> bool {
    let table = unsafe { &*pt_ptr(phys) };
    for i in 0..512 {
        if table[i].flags().contains(PageTableFlags::PRESENT) {
            return true;
        }
    }
    false
}

enum Spot {
    Missing { skip: u64 },
    Huge,
    Leaf { table: u64, index: usize, phys: u64 },
}

fn region_skip(va: u64, align: u64) -> u64 {
    let base = va & !(align - 1);
    let next = base.saturating_add(align);
    next.saturating_sub(va).max(0x1000)
}

fn spot(l4: u64, va: u64) -> Spot {
    let i4 = ((va >> 39) & 0x1ff) as usize;
    let i3 = ((va >> 30) & 0x1ff) as usize;
    let i2 = ((va >> 21) & 0x1ff) as usize;
    let i1 = ((va >> 12) & 0x1ff) as usize;
    let (l3, f4) = read_pte(l4, i4);
    if !f4.contains(PageTableFlags::PRESENT) {
        return Spot::Missing {
            skip: region_skip(va, 1 << 39),
        };
    }
    let (l2, f3) = read_pte(l3, i3);
    if f3.contains(PageTableFlags::PRESENT) && f3.contains(PageTableFlags::HUGE_PAGE) {
        return Spot::Huge;
    }
    if !f3.contains(PageTableFlags::PRESENT) {
        return Spot::Missing {
            skip: region_skip(va, 1 << 30),
        };
    }
    let (l1, f2) = read_pte(l2, i2);
    if f2.contains(PageTableFlags::PRESENT) && f2.contains(PageTableFlags::HUGE_PAGE) {
        return Spot::Huge;
    }
    if !f2.contains(PageTableFlags::PRESENT) {
        return Spot::Missing {
            skip: region_skip(va, 1 << 21),
        };
    }
    let (phys, f1) = read_pte(l1, i1);
    if !f1.contains(PageTableFlags::PRESENT) {
        return Spot::Missing { skip: 0x1000 };
    }
    Spot::Leaf {
        table: l1,
        index: i1,
        phys,
    }
}

fn range_has_huge(l4: u64, start: u64, end: u64) -> bool {
    let mut va = start;
    while va < end {
        match spot(l4, va) {
            Spot::Huge => return true,
            Spot::Missing { skip } => {
                let step = skip.min(end - va).max(0x1000);
                let next = va.saturating_add(step);
                if next <= va {
                    return false;
                }
                va = next;
            }
            Spot::Leaf { .. } => va = va.saturating_add(0x1000),
        }
    }
    false
}

fn aligned_user_span(start: u64, end: u64) -> Result<(), u64> {
    if start > end || end > USER_TOP || (start & 0xFFF) != 0 || (end & 0xFFF) != 0 {
        Err(crate::linux::EINVAL)
    } else {
        Ok(())
    }
}

/// `len == 0` — пустой диапазон. Иначе страницы `[addr, addr+len)` внутри 4 ГиБ.
fn page_span(addr: u64, len: u64) -> Result<Option<(u64, u64)>, u64> {
    if len == 0 {
        return Ok(None);
    }
    if addr & 0xFFF != 0 {
        return Err(crate::linux::EINVAL);
    }
    let rounded = len
        .checked_add(0xFFF)
        .ok_or(crate::linux::EINVAL)?
        & !0xFFF;
    if rounded == 0 {
        return Ok(None);
    }
    let end = addr.checked_add(rounded).ok_or(crate::linux::EINVAL)?;
    if end > USER_TOP {
        return Err(crate::linux::EINVAL);
    }
    Ok(Some((addr, end)))
}

/// Снять лист и пустые таблицы над ним. L4 не трогает. Кадры только в список.
fn clear_leaf(l4: u64, va: u64, freed: &mut Vec<u64>) {
    let Spot::Leaf {
        table: l1,
        index: i1,
        phys,
    } = spot(l4, va)
    else {
        return;
    };
    clear_pte(l1, i1);
    freed.push(phys);
    let i4 = ((va >> 39) & 0x1ff) as usize;
    let i3 = ((va >> 30) & 0x1ff) as usize;
    let i2 = ((va >> 21) & 0x1ff) as usize;
    let (l3, f4) = read_pte(l4, i4);
    if !f4.contains(PageTableFlags::PRESENT) {
        return;
    }
    let (l2, f3) = read_pte(l3, i3);
    if !f3.contains(PageTableFlags::PRESENT) || f3.contains(PageTableFlags::HUGE_PAGE) {
        return;
    }
    if table_any_present(l1) {
        return;
    }
    let (still, f2) = read_pte(l2, i2);
    if !f2.contains(PageTableFlags::PRESENT) || still != l1 || f2.contains(PageTableFlags::HUGE_PAGE)
    {
        return;
    }
    clear_pte(l2, i2);
    freed.push(l1);
    if table_any_present(l2) {
        return;
    }
    let (still3, f3b) = read_pte(l3, i3);
    if !f3b.contains(PageTableFlags::PRESENT)
        || still3 != l2
        || f3b.contains(PageTableFlags::HUGE_PAGE)
    {
        return;
    }
    clear_pte(l3, i3);
    freed.push(l2);
    if table_any_present(l3) {
        return;
    }
    let (still4, f4b) = read_pte(l4, i4);
    if !f4b.contains(PageTableFlags::PRESENT) || still4 != l3 {
        return;
    }
    clear_pte(l4, i4);
    freed.push(l3);
}

/// Правка таблиц без отдачи кадров. Вызывающий держит лок АП, если оно общее.
fn unmap_edit(l4: PhysFrame, start: u64, end: u64, freed: &mut Vec<u64>) -> Result<(), u64> {
    aligned_user_span(start, end)?;
    if start == end {
        return Ok(());
    }
    let l4p = l4.start_address().as_u64();
    if range_has_huge(l4p, start, end) {
        return Err(crate::linux::EINVAL);
    }
    let mut va = start;
    while va < end {
        let step = match spot(l4p, va) {
            Spot::Huge => 0x1000,
            Spot::Missing { skip } => skip.min(end - va).max(0x1000),
            Spot::Leaf { .. } => {
                clear_leaf(l4p, va, freed);
                0x1000
            }
        };
        let next = va.saturating_add(step);
        if next <= va {
            break;
        }
        va = next;
    }
    Ok(())
}

fn commit_free(l4: PhysFrame, freed: Vec<u64>) -> Result<(), u64> {
    if freed.is_empty() {
        return Ok(());
    }
    let cr3 = l4.start_address().as_u64();
    if !crate::smp::shootdown(cr3) {
        serial_println!(
            "[mm] tlb shootdown timed out, leaking {} frames",
            freed.len()
        );
        return Ok(());
    }
    crate::memory::with_frame_allocator(|fa| {
        for phys in freed {
            if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(phys)) {
                fa.deallocate_frame(frame);
            }
        }
    });
    Ok(())
}

fn unmap_with(
    start: u64,
    end: u64,
    edit: impl FnOnce(&mut Vec<u64>) -> Result<PhysFrame, u64>,
) -> Result<(), u64> {
    aligned_user_span(start, end)?;
    if start == end {
        return Ok(());
    }
    let pages = ((end - start) / 4096) as usize;
    let mut freed = Vec::new();
    let need = pages.saturating_add(pages / 512).saturating_add(16);
    if freed.try_reserve(need).is_err() {
        return Err(crate::linux::ENOMEM);
    }
    let l4 = edit(&mut freed)?;
    commit_free(l4, freed)
}

#[cfg(test)]
fn unmap_user(l4: PhysFrame, start: u64, end: u64) -> Result<(), u64> {
    unmap_with(start, end, |freed| {
        unmap_edit(l4, start, end, freed)?;
        Ok(l4)
    })
}

fn unmap_aspace(aspace: &Mutex<AddressSpace>, start: u64, end: u64) -> Result<(), u64> {
    unmap_with(start, end, |freed| {
        let g = aspace.lock();
        unmap_edit(g.l4, start, end, freed)?;
        Ok(g.l4)
    })
}

fn protect_edit(l4: PhysFrame, start: u64, end: u64, flags: PageTableFlags) -> Result<(), u64> {
    aligned_user_span(start, end)?;
    if start == end {
        return Ok(());
    }
    let l4p = l4.start_address().as_u64();
    let mut va = start;
    while va < end {
        match spot(l4p, va) {
            Spot::Huge => return Err(crate::linux::EINVAL),
            Spot::Missing { .. } => return Err(crate::linux::ENOMEM),
            Spot::Leaf { .. } => va = va.saturating_add(0x1000),
        }
    }
    va = start;
    while va < end {
        if let Spot::Leaf { table, index, .. } = spot(l4p, va) {
            set_pte_flags(table, index, flags);
        }
        va = va.saturating_add(0x1000);
    }
    Ok(())
}

#[cfg(test)]
fn leaf_of(l4: PhysFrame, va: u64) -> Option<(u64, PageTableFlags)> {
    match spot(l4.start_address().as_u64(), va) {
        Spot::Leaf { table, index, phys } => {
            let (_, flags) = read_pte(table, index);
            Some((phys, flags))
        }
        _ => None,
    }
}

#[cfg(test)]
fn plant_huge_pde(l4: PhysFrame, va: u64) {
    let l4p = l4.start_address().as_u64();
    let i4 = ((va >> 39) & 0x1ff) as usize;
    let i3 = ((va >> 30) & 0x1ff) as usize;
    let i2 = ((va >> 21) & 0x1ff) as usize;
    let (l3, _) = read_pte(l4p, i4);
    let (l2, _) = read_pte(l3, i3);
    let flags =
        PageTableFlags::PRESENT | PageTableFlags::HUGE_PAGE | PageTableFlags::USER_ACCESSIBLE;
    unsafe {
        (&mut *pt_ptr(l2))[i2].set_addr(PhysAddr::new(0x200000), flags);
    }
}

#[cfg(test)]
fn protect_user(l4: PhysFrame, start: u64, end: u64, prot: u64) -> Result<(), u64> {
    if prot & !7 != 0 {
        return Err(crate::linux::EINVAL);
    }
    aligned_user_span(start, end)?;
    if start == end {
        return Ok(());
    }
    let flags = prot_flags(prot);
    protect_edit(l4, start, end, flags)?;
    if !crate::smp::shootdown(l4.start_address().as_u64()) {
        serial_println!("[mm] tlb shootdown timed out after mprotect");
    }
    Ok(())
}

fn protect_aspace(aspace: &Mutex<AddressSpace>, start: u64, end: u64, prot: u64) -> Result<(), u64> {
    if prot & !7 != 0 {
        return Err(crate::linux::EINVAL);
    }
    aligned_user_span(start, end)?;
    if start == end {
        return Ok(());
    }
    let flags = prot_flags(prot);
    let l4 = {
        let g = aspace.lock();
        protect_edit(g.l4, start, end, flags)?;
        g.l4
    };
    if !crate::smp::shootdown(l4.start_address().as_u64()) {
        serial_println!("[mm] tlb shootdown timed out after mprotect");
    }
    Ok(())
}

fn current_aspace() -> Option<Arc<Mutex<AddressSpace>>> {
    let cur = current_slot();
    if cur < 0 {
        return None;
    }
    with_tasks(|tasks| tasks[cur as usize].as_ref().map(|t| t.aspace.clone()))
}

/// `mprotect`. Дыра в диапазоне — `ENOMEM`, правка не начинается.
/// Огромная страница — `EINVAL`. `PROT_EXEC` принимается, NX не ставится.
pub fn sys_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    if prot & !7 != 0 {
        return crate::linux::EINVAL;
    }
    let (start, end) = match page_span(addr, len) {
        Ok(Some(span)) => span,
        Ok(None) => return 0,
        Err(e) => return e,
    };
    let Some(aspace) = current_aspace() else {
        return crate::linux::EINVAL;
    };
    match protect_aspace(&aspace, start, end, prot) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `munmap`. Дыры внутри диапазона — успех. Кадр уходит после сброса TLB.
pub fn sys_munmap(addr: u64, len: u64) -> u64 {
    let (start, end) = match page_span(addr, len) {
        Ok(Some(span)) => span,
        Ok(None) => return 0,
        Err(e) => return e,
    };
    let Some(aspace) = current_aspace() else {
        return crate::linux::EINVAL;
    };
    match unmap_aspace(&aspace, start, end) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

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

/// Читать байты user-памяти АП `l4` через physmap. Несмапленная страница —
/// ошибка, частичное чтение не возвращается.
fn read_user(l4: PhysFrame, addr: u64, data: &mut [u8]) -> Result<(), MapToError<Size4KiB>> {
    let mapper = unsafe { mapper_for(l4) };
    let mut done = 0usize;
    while done < data.len() {
        let a = addr + done as u64;
        let phys = mapper
            .translate_addr(VirtAddr::new(a))
            .ok_or(MapToError::FrameAllocationFailed)?;
        let page_off = (a & 0xFFF) as usize;
        let n = (4096 - page_off).min(data.len() - done);
        let src = (phys_offset().as_u64() + phys.as_u64()) as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, data.as_mut_ptr().add(done), n) };
        done += n;
    }
    Ok(())
}

/// Скопировать `n` байт внутри одного АП. Буфер на куче: 64 КиБ не кладутся
/// на kernel-стек. Перекрытие источника и назначения определено.
fn copy_user(
    l4: PhysFrame,
    dst: u64,
    src: u64,
    n: usize,
) -> Result<(), MapToError<Size4KiB>> {
    if n == 0 {
        return Ok(());
    }
    let mut buf = alloc::vec![0u8; n];
    read_user(l4, src, &mut buf)?;
    write_user(l4, dst, &buf)
}

/// `DT_RELR`: к слову, уже лежащему по адресу, прибавляется база этого объекта.
/// Не `B + A` из записи RELA — addend живёт в самом слоте.
fn apply_relr(l4: PhysFrame, relr: &[u64], bias: u64) -> Result<(), MapToError<Size4KiB>> {
    let ok = walk_relr(relr, |place| {
        let Some(addr) = place.checked_add(bias) else {
            return false;
        };
        let mut buf = [0u8; 8];
        if read_user(l4, addr, &mut buf).is_err() {
            return false;
        }
        let val = u64::from_le_bytes(buf).wrapping_add(bias);
        write_user(l4, addr, &val.to_le_bytes()).is_ok()
    });
    if ok {
        Ok(())
    } else {
        Err(MapToError::FrameAllocationFailed)
    }
}

/// `R_X86_64_COPY` после обычных релокаций всех объектов. Ноль байт — пустая
/// удача. Дырка в источнике или слоте роняет загрузку.
fn apply_copies(l4: PhysFrame, objs: &[LinkObj]) -> Result<(), MapToError<Size4KiB>> {
    for obj in objs {
        for rel in &obj.parsed.relative {
            if !rel.copy {
                continue;
            }
            if rel.ext.is_some() {
                return Err(MapToError::FrameAllocationFailed);
            }
            let n64 = rel.src_size.min(rel.ref_size);
            if n64 == 0 {
                continue;
            }
            if n64 > COPY_MAX {
                return Err(MapToError::FrameAllocationFailed);
            }
            let n = n64 as usize;
            let sym = rel.sym.ok_or(MapToError::FrameAllocationFailed)?;
            let def_bias = rel.def_bias.ok_or(MapToError::FrameAllocationFailed)?;
            let src = sym
                .checked_add(def_bias)
                .ok_or(MapToError::FrameAllocationFailed)?;
            let dst = rel
                .offset
                .checked_add(obj.bias)
                .ok_or(MapToError::FrameAllocationFailed)?;
            src.checked_add(n64)
                .ok_or(MapToError::FrameAllocationFailed)?;
            dst.checked_add(n64)
                .ok_or(MapToError::FrameAllocationFailed)?;
            copy_user(l4, dst, src, n)?;
        }
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
    pub fds: Arc<Mutex<crate::linux::Fds>>,
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

fn default_fds() -> Arc<Mutex<crate::linux::Fds>> {
    Arc::new(Mutex::new(crate::linux::Fds::new(alloc::vec![
        Some(crate::linux::Fd::console(false)),
        Some(crate::linux::Fd::console(true)),
        Some(crate::linux::Fd::console(true)),
    ])))
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
        name,
        "/",
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
        // IFUNC закроет стартовая страница, когда все обычные релокации
        // всех объектов уже записаны. Ранний вызов здесь был бы вызовом
        // ещё не перемещённого кода. COPY тоже ждёт: в источнике могут
        // лежать указатели, которые эта же петля ещё пишет.
        if rel.defer || rel.ifunc || rel.copy {
            continue;
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

struct IfuncCall {
    slot: u64,
    resolver: u64,
    addend: u64,
}

/// Список резолверов. `None` — адрес 0 или больше `IFUNC_MAX`: образ
/// отвергается. Пустой вектор — IFUNC нет, вход не подменяется.
/// Объекты с конца: зависимости в этом списке идут после программы.
fn ifunc_calls(objs: &[LinkObj]) -> Option<Vec<IfuncCall>> {
    let mut out = Vec::new();
    for obj in objs.iter().rev() {
        for rel in &obj.parsed.relative {
            if !rel.ifunc || rel.missing {
                continue;
            }
            let slot = rel.offset.wrapping_add(obj.bias);
            let (resolver, extra) = if rel.sym.is_none() {
                (rel.addend.wrapping_add(obj.bias), 0)
            } else {
                let base = rel.def_bias.unwrap_or(obj.bias);
                (rel.sym.unwrap_or(0).wrapping_add(base), rel.addend)
            };
            if resolver == 0 {
                serial_println!("[task] IFUNC resolver at 0");
                return None;
            }
            out.push(IfuncCall {
                slot,
                resolver,
                addend: extra,
            });
            if out.len() > IFUNC_MAX {
                serial_println!("[task] too many IFUNC relocations");
                return None;
            }
        }
    }
    Some(out)
}

fn resolved_value(rel: &RelaRel, bias: u64) -> u64 {
    let base = if rel.sym.is_none() {
        bias
    } else {
        rel.def_bias.unwrap_or(bias)
    };
    rel.addend.wrapping_add(rel.sym.unwrap_or(0)).wrapping_add(base)
}

fn collect_lazy(objs: &[LinkObj]) -> Option<LazyBind> {
    let mut any = false;
    let mut slots = Vec::new();
    for obj in objs {
        let mut one = Vec::new();
        for rel in &obj.parsed.relative {
            if !rel.defer {
                continue;
            }
            let Some(arg) = rel.jmprel_off else {
                continue;
            };
            any = true;
            one.push(LazySlot {
                arg,
                got: rel.offset.wrapping_add(obj.bias),
                value: if rel.missing {
                    None
                } else {
                    Some(resolved_value(rel, obj.bias))
                },
            });
        }
        slots.push(one);
    }
    if any { Some(LazyBind { slots }) } else { None }
}

fn resolver_stub() -> &'static [u8] {
    extern "C" {
        static resolve_stub_start: u8;
        static resolve_stub_end: u8;
    }
    unsafe {
        let start = core::ptr::addr_of!(resolve_stub_start);
        let end = core::ptr::addr_of!(resolve_stub_end);
        let n = (end as usize).wrapping_sub(start as usize);
        core::slice::from_raw_parts(start, n)
    }
}

const STUB_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::USER_ACCESSIBLE.bits(),
);

fn install_resolver(
    l4: PhysFrame,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<(), MapToError<Size4KiB>> {
    let bytes = resolver_stub();
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(MapToError::FrameAllocationFailed);
    }
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(RESOLVE_PAGE));
    map_zeroed(l4, page, frame_allocator, STUB_FLAGS)?;
    write_user(l4, RESOLVE_PAGE, bytes)
}

/// GOT[1] — номер объекта, GOT[2] — страница резолвера.
fn arm_plt(
    l4: PhysFrame,
    objs: &[LinkObj],
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<(), MapToError<Size4KiB>> {
    let mut armed = false;
    for (index, obj) in objs.iter().enumerate() {
        if !obj.parsed.relative.iter().any(|rel| rel.defer) {
            continue;
        }
        let Some(pltgot) = obj.parsed.pltgot else {
            return Err(MapToError::FrameAllocationFailed);
        };
        let base = pltgot.wrapping_add(obj.bias);
        write_user(l4, base.wrapping_add(8), &(index as u64).to_le_bytes())?;
        write_user(l4, base.wrapping_add(16), &RESOLVE_PAGE.to_le_bytes())?;
        armed = true;
    }
    if armed {
        install_resolver(l4, frame_allocator)?;
    }
    Ok(())
}

/// Записать адрес в GOT и вернуть его. Сильного символа нет — `None`.
fn fixup_slot(l4: PhysFrame, lazy: &LazyBind, index: u64, arg: u64) -> Option<u64> {
    let obj = lazy.slots.get(index as usize)?;
    let slot = obj.iter().find(|slot| slot.arg == arg)?;
    let value = slot.value?;
    write_user(l4, slot.got, &value.to_le_bytes()).ok()?;
    Some(value)
}

/// Вызов из резолвера. Неизвестный слот и промах сильного символа убивают задачу.
pub fn sys_dl_fixup(index: u64, arg: u64) -> u64 {
    let found = with_current_task(|t| {
        let space = t.aspace.lock();
        let lazy = space.lazy.clone();
        (space.l4, lazy)
    });
    let Some((l4, lazy)) = found else {
        serial_println!("[task] lazy PLT without a task");
        sys_exit(128 + 9);
    };
    let Some(lazy) = lazy else {
        serial_println!("[task] lazy PLT without a link map");
        sys_exit(128 + 9);
    };
    match fixup_slot(l4, &lazy, index, arg) {
        Some(value) => value,
        None => {
            serial_println!("[task] lazy PLT miss obj {} off {}", index, arg);
            sys_exit(128 + 9);
        }
    }
}

core::arch::global_asm!(
    r#"
    .text
    .global resolve_stub_start
    .global resolve_stub_end
resolve_stub_start:
    # Стек от PLT: [GOT1][reloc_off][адрес возврата вызывающего].
    # Аргументы функции и xmm0-7 сохраняем: syscall и Rust их затирают.
    sub rsp, 128
    movdqu xmmword ptr [rsp + 0], xmm0
    movdqu xmmword ptr [rsp + 16], xmm1
    movdqu xmmword ptr [rsp + 32], xmm2
    movdqu xmmword ptr [rsp + 48], xmm3
    movdqu xmmword ptr [rsp + 64], xmm4
    movdqu xmmword ptr [rsp + 80], xmm5
    movdqu xmmword ptr [rsp + 96], xmm6
    movdqu xmmword ptr [rsp + 112], xmm7
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov rdi, qword ptr [rsp + 200]
    mov rsi, qword ptr [rsp + 208]
    mov eax, {nr}
    syscall
    mov qword ptr [rsp + 200], rax
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    movdqu xmm7, xmmword ptr [rsp + 112]
    movdqu xmm6, xmmword ptr [rsp + 96]
    movdqu xmm5, xmmword ptr [rsp + 80]
    movdqu xmm4, xmmword ptr [rsp + 64]
    movdqu xmm3, xmmword ptr [rsp + 48]
    movdqu xmm2, xmmword ptr [rsp + 32]
    movdqu xmm1, xmmword ptr [rsp + 16]
    movdqu xmm0, xmmword ptr [rsp + 0]
    add rsp, 128
    pop r11
    add rsp, 8
    jmp r11
resolve_stub_end:
    "#,
    nr = const DL_FIXUP_NR,
);

fn ifunc_stub() -> &'static [u8] {
    extern "C" {
        static ifunc_stub_start: u8;
        static ifunc_stub_end: u8;
    }
    unsafe {
        let start = core::ptr::addr_of!(ifunc_stub_start);
        let end = core::ptr::addr_of!(ifunc_stub_end);
        let n = (end as usize).wrapping_sub(start as usize);
        core::slice::from_raw_parts(start, n)
    }
}

/// Поставить стартовую страницу и таблицу. `entry` — настоящий вход,
/// куда страница прыгнет после резолверов. `Ok(false)` — вызовов нет.
fn install_ifunc(
    l4: PhysFrame,
    objs: &[LinkObj],
    entry: u64,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<bool, MapToError<Size4KiB>> {
    let Some(calls) = ifunc_calls(objs) else {
        return Err(MapToError::FrameAllocationFailed);
    };
    if calls.is_empty() {
        return Ok(false);
    }
    let bytes = ifunc_stub();
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(MapToError::FrameAllocationFailed);
    }
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(IFUNC_PAGE));
    map_zeroed(l4, page, frame_allocator, STUB_FLAGS)?;
    write_user(l4, IFUNC_PAGE, bytes)?;

    let nbytes = 16 + calls.len() * 24;
    let pages = (nbytes + 4095) / 4096;
    for i in 0..pages {
        let addr = IFUNC_TABLE + (i as u64) * 4096;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
        map_zeroed(l4, page, frame_allocator, USER_FLAGS)?;
    }
    let mut raw = Vec::with_capacity(nbytes);
    raw.extend_from_slice(&(calls.len() as u64).to_le_bytes());
    raw.extend_from_slice(&entry.to_le_bytes());
    for call in &calls {
        raw.extend_from_slice(&call.slot.to_le_bytes());
        raw.extend_from_slice(&call.resolver.to_le_bytes());
        raw.extend_from_slice(&call.addend.to_le_bytes());
    }
    write_user(l4, IFUNC_TABLE, &raw)?;
    Ok(true)
}

core::arch::global_asm!(
    r#"
    .text
    .global ifunc_stub_start
    .global ifunc_stub_end
ifunc_stub_start:
    # Вход процесса: rsp кратен 16, на стеке argc. Вызов из теста тоже
    # годится: ниже выравниваем так, чтобы call вошёл в резолвер с
    # rsp ≡ 8 (mod 16). Резолвер без аргументов, возврат в rax.
    # Четыре push после выравнивания держат rsp кратным 16 перед call.
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    push r13
    push r14
    mov r12, {table}
    mov r13, qword ptr [r12]
    lea r12, [r12 + 16]
    test r13, r13
    jz .Lifunc_done
.Lifunc_loop:
    mov rax, qword ptr [r12 + 8]
    call rax
    add rax, qword ptr [r12 + 16]
    mov rbx, qword ptr [r12]
    mov qword ptr [rbx], rax
    add r12, 24
    dec r13
    jnz .Lifunc_loop
.Lifunc_done:
    mov rax, {table}
    mov rax, qword ptr [rax + 8]
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    jmp rax
ifunc_stub_end:
    "#,
    table = const IFUNC_TABLE,
);

/// Загрузить ELF в АП l4 и построить начальный стек (argc/argv/envp/auxv).
/// Если есть `PT_INTERP`, вход — в интерпретатор, а `AT_ENTRY` остаётся
/// входом основной программы. `lazy` — слоты, которые первый вызов дописывает.
pub fn load_elf_image(
    l4: PhysFrame,
    elf_bytes: &[u8],
    argv: &[String],
    envp: &[String],
    stack_top: u64,
    frame_allocator: &mut BootInfoFrameAllocator,
    cred: Cred,
    origin: &str,
    cwd: &str,
) -> Result<LoadedImage, MapToError<Size4KiB>> {
    let linked = match link_program(elf_bytes, origin, cwd, envp) {
        Some(linked) => linked,
        None => return Err(MapToError::FrameAllocationFailed),
    };
    for obj in &linked.objs {
        map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, frame_allocator)?;
        // Сначала RELR, потом RELA: как glibc. Оба — обычные релокации,
        // до COPY и до резолверов IFUNC.
        apply_relr(l4, &obj.parsed.relr, obj.bias)?;
        apply_relative(l4, &obj.parsed.relative, obj.bias)?;
    }
    // Слот программы заполняется из уже перемещённого источника.
    // Возвраты IFUNC в эти байты не входят: резолверы бегут позже.
    apply_copies(l4, &linked.objs)?;
    arm_plt(l4, &linked.objs, frame_allocator)?;
    let lazy = collect_lazy(&linked.objs);
    let main = &linked.objs[0];
    let phdr_vaddr = main.parsed.phdr_vaddr.wrapping_add(main.bias);
    let phnum = main.parsed.phnum;
    let at_entry = main.parsed.entry.wrapping_add(main.bias);
    let (mut entry, at_base) = if let Some(index) = linked.interp_index {
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
    // Обычные релокации уже записаны. Резолвер IFUNC видит их, а не
    // нули, и отрабатывает до интерпретатора и до ленивого PLT.
    if install_ifunc(l4, &linked.objs, entry, frame_allocator)? {
        entry = IFUNC_PAGE;
    }

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

    Ok(LoadedImage { entry, user_rsp: sp, lazy })
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
    let LoadedImage { entry, user_rsp, lazy } = img;
    if let Some(lazy) = lazy {
        aspace.lock().lazy = Some(Arc::new(lazy));
    }
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
        core::ptr::write(f.add(GPRS + 0), entry); // rip
        core::ptr::write(f.add(GPRS + 1), u64::from(user_code.0)); // cs (0x30|3)
        core::ptr::write(f.add(GPRS + 2), 0x202); // rflags: IF
        core::ptr::write(f.add(GPRS + 3), user_rsp); // user rsp
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
                    let (brk_base, brk, mmap_next, thread_stacks, lazy) = {
                        let a = parent_as.lock();
                        (a.brk_base, a.brk, a.mmap_next, a.thread_stacks, a.lazy.clone())
                    };
                    Ok(Arc::new(Mutex::new(AddressSpace {
                        l4,
                        brk_base,
                        brk,
                        mmap_next,
                        thread_stacks,
                        lazy,
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
            let cloned = parent_fds.lock().clone_for_fork();
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
    let cwd = current_cwd();
    let canon = match crate::fs::resolve(&cwd, &path) {
        Some(c) => c,
        None => return E2BIG,
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
        let img = load_elf_image(l4, &elf, &argv_full, &envp, USER_STACK_TOP, fa, cred, &canon, &cwd)?;
        Ok((aspace, img))
    });
    let (aspace, img) = match built {
        Ok(v) => v,
        Err(_) => return ENOEXEC,
    };
    let LoadedImage { entry, user_rsp, lazy } = img;
    if let Some(lazy) = lazy {
        aspace.lock().lazy = Some(Arc::new(lazy));
    }

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
        *f.add(FRAME::RIP) = entry;
        *f.add(FRAME::RSP) = user_rsp;
    }
    drop(old);
    crate::linux::close_on_exec();
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
    // Рост маппит недостающие страницы. Сжатие снимает целые страницы ниже нового brk.
    if addr > old_brk {
        let grow_start = (old_brk + 0xFFF) & !0xFFF;
        let grow_end = addr & !0xFFF;
        if grow_end >= grow_start {
            let r = {
                let _guard = aspace.lock();
                crate::memory::with_frame_allocator(|fa| {
                    map_range_zeroed(
                        l4,
                        VirtAddr::new(grow_start),
                        VirtAddr::new(grow_end),
                        fa,
                        USER_FLAGS,
                    )
                })
            };
            if r.is_err() {
                let mut a = aspace.lock();
                a.brk = old_brk;
                return old_brk;
            }
        }
        return addr;
    }
    if let Some((start, end)) = brk_free_span(old_brk, addr) {
        if unmap_aspace(&aspace, start, end).is_err() {
            aspace.lock().brk = old_brk;
            return old_brk;
        }
    }
    aspace.lock().brk = addr;
    addr
}

/// sys_mmap: анонимные приватные маппинги из бамп-региона АП.
/// `prot` — те же биты, что у `mprotect`. Чужой бит отвергается до выдачи адреса.
pub fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, _fd: u64, _off: u64) -> u64 {
    use crate::linux::{EINVAL, ENOMEM, ENODEV};
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
    if prot & !7 != 0 {
        return EINVAL;
    }
    let pte = prot_flags(prot);
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
    let fixed = addr != 0 && (flags & MAP_FIXED) != 0;
    if fixed {
        let end = base + pages * 0x1000;
        if let Err(e) = unmap_aspace(&aspace, base, end) {
            return e;
        }
    }
    let r = {
        let guard = aspace.lock();
        let l4 = guard.l4;
        crate::memory::with_frame_allocator(|fa| {
            map_range_zeroed(
                l4,
                VirtAddr::new(base),
                VirtAddr::new(base + pages * 0x1000 - 1),
                fa,
                pte,
            )
        })
    };
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
    let r = {
        let _guard = aspace.lock();
        crate::memory::with_frame_allocator(|fa| {
            map_range_zeroed(
                l4,
                VirtAddr::new(base),
                VirtAddr::new(top - 1),
                fa,
                USER_FLAGS,
            )
        })
    };
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

/// Вызвать стартовую страницу IFUNC на АП `l4` и вернуться.
/// Процесс входит в неё через iret в ring 3. Тест бежит не как задача,
/// поэтому та же страница вызывается из ring 0: SMEP и SMAP на это время
/// снимаются и возвращаются как были.
#[cfg(test)]
fn call_ifunc_stub(l4: PhysFrame) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    let phys = l4.start_address().as_u64();
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        let old = Cr4::read();
        let mut cr4 = old;
        cr4.remove(
            Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION
                | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION,
        );
        Cr4::write(cr4);
        core::arch::asm!(
            "mov r15, cr3",
            "mov cr3, {l4}",
            "call {stub}",
            "mov cr3, r15",
            l4 = in(reg) phys,
            stub = in(reg) IFUNC_PAGE,
            out("r15") _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
        Cr4::write(old);
    });
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
        assert!(!strict_permits(DL_FIXUP_NR));
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
        craft_elf(
            needed, syms, rels, jmprel, dt_rel, interp, false, false, None, false,
        )
    }

    /// `gnu_chain`: только `DT_GNU_HASH`, одна цепочка на все символы.
    /// Первый символ не заканчивает цепочку, последний — заканчивает.
    /// `gnu_empty`: bucket пустой, граница равна `symoffset` (1).
    fn craft_elf(
        needed: &[&str],
        syms: &[(&str, u16, u64, u8)],
        rels: &[(u64, u64, u64, u64)],
        jmprel: bool,
        dt_rel: bool,
        interp: Option<&str>,
        gnu_chain: bool,
        gnu_empty: bool,
        pltgot: Option<u64>,
        bind_now: bool,
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
        let gnu = gnu_chain || gnu_empty;
        if !syms.is_empty() || !rels.is_empty() {
            let tag = if gnu { 0x6fff_fef5 } else { 4 };
            tags.push((tag, 0x3C0));
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
        if let Some(got) = pltgot {
            tags.push((3, got));
        }
        if bind_now {
            tags.push((0x6fff_fffb, 1));
        }
        tags.push((0, 0));
        let mut dynamic = Vec::new();
        for (tag, val) in tags {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&val.to_le_bytes());
        }
        assert!(0x300 + dynamic.len() <= 0x3C0, "dynamic overlaps hash");

        let mut hash = Vec::new();
        if gnu {
            // nbuckets, symoffset, bloom_size, bloom_shift, один bloom u64, bucket.
            hash.extend_from_slice(&1u32.to_le_bytes());
            hash.extend_from_slice(&1u32.to_le_bytes());
            hash.extend_from_slice(&1u32.to_le_bytes());
            hash.extend_from_slice(&0u32.to_le_bytes());
            hash.extend_from_slice(&0u64.to_le_bytes());
            if gnu_empty || syms.is_empty() {
                hash.extend_from_slice(&0u32.to_le_bytes());
            } else {
                hash.extend_from_slice(&1u32.to_le_bytes());
                for i in 0..syms.len() {
                    let end: u32 = if i + 1 == syms.len() { 1 } else { 0 };
                    hash.extend_from_slice(&end.to_le_bytes());
                }
            }
        } else {
            let nchain = 1 + syms.len();
            hash.extend_from_slice(&1u32.to_le_bytes());
            hash.extend_from_slice(&(nchain as u32).to_le_bytes());
            hash.extend_from_slice(&1u32.to_le_bytes());
            for _ in 0..nchain {
                hash.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        assert!(hash.len() <= 0x80, "hash overlaps rela");

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
        // Без DT_PLTGOT JUMP_SLOT пишется при загрузке.
        assert_eq!(app.jmprel_off, Some(0));
        assert!(!app.defer);
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
        // Адрес 1 и размер 8: это не таблица из записей по 16 байт.
        let elf = craft_dyn(&[], &[], &[], false, true, None);
        assert!(parse_elf64(&elf).is_none());
        serial_println!("[ok]");
    }

    /// `DT_REL`: addend читается из слота, не из записи. `B + A` как у RELA.
    /// `DT_JMPREL` с `DT_PLTREL == DT_REL` — записи по 16 байт.
    #[test_case]
    fn dt_rel_reads_the_addend_from_the_slot() {
        serial_print!("test dt_rel_reads_the_addend_from_the_slot... ");
        let mut elf = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut elf, 17, 0x440);
        add_dyn(&mut elf, 18, 16);
        let mut ent = [0u8; 16];
        ent[0..8].copy_from_slice(&0x800u64.to_le_bytes());
        ent[8..16].copy_from_slice(&8u64.to_le_bytes());
        plant(&mut elf, 0x440, &ent);
        put_u64(&mut elf, 0x800, 0x11);
        let linked = link_with(elf.as_slice(), |_| None).expect("rel");
        assert_eq!(linked.objs[0].parsed.relative.len(), 1);
        assert_eq!(linked.objs[0].parsed.relative[0].addend, 0x11);
        assert!(linked.objs[0].parsed.relative[0].sym.is_none());
        let bias = linked.objs[0].bias;
        let got = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            let obj = &linked.objs[0];
            map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, fa).expect("map");
            apply_relative(l4, &obj.parsed.relative, obj.bias).expect("apply");
            let v = read_u64(l4, bias + 0x800);
            free_user_space(l4, fa);
            v
        });
        assert_eq!(got, 0x11 + bias);

        let mut bad_step = elf.clone();
        add_dyn(&mut bad_step, 19, 24);
        assert!(parse_elf64(&bad_step).is_none());
        let mut only_addr = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut only_addr, 17, 0x440);
        assert!(parse_elf64(&only_addr).is_none());

        let mut bss = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut bss, 17, 0x440);
        add_dyn(&mut bss, 18, 16);
        let mut ent = [0u8; 16];
        ent[0..8].copy_from_slice(&0x1_0000u64.to_le_bytes());
        ent[8..16].copy_from_slice(&8u64.to_le_bytes());
        plant(&mut bss, 0x440, &ent);
        let parsed = parse_elf64(&bss).expect("bss");
        assert_eq!(parsed.relative[0].addend, 0);

        let mut jmp = craft_dyn(&[], &[("foo", 1, 0x100, 0x12)], &[], false, false, None);
        add_dyn(&mut jmp, 23, 0x440);
        add_dyn(&mut jmp, 2, 16);
        add_dyn(&mut jmp, 20, 17);
        let mut ent = [0u8; 16];
        ent[0..8].copy_from_slice(&0x480u64.to_le_bytes());
        ent[8..16].copy_from_slice(&((1u64 << 32) | 7).to_le_bytes());
        plant(&mut jmp, 0x440, &ent);
        let parsed = parse_elf64(&jmp).expect("jmprel");
        let slot = &parsed.relative[0];
        assert_eq!(slot.sym, Some(0x100));
        assert_eq!(slot.addend, 0);
        assert_eq!(slot.jmprel_off, Some(0));
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
                    jmprel_off: None,
                    defer: false,
                    missing: false,
                    ifunc: false,
                    copy: false,
                    ref_size: 0,
                    src_size: 0,
                    preempt: None,
                },
                RelaRel {
                    offset: 8,
                    addend: 5,
                    sym: None,
                    def_bias: None,
                    ext: None,
                    jmprel_off: None,
                    defer: false,
                    missing: false,
                    ifunc: false,
                    copy: false,
                    ref_size: 0,
                    src_size: 0,
                    preempt: None,
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

    /// Цепочка из двух символов: первое слово без младшего бита, второе с ним.
    /// Граница — 3, иначе `sub` не виден.
    #[test_case]
    fn gnu_hash_chain_binds_the_second_symbol() {
        serial_print!("test gnu_hash_chain_binds_the_second_symbol... ");
        let lib = craft_elf(
            &[],
            &[("add", 1, 0x111, 0x12), ("sub", 1, 0x222, 0x12)],
            &[],
            false,
            false,
            None,
            true,
            false,
            None,
            false,
        );
        let parsed = parse_elf64(&lib).expect("lib");
        assert_eq!(parsed.dynsym.nchain, 3);
        let main = craft_dyn(
            &["libgnu.so"],
            &[("sub", 0, 0, 0x10)],
            &[(0x480, 1, 1, 0)],
            false,
            false,
            None,
        );
        let linked = link_with(main.as_slice(), |path| match path {
            "/lib/libgnu.so" => Some(lib.clone()),
            _ => None,
        })
        .expect("link");
        assert_eq!(linked.objs.len(), 2);
        assert_eq!(linked.objs[1].bias, 0x0200_0000);
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0x222));
        assert_eq!(rel.def_bias, Some(0x0200_0000));
        assert!(rel.ext.is_none());
        serial_println!("[ok]");
    }

    /// Пустой bucket не дочитывает dynsym выше `symoffset`. Символ есть в
    /// файле, связи нет.
    #[test_case]
    fn gnu_hash_empty_bucket_hides_the_symbol() {
        serial_print!("test gnu_hash_empty_bucket_hides_the_symbol... ");
        let lib = craft_elf(
            &[],
            &[("add", 1, 0x111, 0x12)],
            &[],
            false,
            false,
            None,
            false,
            true,
            None,
            false,
        );
        let parsed = parse_elf64(&lib).expect("lib");
        assert_eq!(parsed.dynsym.nchain, 1);
        let main = craft_dyn(
            &["libempty.so"],
            &[("add", 0, 0, 0x10)],
            &[(0x480, 1, 1, 0)],
            false,
            false,
            None,
        );
        assert!(link_with(main.as_slice(), |path| match path {
            "/lib/libempty.so" => Some(lib.clone()),
            _ => None,
        })
        .is_none());
        serial_println!("[ok]");
    }

    /// `filesz` PT_LOAD всё ещё покрывает слово цепочки, буфер — нет.
    #[test_case]
    fn gnu_hash_truncated_chain_is_refused() {
        serial_print!("test gnu_hash_truncated_chain_is_refused... ");
        let mut elf = craft_elf(
            &[],
            &[("add", 1, 0x111, 0x12)],
            &[],
            false,
            false,
            None,
            true,
            false,
            None,
            false,
        );
        let filesz = u64::from_le_bytes(elf[0x40 + 32..0x40 + 40].try_into().unwrap());
        elf.truncate(0x3C0 + 16 + 8 + 4);
        assert!(filesz > elf.len() as u64);
        assert!(parse_elf64(&elf).is_none());
        serial_println!("[ok]");
    }

    struct CraftSym {
        name: &'static str,
        shndx: u16,
        value: u64,
        info: u8,
        /// Имя версии и скрытность. None — `VER_NDX_GLOBAL`.
        ver: Option<(&'static str, bool)>,
    }

    /// Как `craft_dyn`, плюс `DT_VERSYM` / `DT_VERDEF` / `DT_VERNEED`.
    /// `need` — (файл, имя версии, слабая) для неопределённых символов с версией.
    /// Версии лежат с 0x800, `DT_VERSYM` — с 0x900.
    fn craft_ver(
        needed: &[&str],
        soname: Option<&str>,
        syms: &[CraftSym],
        rels: &[(u64, u64, u64, u64)],
        need: Option<(&str, &str, bool)>,
    ) -> Vec<u8> {
        let mut ndx_of = Vec::new();
        let mut def_vers: Vec<(&str, u16, bool)> = Vec::new();
        let mut next: u16 = 2;
        let mut need_ndx: Option<u16> = None;
        for s in syms {
            if s.shndx != 0 {
                if let Some((vn, hidden)) = s.ver {
                    def_vers.push((vn, next, hidden));
                    ndx_of.push(next);
                    next += 1;
                } else {
                    ndx_of.push(1);
                }
            } else if let Some((vn, _)) = s.ver {
                let (_, vname, _) = need.expect("versioned undef needs VERNEED");
                assert_eq!(vn, vname);
                let ndx = *need_ndx.get_or_insert(next);
                ndx_of.push(ndx);
            } else {
                ndx_of.push(1);
            }
        }
        if need.is_some() {
            assert!(need_ndx.is_some(), "VERNEED without a versioned undef");
        }

        let mut strings = alloc::vec![0u8];
        let mut needed_at = Vec::new();
        for name in needed {
            needed_at.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let soname_at = soname.map(|s| {
            let at = strings.len() as u64;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        });
        let mut sym_at = Vec::new();
        for s in syms {
            sym_at.push(strings.len() as u32);
            strings.extend_from_slice(s.name.as_bytes());
            strings.push(0);
        }
        let mut def_name_at = Vec::new();
        for (vn, _, _) in &def_vers {
            def_name_at.push(strings.len() as u32);
            strings.extend_from_slice(vn.as_bytes());
            strings.push(0);
        }
        let need_at = need.map(|(file, vname, _)| {
            let file_at = strings.len() as u32;
            strings.extend_from_slice(file.as_bytes());
            strings.push(0);
            let name_at = strings.len() as u32;
            strings.extend_from_slice(vname.as_bytes());
            strings.push(0);
            (file_at, name_at)
        });
        assert!(strings.len() <= 0x100, "dynstr overlaps symtab");

        let mut symtab = alloc::vec![0u8; 24];
        for i in 0..syms.len() {
            let s = &syms[i];
            symtab.extend_from_slice(&sym_at[i].to_le_bytes());
            symtab.push(s.info);
            symtab.push(0);
            symtab.extend_from_slice(&s.shndx.to_le_bytes());
            symtab.extend_from_slice(&s.value.to_le_bytes());
            symtab.extend_from_slice(&0u64.to_le_bytes());
        }
        assert!(0x200 + symtab.len() <= 0x300, "dynsym overlaps dynamic");

        let mut verdef = Vec::new();
        for (i, (_, ndx, _)) in def_vers.iter().enumerate() {
            let last = i + 1 == def_vers.len();
            verdef.extend_from_slice(&1u16.to_le_bytes());
            verdef.extend_from_slice(&0u16.to_le_bytes());
            verdef.extend_from_slice(&ndx.to_le_bytes());
            verdef.extend_from_slice(&1u16.to_le_bytes());
            verdef.extend_from_slice(&0u32.to_le_bytes());
            verdef.extend_from_slice(&20u32.to_le_bytes());
            let step: u32 = if last { 0 } else { 28 };
            verdef.extend_from_slice(&step.to_le_bytes());
            verdef.extend_from_slice(&def_name_at[i].to_le_bytes());
            verdef.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut verneed = Vec::new();
        if let Some((file_at, name_at)) = need_at {
            let weak = need.unwrap().2;
            let ndx = need_ndx.unwrap();
            verneed.extend_from_slice(&1u16.to_le_bytes());
            verneed.extend_from_slice(&1u16.to_le_bytes());
            verneed.extend_from_slice(&file_at.to_le_bytes());
            verneed.extend_from_slice(&16u32.to_le_bytes());
            verneed.extend_from_slice(&0u32.to_le_bytes());
            verneed.extend_from_slice(&0u32.to_le_bytes());
            let flags: u16 = if weak { 2 } else { 0 };
            verneed.extend_from_slice(&flags.to_le_bytes());
            verneed.extend_from_slice(&ndx.to_le_bytes());
            verneed.extend_from_slice(&name_at.to_le_bytes());
            verneed.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut versym = Vec::new();
        if !verdef.is_empty() || !verneed.is_empty() {
            versym.extend_from_slice(&0u16.to_le_bytes());
            for (i, s) in syms.iter().enumerate() {
                let mut ndx = ndx_of[i];
                if s.shndx != 0 {
                    if let Some((_, hidden)) = s.ver {
                        if hidden {
                            ndx |= 0x8000;
                        }
                    }
                }
                versym.extend_from_slice(&ndx.to_le_bytes());
            }
        }

        let mut tags: Vec<(u64, u64)> = Vec::new();
        for at in &needed_at {
            tags.push((1, *at));
        }
        if let Some(at) = soname_at {
            tags.push((14, at));
        }
        tags.push((5, 0x100));
        tags.push((6, 0x200));
        tags.push((11, 24));
        if !syms.is_empty() || !rels.is_empty() {
            tags.push((4, 0x3C0));
        }
        if !rels.is_empty() {
            tags.push((7, 0x440));
            tags.push((8, (rels.len() * 24) as u64));
            tags.push((9, 24));
        }
        if !versym.is_empty() {
            tags.push((0x6fff_fff0, 0x900));
        }
        if !verdef.is_empty() {
            tags.push((0x6fff_fffc, 0x800));
            tags.push((0x6fff_fffd, def_vers.len() as u64));
        }
        if !verneed.is_empty() {
            tags.push((0x6fff_fffe, 0x880));
            tags.push((0x6fff_ffff, 1));
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
        assert!(hash.len() <= 0x80, "hash overlaps rela");

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
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());
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
        let place = |elf: &mut Vec<u8>, at: usize, data: &[u8]| {
            if data.is_empty() {
                return;
            }
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
        place(&mut elf, 0x800, &verdef);
        place(&mut elf, 0x880, &verneed);
        place(&mut elf, 0x900, &versym);
        let len = elf.len() as u64;
        elf[0x40 + 32..0x40 + 40].copy_from_slice(&len.to_le_bytes());
        elf[0x40 + 40..0x40 + 48].copy_from_slice(&len.to_le_bytes());
        elf
    }

    #[test_case]
    fn symbol_version_same_object_skips_the_hidden_one() {
        serial_print!("test symbol_version_same_object_skips_the_hidden_one... ");
        let elf = craft_ver(
            &[],
            None,
            &[
                CraftSym { name: "foo", shndx: 1, value: 0x111, info: 0x12, ver: Some(("VER_1", true)) },
                CraftSym { name: "foo", shndx: 1, value: 0x222, info: 0x12, ver: Some(("VER_2", false)) },
                CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: None },
            ],
            &[(0x480, 1, 3, 0)],
            None,
        );
        let linked = link_with(elf.as_slice(), |_| None).expect("link");
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0x222));
        assert!(rel.def_bias.is_none());
        assert!(rel.ext.is_none());
        serial_println!("[ok]");
    }

    #[test_case]
    fn symbol_version_needed_binds_the_named_one() {
        serial_print!("test symbol_version_needed_binds_the_named_one... ");
        let lib = craft_ver(
            &[],
            Some("libver.so"),
            &[
                CraftSym { name: "foo", shndx: 1, value: 0x111, info: 0x12, ver: Some(("VER_1", true)) },
                CraftSym { name: "foo", shndx: 1, value: 0x222, info: 0x12, ver: Some(("VER_2", false)) },
            ],
            &[],
            None,
        );
        let bare = craft_ver(
            &[],
            None,
            &[CraftSym { name: "foo", shndx: 1, value: 0x55, info: 0x12, ver: Some(("VER_1", false)) }],
            &[],
            None,
        );
        let named = craft_ver(
            &["libver.so"],
            None,
            &[CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: Some(("VER_1", false)) }],
            &[(0x480, 1, 1, 0)],
            Some(("libver.so", "VER_1", false)),
        );
        let linked = link_with(named.as_slice(), |path| match path {
            "/lib/libver.so" => Some(lib.clone()),
            _ => None,
        })
        .expect("named");
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0x111));
        assert_eq!(rel.def_bias, Some(0x0200_0000));
        let unvers = craft_dyn(
            &["libver.so"],
            &[("foo", 0, 0, 0x10)],
            &[(0x480, 1, 1, 0)],
            false,
            false,
            None,
        );
        let linked = link_with(unvers.as_slice(), |path| match path {
            "/lib/libver.so" => Some(lib.clone()),
            _ => None,
        })
        .expect("default");
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0x222));
        assert_eq!(rel.def_bias, Some(0x0200_0000));
        let by_file = craft_ver(
            &["libbare.so"],
            None,
            &[CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: Some(("VER_1", false)) }],
            &[(0x480, 1, 1, 0)],
            Some(("libbare.so", "VER_1", false)),
        );
        let linked = link_with(by_file.as_slice(), |path| match path {
            "/lib/libbare.so" => Some(bare.clone()),
            _ => None,
        })
        .expect("basename");
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0x55));
        assert_eq!(rel.def_bias, Some(0x0200_0000));
        serial_println!("[ok]");
    }

    #[test_case]
    fn symbol_version_wrong_file_or_plain_def_refuses() {
        serial_print!("test symbol_version_wrong_file_or_plain_def_refuses... ");
        let lib = craft_ver(
            &[],
            Some("libver.so"),
            &[CraftSym { name: "foo", shndx: 1, value: 0x111, info: 0x12, ver: Some(("VER_1", false)) }],
            &[],
            None,
        );
        let wrong = craft_ver(
            &["libver.so"],
            None,
            &[CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: Some(("VER_1", false)) }],
            &[(0x480, 1, 1, 0)],
            Some(("libother.so", "VER_1", false)),
        );
        assert!(link_with(wrong.as_slice(), |path| match path {
            "/lib/libver.so" => Some(lib.clone()),
            _ => None,
        })
        .is_none());
        let plain = craft_dyn(&[], &[("foo", 1, 0x55, 0x12)], &[], false, false, None);
        let main = craft_ver(
            &["libplain.so"],
            None,
            &[CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: Some(("VER_1", false)) }],
            &[(0x480, 1, 1, 0)],
            Some(("libplain.so", "VER_1", false)),
        );
        assert!(link_with(main.as_slice(), |path| match path {
            "/lib/libplain.so" => Some(plain.clone()),
            _ => None,
        })
        .is_none());
        serial_println!("[ok]");
    }

    #[test_case]
    fn symbol_version_weak_requirement_is_zero() {
        serial_print!("test symbol_version_weak_requirement_is_zero... ");
        let weak = craft_ver(
            &[],
            None,
            &[CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: Some(("VER_1", false)) }],
            &[(0x480, 1, 1, 0)],
            Some(("libmissing.so", "VER_1", true)),
        );
        let linked = link_with(weak.as_slice(), |_| None).expect("weak ver");
        let rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(rel.sym, Some(0));
        assert_eq!(rel.def_bias, Some(0));
        let strong = craft_ver(
            &[],
            None,
            &[CraftSym { name: "foo", shndx: 0, value: 0, info: 0x10, ver: Some(("VER_1", false)) }],
            &[(0x480, 1, 1, 0)],
            Some(("libmissing.so", "VER_1", false)),
        );
        assert!(link_with(strong.as_slice(), |_| None).is_none());
        serial_println!("[ok]");
    }

    #[test_case]
    fn symbol_version_bad_table_is_refused() {
        serial_print!("test symbol_version_bad_table_is_refused... ");
        let elf = craft_ver(
            &[],
            None,
            &[CraftSym { name: "foo", shndx: 1, value: 0x111, info: 0x12, ver: Some(("VER_1", false)) }],
            &[],
            None,
        );
        assert!(parse_elf64(&elf).is_some());
        let filesz = u64::from_le_bytes(elf[0x40 + 32..0x40 + 40].try_into().unwrap());
        let mut cut = elf.clone();
        cut.truncate(0x902);
        assert!(filesz > cut.len() as u64);
        assert!(parse_elf64(&cut).is_none());
        let mut bad = elf;
        bad[0x902] = 5;
        bad[0x903] = 0;
        assert!(parse_elf64(&bad).is_none());
        serial_println!("[ok]");
    }

    /// `DT_NEEDED` и, если заданы, `DT_RPATH` / `DT_RUNPATH`. Пустая строка —
    /// тег есть, каталогов нет.
    fn craft_search(
        needed: &[&str],
        rpath: Option<&str>,
        runpath: Option<&str>,
        interp: Option<&str>,
    ) -> Vec<u8> {
        let mut strings = alloc::vec![0u8];
        let mut needed_at = Vec::new();
        for name in needed {
            needed_at.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let put_path = |strings: &mut Vec<u8>, text: &str| -> u64 {
            if text.is_empty() {
                return 0;
            }
            let at = strings.len() as u64;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            at
        };
        let rpath_at = rpath.map(|text| put_path(&mut strings, text));
        let runpath_at = runpath.map(|text| put_path(&mut strings, text));
        assert!(strings.len() <= 0x100, "dynstr overlaps symtab");

        let mut tags: Vec<(u64, u64)> = Vec::new();
        for at in &needed_at {
            tags.push((1, *at));
        }
        tags.push((5, 0x100));
        tags.push((6, 0x200));
        tags.push((11, 24));
        if let Some(at) = rpath_at {
            tags.push((15, at));
        }
        if let Some(at) = runpath_at {
            tags.push((29, at));
        }
        tags.push((0, 0));
        let mut dynamic = Vec::new();
        for (tag, val) in tags {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&val.to_le_bytes());
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
            let mut raw = path.as_bytes().to_vec();
            raw.push(0);
            assert!(0xF0 + raw.len() <= 0x100);
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
        place(&mut elf, 0x200, &[0u8; 24]);
        place(&mut elf, 0x300, &dynamic);
        let len = elf.len() as u64;
        elf[0x40 + 32..0x40 + 40].copy_from_slice(&len.to_le_bytes());
        elf[0x40 + 40..0x40 + 48].copy_from_slice(&len.to_le_bytes());
        elf
    }

    fn load_logged(
        main: &[u8],
        origin: Option<&str>,
        cwd: &str,
        files: &[(&str, Vec<u8>)],
    ) -> (Option<Linked>, Vec<String>) {
        let log = core::cell::RefCell::new(Vec::new());
        let linked = link_at(main, origin, cwd, None, false, |path| {
            log.borrow_mut().push(String::from(path));
            files.iter().find(|(name, _)| *name == path).map(|(_, bytes)| bytes.clone())
        });
        (linked, log.into_inner())
    }

    #[test_case]
    fn runpath_beats_rpath_and_expands_tokens() {
        serial_print!("test runpath_beats_rpath_and_expands_tokens... ");
        let lib = craft_dyn(&[], &[], &[], false, false, None);
        let main = craft_search(&["libfoo.so"], Some("/wrong"), Some("/opt"), None);
        let (linked, log) = load_logged(main.as_slice(), None, "/", &[("/opt/libfoo.so", lib.clone())]);
        assert!(linked.is_some());
        assert_eq!(log, alloc::vec![String::from("/opt/libfoo.so")]);
        let main = craft_search(&["libfoo.so"], None, Some("$ORIGIN/../lib"), None);
        let (linked, log) = load_logged(
            main.as_slice(),
            Some("/app/bin/prog"),
            "/",
            &[("/app/lib/libfoo.so", lib.clone())],
        );
        assert!(linked.is_some());
        assert_eq!(log, alloc::vec![String::from("/app/lib/libfoo.so")]);
        let main = craft_search(&["libfoo.so"], None, Some("/usr/$LIB"), None);
        let (linked, log) = load_logged(main.as_slice(), None, "/", &[("/usr/lib/libfoo.so", lib)]);
        assert!(linked.is_some());
        assert_eq!(log, alloc::vec![String::from("/usr/lib/libfoo.so")]);
        serial_println!("[ok]");
    }

    #[test_case]
    fn rpath_follows_the_loader_until_runpath() {
        serial_print!("test rpath_follows_the_loader_until_runpath... ");
        let libb = craft_dyn(&[], &[], &[], false, false, None);
        let liba = craft_search(&["libb.so"], None, None, None);
        let main = craft_search(&["liba.so"], Some("/opt"), None, None);
        let (linked, log) = load_logged(
            main.as_slice(),
            None,
            "/",
            &[("/opt/liba.so", liba), ("/opt/libb.so", libb.clone())],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/opt/liba.so"), String::from("/opt/libb.so")]
        );
        let liba = craft_search(&["libb.so"], None, Some("/else"), None);
        let main = craft_search(&["liba.so"], Some("/opt"), None, None);
        let (linked, log) = load_logged(
            main.as_slice(),
            None,
            "/",
            &[("/opt/liba.so", liba), ("/else/libb.so", libb)],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/opt/liba.so"), String::from("/else/libb.so")]
        );
        // У liba есть и RPATH, и RUNPATH. Прямая зависимость берёт только
        // RUNPATH. Зависимость той зависимости снова видит RPATH liba,
        // а RUNPATH liba — нет.
        let libd = craft_dyn(&[], &[], &[], false, false, None);
        let libb = craft_search(&["libd.so"], None, None, None);
        let liba = craft_search(&["libb.so"], Some("/froma"), Some("/else"), None);
        let main = craft_search(&["liba.so"], Some("/opt"), None, None);
        let (linked, log) = load_logged(
            main.as_slice(),
            None,
            "/",
            &[
                ("/opt/liba.so", liba),
                ("/else/libb.so", libb),
                ("/froma/libd.so", libd),
            ],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![
                String::from("/opt/liba.so"),
                String::from("/else/libb.so"),
                String::from("/froma/libd.so"),
            ]
        );
        serial_println!("[ok]");
    }

    #[test_case]
    fn empty_runpath_relative_path_and_platform() {
        serial_print!("test empty_runpath_relative_path_and_platform... ");
        let lib = craft_dyn(&[], &[], &[], false, false, None);
        let main = craft_search(&["libfoo.so"], Some("/opt"), Some(""), None);
        let (linked, log) = load_logged(main.as_slice(), None, "/", &[("/lib/libfoo.so", lib.clone())]);
        assert!(linked.is_some());
        assert_eq!(log, alloc::vec![String::from("/lib/libfoo.so")]);
        let main = craft_search(&["./libfoo.so"], None, None, None);
        let (linked, log) = load_logged(main.as_slice(), None, "/app", &[("/app/libfoo.so", lib.clone())]);
        assert!(linked.is_some());
        assert_eq!(log, alloc::vec![String::from("/app/libfoo.so")]);
        let main = craft_search(&["libfoo.so"], None, Some("rel"), None);
        let (linked, log) = load_logged(
            main.as_slice(),
            None,
            "/app",
            &[("/app/rel/libfoo.so", lib)],
        );
        assert!(linked.is_some());
        assert_eq!(log, alloc::vec![String::from("/app/rel/libfoo.so")]);
        let main = craft_search(&["libfoo.so"], None, Some("/usr/$PLATFORM"), None);
        assert!(link_at(main.as_slice(), None, "/", None, false, |_| Some(Vec::new())).is_none());
        serial_println!("[ok]");
    }

    #[test_case]
    fn interpreter_uses_the_executable_rpath() {
        serial_print!("test interpreter_uses_the_executable_rpath... ");
        let lib = craft_dyn(&[], &[], &[], false, false, None);
        let ld = craft_dyn(&["libld.so"], &[], &[], false, false, None);
        let main = craft_search(&[], Some("/opt"), None, Some("/bin/ld.so"));
        let (linked, log) = load_logged(
            main.as_slice(),
            None,
            "/",
            &[("/bin/ld.so", ld.clone()), ("/opt/libld.so", lib.clone())],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/bin/ld.so"), String::from("/opt/libld.so")]
        );
        let main = craft_search(&[], Some("/opt"), Some("/app-run"), Some("/bin/ld.so"));
        let (linked, log) = load_logged(
            main.as_slice(),
            None,
            "/",
            &[("/bin/ld.so", ld), ("/lib/libld.so", lib)],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/bin/ld.so"), String::from("/lib/libld.so")]
        );
        serial_println!("[ok]");
    }

    fn load_libpath(
        main: &[u8],
        origin: Option<&str>,
        cwd: &str,
        libpath: Option<&str>,
        files: &[(&str, Vec<u8>)],
    ) -> (Option<Linked>, Vec<String>) {
        let log = core::cell::RefCell::new(Vec::new());
        let linked = link_at(main, origin, cwd, libpath, false, |path| {
            log.borrow_mut().push(String::from(path));
            files
                .iter()
                .find(|(name, _)| *name == path)
                .map(|(_, bytes)| bytes.clone())
        });
        (linked, log.into_inner())
    }

    #[test_case]
    fn ld_library_path_sits_between_rpath_and_runpath() {
        serial_print!("test ld_library_path_sits_between_rpath_and_runpath... ");
        let env = alloc::vec![
            String::from("OTHER=1"),
            String::from("LD_LIBRARY_PATH=/first"),
            String::from("LD_LIBRARY_PATH=/second"),
        ];
        assert_eq!(ld_library_path(&env), Some("/first"));
        assert_eq!(ld_library_path(&[String::from("PATH=/bin")]), None);

        let lib = craft_dyn(&[], &[], &[], false, false, None);
        // RPATH раньше переменной. Файла в RPATH нет, он в LD_LIBRARY_PATH.
        let main = craft_search(&["libfoo.so"], Some("/rpath"), None, None);
        let (linked, log) = load_libpath(
            main.as_slice(),
            None,
            "/",
            Some("/mid"),
            &[("/mid/libfoo.so", lib.clone())],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/rpath/libfoo.so"), String::from("/mid/libfoo.so")]
        );
        // DT_RUNPATH отменяет RPATH, но не LD_LIBRARY_PATH: переменная
        // раньше RUNPATH.
        let main = craft_search(&["libfoo.so"], Some("/rpath"), Some("/run"), None);
        let (linked, log) = load_libpath(
            main.as_slice(),
            None,
            "/",
            Some("/mid"),
            &[("/run/libfoo.so", lib.clone())],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/mid/libfoo.so"), String::from("/run/libfoo.so")]
        );
        // $ORIGIN в переменной — каталог программы. `;` тоже разделитель.
        let main = craft_search(&["libfoo.so"], None, None, None);
        let (linked, log) = load_libpath(
            main.as_slice(),
            Some("/app/bin/prog"),
            "/app",
            Some("$ORIGIN/extra;rel"),
            &[("/app/rel/libfoo.so", lib.clone())],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![
                String::from("/app/bin/extra/libfoo.so"),
                String::from("/app/rel/libfoo.so"),
            ]
        );
        // Зависимость интерпретатора видит ту же переменную, не RUNPATH
        // программы.
        let ld = craft_dyn(&["libld.so"], &[], &[], false, false, None);
        let main = craft_search(&[], Some("/opt"), Some("/app-run"), Some("/bin/ld.so"));
        let (linked, log) = load_libpath(
            main.as_slice(),
            None,
            "/",
            Some("/mid"),
            &[("/bin/ld.so", ld), ("/mid/libld.so", lib)],
        );
        assert!(linked.is_some());
        assert_eq!(
            log,
            alloc::vec![String::from("/bin/ld.so"), String::from("/mid/libld.so")]
        );
        let main = craft_search(&["libfoo.so"], None, None, None);
        assert!(link_at(main.as_slice(), None, "/", Some("/usr/$PLATFORM"), false, |_| {
            Some(Vec::new())
        })
        .is_none());
        assert!(link_at(main.as_slice(), None, "/", Some("$ORIGIN/lib"), false, |_| {
            Some(Vec::new())
        })
        .is_none());
        let mut wide = String::new();
        for i in 0..33 {
            if i != 0 {
                wide.push(':');
            }
            wide.push('a');
        }
        assert!(link_at(main.as_slice(), None, "/", Some(&wide), false, |_| Some(Vec::new())).is_none());
        serial_println!("[ok]");
    }

    fn extend_load(elf: &mut Vec<u8>, end: usize) {
        if elf.len() < end {
            elf.resize(end, 0);
        }
        let n = elf.len() as u64;
        elf[0x40 + 32..0x40 + 40].copy_from_slice(&n.to_le_bytes());
        elf[0x40 + 40..0x40 + 48].copy_from_slice(&n.to_le_bytes());
    }

    fn read_u64(l4: PhysFrame, addr: u64) -> u64 {
        let mapper = unsafe { mapper_for(l4) };
        let phys = mapper.translate_addr(VirtAddr::new(addr)).expect("mapped");
        let ptr = (phys_offset().as_u64() + phys.as_u64()) as *const u8;
        let mut buf = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 8) };
        u64::from_le_bytes(buf)
    }

    fn read_bytes(l4: PhysFrame, addr: u64, n: usize) -> Vec<u8> {
        let mapper = unsafe { mapper_for(l4) };
        let phys = mapper.translate_addr(VirtAddr::new(addr)).expect("mapped");
        let ptr = (phys_offset().as_u64() + phys.as_u64()) as *const u8;
        let mut buf = alloc::vec![0u8; n];
        unsafe { core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), n) };
        buf
    }

    /// `JUMP_SLOT` из `DT_JMPREL` не пишется при загрузке. `RELATIVE` в той же
    /// таблице пишется. Первый вызов кладёт адрес определившего объекта.
    #[test_case]
    fn lazy_jump_slot_is_filled_on_the_first_call() {
        serial_print!("test lazy_jump_slot_is_filled_on_the_first_call... ");
        let lib = craft_dyn(&[], &[("foo", 1, 0x100, 0x12)], &[], false, false, None);
        let mut main = craft_elf(
            &["libfoo.so"],
            &[("foo", 0, 0, 0x10)],
            &[(0x480, 8, 0, 7), (0x518, 7, 1, 9)],
            true,
            false,
            None,
            false,
            false,
            Some(0x500),
            false,
        );
        extend_load(&mut main, 0x520);
        let marker: u64 = 0x0123_4567_89AB_CDEF;
        main[0x518..0x520].copy_from_slice(&marker.to_le_bytes());
        let linked = link_at(main.as_slice(), None, "/", None, false, |path| {
            if path == "/lib/libfoo.so" {
                Some(lib.clone())
            } else {
                None
            }
        })
        .expect("lazy link");
        assert_eq!(linked.objs[0].bias, 0x400000);
        assert_eq!(linked.objs[1].bias, 0x0200_0000);
        let relative = &linked.objs[0].parsed.relative[0];
        assert!(!relative.defer);
        assert!(relative.jmprel_off.is_none());
        let jump = &linked.objs[0].parsed.relative[1];
        assert!(jump.defer);
        assert!(!jump.missing);
        assert_eq!(jump.jmprel_off, Some(24));
        assert_eq!(jump.addend, 0);
        assert_eq!(jump.sym, Some(0x100));
        assert_eq!(jump.def_bias, Some(0x0200_0000));
        let checked = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            for obj in &linked.objs {
                map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, fa).expect("map");
                apply_relative(l4, &obj.parsed.relative, obj.bias).expect("apply");
            }
            let relative_at = read_u64(l4, 0x400480);
            let still = read_u64(l4, 0x400518);
            arm_plt(l4, &linked.objs, fa).expect("arm");
            let got1 = read_u64(l4, 0x400508);
            let got2 = read_u64(l4, 0x400510);
            let lazy = collect_lazy(&linked.objs).expect("lazy");
            let filled = fixup_slot(l4, &lazy, 0, 24).expect("fixup");
            let slot = read_u64(l4, 0x400518);
            let stub = read_bytes(l4, RESOLVE_PAGE, 256);
            free_user_space(l4, fa);
            (relative_at, still, got1, got2, filled, slot, stub)
        });
        assert_eq!(checked.0, 0x400000 + 7);
        assert_eq!(checked.1, marker);
        assert_eq!(checked.2, 0);
        assert_eq!(checked.3, RESOLVE_PAGE);
        assert_eq!(checked.4, 0x0200_0100);
        assert_eq!(checked.5, 0x0200_0100);
        assert!(checked.6.windows(2).any(|w| w == [0x0f, 0x05]));
        assert!(checked.6.windows(5).any(|w| w == [0xb8, 0x00, 0x04, 0x00, 0x00]));
        serial_println!("[ok]");
    }

    /// `DF_1_NOW` и `LD_BIND_NOW` связывают сразу и роняют загрузку, если
    /// сильного символа нет. Без них промах доживает до вызова.
    #[test_case]
    fn bind_now_keeps_the_slot_eager() {
        serial_print!("test bind_now_keeps_the_slot_eager... ");
        assert!(ld_bind_now(&[String::from("LD_BIND_NOW")]));
        assert!(ld_bind_now(&[String::from("LD_BIND_NOW=")]));
        assert!(ld_bind_now(&[String::from("LD_BIND_NOW=1")]));
        assert!(!ld_bind_now(&[String::from("LD_LIBRARY_PATH=/a")]));

        let lib = craft_dyn(&[], &[("foo", 1, 0x100, 0x12)], &[], false, false, None);
        let mut main = craft_elf(
            &["libfoo.so"],
            &[("foo", 0, 0, 0x10)],
            &[(0x480, 7, 1, 9)],
            true,
            false,
            None,
            false,
            false,
            Some(0x500),
            true,
        );
        extend_load(&mut main, 0x488);
        let linked = link_at(main.as_slice(), None, "/", None, false, |path| {
            if path == "/lib/libfoo.so" {
                Some(lib.clone())
            } else {
                None
            }
        })
        .expect("df_1_now");
        let rel = &linked.objs[0].parsed.relative[0];
        assert!(!rel.defer);
        assert_eq!(rel.sym, Some(0x100));
        assert_eq!(rel.addend, 0);
        let written = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            let obj = &linked.objs[0];
            map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, fa).expect("map");
            apply_relative(l4, &obj.parsed.relative, obj.bias).expect("apply");
            let v = read_u64(l4, obj.bias + 0x480);
            free_user_space(l4, fa);
            v
        });
        assert_eq!(written, 0x0200_0100);

        let missing_now = craft_elf(
            &[],
            &[("missing", 0, 0, 0x10)],
            &[(0x480, 7, 1, 0)],
            true,
            false,
            None,
            false,
            false,
            Some(0x500),
            true,
        );
        assert!(link_at(missing_now.as_slice(), None, "/", None, false, |_| None).is_none());

        let lazy_missing = craft_elf(
            &[],
            &[("missing", 0, 0, 0x10)],
            &[(0x480, 7, 1, 0)],
            true,
            false,
            None,
            false,
            false,
            Some(0x500),
            false,
        );
        assert!(link_at(lazy_missing.as_slice(), None, "/", None, true, |_| None).is_none());
        let linked = link_at(lazy_missing.as_slice(), None, "/", None, false, |_| None).expect("lazy miss");
        let rel = &linked.objs[0].parsed.relative[0];
        assert!(rel.defer && rel.missing);
        let lazy = collect_lazy(&linked.objs).expect("table");
        assert!(lazy.slots[0][0].value.is_none());
        let missed = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            let got = fixup_slot(l4, &lazy, 0, 0);
            free_user_space(l4, fa);
            got
        });
        assert!(missed.is_none());

        let weak = craft_elf(
            &[],
            &[("missing", 0, 0, 0x20)],
            &[(0x480, 7, 1, 4)],
            true,
            false,
            None,
            false,
            false,
            Some(0x500),
            false,
        );
        let linked = link_at(weak.as_slice(), None, "/", None, false, |_| None).expect("weak");
        let rel = &linked.objs[0].parsed.relative[0];
        assert!(rel.defer && !rel.missing);
        assert_eq!(rel.sym, Some(0));
        assert_eq!(rel.def_bias, Some(0));
        let lazy = collect_lazy(&linked.objs).expect("weak table");
        assert_eq!(lazy.slots[0][0].value, Some(0));
        serial_println!("[ok]");
    }

    fn plant(elf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
        if elf.len() < at + bytes.len() {
            elf.resize(at + bytes.len(), 0);
        }
        elf[at..at + bytes.len()].copy_from_slice(bytes);
        let n = elf.len() as u64;
        elf[0x40 + 32..0x40 + 40].copy_from_slice(&n.to_le_bytes());
        elf[0x40 + 40..0x40 + 48].copy_from_slice(&n.to_le_bytes());
    }

    /// Резолвер `mov eax, imm; ret` реально вызывается до входа.
    /// IRELATIVE пишет возврат, `R_X86_64_64` прибавляет addend,
    /// `GLOB_DAT` addend отбрасывает. Чужой IFUNC в `JUMP_SLOT` не
    /// откладывается, соседний обычный слот остаётся ленивым.
    #[test_case]
    fn ifunc_resolver_runs_before_the_entry() {
        serial_print!("test ifunc_resolver_runs_before_the_entry... ");
        let mut rels = Vec::new();
        for _ in 0..257 {
            rels.push((0x100u64, 37u64, 0u64, 0x100u64));
        }
        let many = craft_elf(
            &[],
            &[],
            &rels,
            false,
            false,
            None,
            false,
            false,
            None,
            false,
        );
        assert!(link_with(many.as_slice(), |_| None).is_none());

        let mut zero = craft_elf(
            &[],
            &[],
            &[(0x100, 37, 0, 0)],
            false,
            false,
            None,
            false,
            false,
            None,
            false,
        );
        zero[16] = 2;
        assert!(link_with(zero.as_slice(), |_| None).is_none());

        let weak = craft_dyn(
            &[],
            &[("missing", 0, 0, 0x20)],
            &[(0x480, 1, 1, 4)],
            false,
            false,
            None,
        );
        let linked = link_with(weak.as_slice(), |_| None).expect("weak");
        let rel = &linked.objs[0].parsed.relative[0];
        assert!(!rel.ifunc);
        assert_eq!(rel.sym, Some(0));

        // Резолвер 0x42 по 0x800, `ret` по 0x810, слоты с 0x820.
        let mut main = craft_elf(
            &[],
            &[("pick", 1, 0x800, 0x1A)],
            &[
                (0x820, 37, 0, 0x800),
                (0x828, 1, 1, 0x11),
                (0x830, 6, 1, 0x99),
                (0x838, 8, 0, 7),
            ],
            false,
            false,
            None,
            false,
            false,
            None,
            false,
        );
        plant(&mut main, 0x800, &[0xB8, 0x42, 0x00, 0x00, 0x00, 0xC3]);
        plant(&mut main, 0x810, &[0xC3]);
        main[24..32].copy_from_slice(&0x810u64.to_le_bytes());
        let l4 = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            map_range_zeroed(
                l4,
                VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE),
                VirtAddr::new(USER_STACK_TOP - 1),
                fa,
                USER_FLAGS,
            )
            .expect("stack");
            let img = load_elf_image(
                l4,
                &main,
                &[String::from("t")],
                &[],
                USER_STACK_TOP,
                fa,
                Cred::root(),
                "/bin/t.elf",
                "/",
            )
            .expect("load");
            assert_eq!(img.entry, IFUNC_PAGE);
            assert_eq!(read_u64(l4, IFUNC_TABLE), 3);
            assert_eq!(read_u64(l4, IFUNC_TABLE + 8), 0x400810);
            assert_eq!(read_u64(l4, IFUNC_TABLE + 16), 0x400820);
            assert_eq!(read_u64(l4, IFUNC_TABLE + 24), 0x400800);
            assert_eq!(read_u64(l4, IFUNC_TABLE + 32), 0);
            assert_eq!(read_u64(l4, IFUNC_TABLE + 56), 0x11);
            assert_eq!(read_u64(l4, IFUNC_TABLE + 80), 0);
            assert_eq!(read_u64(l4, 0x400820), 0);
            assert_eq!(read_u64(l4, 0x400828), 0);
            assert_eq!(read_u64(l4, 0x400830), 0);
            assert_eq!(read_u64(l4, 0x400838), 0x400007);
            l4
        });
        call_ifunc_stub(l4);
        let (irel, abs, glob) = crate::memory::with_frame_allocator(|fa| {
            let irel = read_u64(l4, 0x400820);
            let abs = read_u64(l4, 0x400828);
            let glob = read_u64(l4, 0x400830);
            free_user_space(l4, fa);
            (irel, abs, glob)
        });
        assert_eq!(irel, 0x42);
        assert_eq!(abs, 0x53);
        assert_eq!(glob, 0x42);

        let mut lib = craft_dyn(
            &[],
            &[("foo", 1, 0x800, 0x1A), ("bar", 1, 0x100, 0x12)],
            &[],
            false,
            false,
            None,
        );
        plant(&mut lib, 0x800, &[0xB8, 0x77, 0x00, 0x00, 0x00, 0xC3]);
        let mut host = craft_elf(
            &["libfoo.so"],
            &[("foo", 0, 0, 0x10), ("bar", 0, 0, 0x10)],
            &[(0x480, 7, 1, 99), (0x488, 7, 2, 5)],
            true,
            false,
            None,
            false,
            false,
            Some(0x500),
            false,
        );
        plant(&mut host, 0x810, &[0xC3]);
        host[24..32].copy_from_slice(&0x810u64.to_le_bytes());
        let marker = 0x1111_1111_1111_1111u64;
        let other = 0x2222_2222_2222_2222u64;
        host[0x480..0x488].copy_from_slice(&marker.to_le_bytes());
        host[0x488..0x490].copy_from_slice(&other.to_le_bytes());
        let linked = link_with(host.as_slice(), |path| {
            if path == "/lib/libfoo.so" {
                Some(lib.clone())
            } else {
                None
            }
        })
        .expect("ext ifunc");
        let foo = &linked.objs[0].parsed.relative[0];
        assert!(foo.ifunc && !foo.defer && foo.jmprel_off.is_none());
        assert_eq!(foo.addend, 0);
        assert_eq!(foo.sym, Some(0x800));
        assert_eq!(foo.def_bias, Some(0x0200_0000));
        let bar = &linked.objs[0].parsed.relative[1];
        assert!(!bar.ifunc && bar.defer && bar.jmprel_off == Some(24));
        let lazy = collect_lazy(&linked.objs).expect("lazy");
        assert_eq!(lazy.slots[0].len(), 1);
        assert_eq!(lazy.slots[0][0].got, 0x400488);
        assert_eq!(lazy.slots[0][0].value, Some(0x0200_0100));
        let l4 = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            for obj in &linked.objs {
                map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, fa).expect("map");
                apply_relative(l4, &obj.parsed.relative, obj.bias).expect("apply");
            }
            arm_plt(l4, &linked.objs, fa).expect("arm");
            assert!(install_ifunc(l4, &linked.objs, 0x400810, fa).expect("ifunc"));
            assert_eq!(read_u64(l4, 0x400480), marker);
            assert_eq!(read_u64(l4, 0x400488), other);
            assert_eq!(read_u64(l4, 0x400510), RESOLVE_PAGE);
            l4
        });
        call_ifunc_stub(l4);
        let (foo_slot, bar_slot) = crate::memory::with_frame_allocator(|fa| {
            let foo_slot = read_u64(l4, 0x400480);
            let bar_slot = read_u64(l4, 0x400488);
            free_user_space(l4, fa);
            (foo_slot, bar_slot)
        });
        assert_eq!(foo_slot, 0x77);
        assert_eq!(bar_slot, other);
        serial_println!("[ok]");
    }

    /// `st_size` и `st_other` у символа `index`. Нулевой символ — индекс 0.
    fn patch_sym(elf: &mut Vec<u8>, index: usize, size: u64, other: u8) {
        let at = 0x200 + index * 24;
        elf[at + 5] = other;
        elf[at + 16..at + 24].copy_from_slice(&size.to_le_bytes());
    }

    fn with_lib(lib: Vec<u8>) -> impl FnMut(&str) -> Option<Vec<u8>> {
        move |path: &str| {
            if path == "/lib/libfoo.so" {
                Some(lib.clone())
            } else {
                None
            }
        }
    }

    /// Слот библиотеки и восемь байт слота программы после копирования.
    fn copied(linked: &Linked) -> (u64, Vec<u8>, Vec<u8>) {
        crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            for obj in &linked.objs {
                map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, fa).expect("map");
                apply_relative(l4, &obj.parsed.relative, obj.bias).expect("apply");
            }
            apply_copies(l4, &linked.objs).expect("copy");
            let slot = read_u64(l4, linked.objs[1].bias + 0x820);
            let got = read_bytes(l4, linked.objs[0].bias + 0x900, 8);
            let src = read_bytes(l4, linked.objs[1].bias + 0x800, 4);
            free_user_space(l4, fa);
            (slot, got, src)
        })
    }

    /// `R_X86_64_COPY` переносит минимум `st_size` из библиотеки в программу,
    /// а `GLOB_DAT` библиотеки начинает указывать на слот программы.
    /// Защищённый символ библиотека оставляет себе. Нет источника, источник
    /// IFUNC и минимум больше 64 КиБ — отказ.
    #[test_case]
    fn copy_reloc_fills_the_executable_slot() {
        serial_print!("test copy_reloc_fills_the_executable_slot... ");
        let mut alone = craft_dyn(
            &[],
            &[("var", 1, 0x900, 0x11)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut alone, 1, 8, 0);
        assert!(link_with(alone.as_slice(), |_| None).is_none());

        let mut weak_alone = craft_dyn(
            &[],
            &[("var", 1, 0x900, 0x21)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut weak_alone, 1, 8, 0);
        assert!(link_with(weak_alone.as_slice(), |_| None).is_none());

        let mut ifunc_lib = craft_dyn(&[], &[("var", 1, 0x800, 0x1A)], &[], false, false, None);
        patch_sym(&mut ifunc_lib, 1, 4, 0);
        let mut ifunc_main = craft_dyn(
            &["libfoo.so"],
            &[("var", 1, 0x900, 0x11)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut ifunc_main, 1, 8, 0);
        assert!(link_with(ifunc_main.as_slice(), with_lib(ifunc_lib)).is_none());

        let big = COPY_MAX + 1;
        let mut big_lib = craft_dyn(&[], &[("var", 1, 0x800, 0x11)], &[], false, false, None);
        patch_sym(&mut big_lib, 1, big, 0);
        let mut big_main = craft_dyn(
            &["libfoo.so"],
            &[("var", 1, 0x900, 0x11)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut big_main, 1, big, 0);
        assert!(link_with(big_main.as_slice(), with_lib(big_lib)).is_none());

        let mut small_lib = craft_dyn(&[], &[("var", 1, 0x800, 0x11)], &[], false, false, None);
        patch_sym(&mut small_lib, 1, 4, 0);
        let mut huge_ref = craft_dyn(
            &["libfoo.so"],
            &[("var", 1, 0x900, 0x11)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut huge_ref, 1, big, 0);
        let linked = link_with(huge_ref.as_slice(), with_lib(small_lib)).expect("min under the cap");
        let rel = &linked.objs[0].parsed.relative[0];
        assert!(rel.copy);
        assert_eq!(rel.ref_size, big);
        assert_eq!(rel.src_size, 4);

        let mut lib = craft_dyn(
            &[],
            &[("var", 1, 0x800, 0x11)],
            &[(0x820, 6, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut lib, 1, 4, 0);
        plant(&mut lib, 0x800, &[0x11, 0x22, 0x33, 0x44]);
        plant(&mut lib, 0x820, &[0u8; 8]);
        let mut main = craft_dyn(
            &["libfoo.so"],
            &[("var", 1, 0x900, 0x11)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut main, 1, 8, 0);
        plant(&mut main, 0x900, &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        let linked = link_with(main.as_slice(), with_lib(lib)).expect("copy");
        assert_eq!(linked.objs[0].bias, 0x400000);
        assert_eq!(linked.objs[1].bias, 0x0200_0000);
        let main_rel = &linked.objs[0].parsed.relative[0];
        assert!(main_rel.copy && main_rel.ext.is_none());
        assert!(!main_rel.defer && main_rel.jmprel_off.is_none());
        assert_eq!(main_rel.sym, Some(0x800));
        assert_eq!(main_rel.def_bias, Some(0x0200_0000));
        assert_eq!(main_rel.src_size, 4);
        assert_eq!(main_rel.ref_size, 8);
        let lib_rel = &linked.objs[1].parsed.relative[0];
        assert!(!lib_rel.copy && !lib_rel.ifunc);
        assert_eq!(lib_rel.sym, Some(0x900));
        assert_eq!(lib_rel.def_bias, Some(0x400000));
        let (slot, got, src) = copied(&linked);
        assert_eq!(slot, 0x400900);
        assert_eq!(got, alloc::vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xAA, 0xAA, 0xAA]);
        assert_eq!(src, alloc::vec![0x11, 0x22, 0x33, 0x44]);

        let mut plib = craft_dyn(
            &[],
            &[("var", 1, 0x800, 0x11)],
            &[(0x820, 6, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut plib, 1, 4, 3);
        plant(&mut plib, 0x800, &[0x11, 0x22, 0x33, 0x44]);
        plant(&mut plib, 0x820, &[0u8; 8]);
        let mut pmain = craft_dyn(
            &["libfoo.so"],
            &[("var", 1, 0x900, 0x11)],
            &[(0x900, 5, 1, 0)],
            false,
            false,
            None,
        );
        patch_sym(&mut pmain, 1, 8, 0);
        plant(&mut pmain, 0x900, &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        let linked = link_with(pmain.as_slice(), with_lib(plib)).expect("protected");
        let lib_rel = &linked.objs[1].parsed.relative[0];
        assert_eq!(lib_rel.sym, Some(0x800));
        assert!(lib_rel.def_bias.is_none());
        let main_rel = &linked.objs[0].parsed.relative[0];
        assert_eq!(main_rel.sym, Some(0x800));
        assert_eq!(main_rel.def_bias, Some(0x0200_0000));
        let (slot, got, src) = copied(&linked);
        assert_eq!(slot, 0x0200_0000 + 0x800);
        assert_eq!(got, alloc::vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xAA, 0xAA, 0xAA]);
        assert_eq!(src, alloc::vec![0x11, 0x22, 0x33, 0x44]);
        serial_println!("[ok]");
    }

    /// Вставить тег в `.dynamic` перед `DT_NULL` и растянуть `PT_DYNAMIC`.
    fn add_dyn(elf: &mut Vec<u8>, tag: u64, val: u64) {
        let mut at = 0x300usize;
        loop {
            assert!(at + 16 <= 0x3C0, "dynamic ran into the hash");
            let have = u64::from_le_bytes(elf[at..at + 8].try_into().unwrap());
            if have == 0 {
                let null = elf[at..at + 16].to_vec();
                if elf.len() < at + 32 {
                    elf.resize(at + 32, 0);
                }
                elf[at..at + 8].copy_from_slice(&tag.to_le_bytes());
                elf[at + 8..at + 16].copy_from_slice(&val.to_le_bytes());
                elf[at + 16..at + 32].copy_from_slice(&null);
                let sz = (at + 32 - 0x300) as u64;
                elf[0x78 + 32..0x78 + 40].copy_from_slice(&sz.to_le_bytes());
                elf[0x78 + 40..0x78 + 48].copy_from_slice(&sz.to_le_bytes());
                let n = elf.len() as u64;
                let load = u64::from_le_bytes(elf[0x40 + 32..0x40 + 40].try_into().unwrap());
                if n > load {
                    elf[0x40 + 32..0x40 + 40].copy_from_slice(&n.to_le_bytes());
                    elf[0x40 + 40..0x40 + 48].copy_from_slice(&n.to_le_bytes());
                }
                return;
            }
            at += 16;
        }
    }

    fn put_u64(elf: &mut Vec<u8>, at: usize, val: u64) {
        plant(elf, at, &val.to_le_bytes());
    }

    /// `DT_RELR`: чётный адрес и битовая карта. К слову прибавляется база,
    /// сосед без бита не трогается, вторая карта прыгает на 63 слота.
    /// `R_X86_64_RELATIVE` рядом пишет `B + A`. Кривая таблица — отказ.
    #[test_case]
    fn relr_adds_the_bias_to_the_stored_word() {
        serial_print!("test relr_adds_the_bias_to_the_stored_word... ");
        let mut bare = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut bare, 36, 0x500);
        assert!(parse_elf64(&bare).is_none());
        let mut step = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut step, 35, 8);
        add_dyn(&mut step, 36, 0x500);
        add_dyn(&mut step, 37, 4);
        put_u64(&mut step, 0x500, 0x800);
        assert!(parse_elf64(&step).is_none());
        let mut odd = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut odd, 35, 4);
        add_dyn(&mut odd, 36, 0x500);
        assert!(parse_elf64(&odd).is_none());
        let mut lead = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut lead, 35, 8);
        add_dyn(&mut lead, 36, 0x500);
        put_u64(&mut lead, 0x500, 1);
        assert!(parse_elf64(&lead).is_none());
        let mut skew = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut skew, 35, 8);
        add_dyn(&mut skew, 36, 0x500);
        put_u64(&mut skew, 0x500, 0x802);
        assert!(parse_elf64(&skew).is_none());
        let mut outside = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut outside, 35, 8);
        add_dyn(&mut outside, 36, 0x500);
        put_u64(&mut outside, 0x500, 0x8000_0000);
        assert!(parse_elf64(&outside).is_none());
        let mut huge = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut huge, 35, RELR_MAX + 8);
        add_dyn(&mut huge, 36, 0x500);
        assert!(parse_elf64(&huge).is_none());
        let mut short = craft_dyn(&[], &[], &[], false, false, None);
        add_dyn(&mut short, 35, 16);
        add_dyn(&mut short, 36, 0x500);
        put_u64(&mut short, 0x500, 0x800);
        put_u64(&mut short, 0x508, 3);
        put_u64(&mut short, 0x800, 0x11);
        assert!(parse_elf64(&short).is_none());

        let mut elf = craft_dyn(&[], &[], &[(0x830, 8, 0, 7)], false, false, None);
        add_dyn(&mut elf, 35, 24);
        add_dyn(&mut elf, 36, 0x500);
        add_dyn(&mut elf, 37, 8);
        // 0x800, затем биты на 0x808 и 0x810, затем через 63 слота — 0xA00.
        put_u64(&mut elf, 0x500, 0x800);
        put_u64(&mut elf, 0x508, 0b0111);
        put_u64(&mut elf, 0x510, 0b0011);
        put_u64(&mut elf, 0x800, 0x11);
        put_u64(&mut elf, 0x808, 0x22);
        put_u64(&mut elf, 0x810, 0x33);
        put_u64(&mut elf, 0x818, 0x44);
        put_u64(&mut elf, 0x900, 0x66);
        put_u64(&mut elf, 0xA00, 0x55);
        let linked = link_with(elf.as_slice(), |_| None).expect("relr");
        assert_eq!(linked.objs[0].bias, 0x400000);
        assert_eq!(linked.objs[0].parsed.relr.len(), 3);
        let bias = 0x400000u64;
        let got = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            let obj = &linked.objs[0];
            map_and_copy(l4, &obj.bytes, &obj.parsed.segments, obj.bias, fa).expect("map");
            apply_relr(l4, &obj.parsed.relr, obj.bias).expect("relr");
            apply_relative(l4, &obj.parsed.relative, obj.bias).expect("rela");
            let vals = [
                read_u64(l4, bias + 0x800),
                read_u64(l4, bias + 0x808),
                read_u64(l4, bias + 0x810),
                read_u64(l4, bias + 0x818),
                read_u64(l4, bias + 0x900),
                read_u64(l4, bias + 0xA00),
                read_u64(l4, bias + 0x830),
            ];
            free_user_space(l4, fa);
            vals
        });
        assert_eq!(got[0], 0x11 + bias);
        assert_eq!(got[1], 0x22 + bias);
        assert_eq!(got[2], 0x33 + bias);
        assert_eq!(got[3], 0x44);
        assert_eq!(got[4], 0x66);
        assert_eq!(got[5], 0x55 + bias);
        assert_eq!(got[6], 7 + bias);
        serial_println!("[ok]");
    }

    /// Средняя страница уходит в список кадров, соседи остаются.
    /// `mprotect` меняет биты и не ставит NX. Огромная страница — отказ до правки.
    #[test_case]
    fn munmap_returns_the_frame_and_mprotect_changes_bits() {
        serial_print!("test munmap_returns_the_frame_and_mprotect_changes_bits... ");
        assert_eq!(
            brk_free_span(0x1000_1000, 0x1000_0000),
            Some((0x1000_0000, 0x1000_1000))
        );
        assert_eq!(
            brk_free_span(0x1000_0100, 0x1000_0000),
            Some((0x1000_0000, 0x1000_1000))
        );
        assert_eq!(brk_free_span(0x1001, 0x1000), Some((0x1000, 0x2000)));
        assert_eq!(brk_free_span(0x2000, 0x1800), None);
        assert_eq!(brk_free_span(0x2800, 0x1800), Some((0x2000, 0x3000)));
        assert_eq!(sys_munmap(0, 0), 0);
        assert_eq!(sys_munmap(0x1001, 0x1000), crate::linux::EINVAL);
        assert_eq!(sys_mprotect(0x1000, 0x1000, 8), crate::linux::EINVAL);
        assert_eq!(sys_munmap(0x1000, 0x1000), crate::linux::EINVAL);
        // Чужой бит prot — EINVAL до задачи и до выдачи адреса.
        assert_eq!(sys_mmap(0, 0x1000, 8, 0x22, u64::MAX, 0), crate::linux::EINVAL);
        assert_eq!(sys_mmap(0, 0x1000, 3, 0x22, u64::MAX, 0), crate::linux::ENOMEM);

        const BASE: u64 = 0x5000_0000;
        let (l4, phys) = crate::memory::with_frame_allocator(|fa| {
            let l4 = alloc_l4(fa).expect("l4");
            let mut phys = [0u64; 3];
            for i in 0..3u64 {
                let va = BASE + i * 0x1000;
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
                map_zeroed(l4, page, fa, USER_FLAGS).expect("map");
                phys[i as usize] = leaf_of(l4, va).expect("leaf").0;
            }
            // Те же биты, что mmap кладёт в PTE: NONE, READ, WRITE, EXEC.
            for (i, prot) in [0u64, 1, 2, 4].iter().enumerate() {
                let va = 0x5010_0000 + i as u64 * 0x1000;
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
                map_zeroed(l4, page, fa, prot_flags(*prot)).expect("prot");
            }
            (l4, phys)
        });
        for (i, (prot, expect_user, expect_write)) in [
            (0u64, false, false),
            (1, true, false),
            (2, true, true),
            (4, true, false),
        ]
        .iter()
        .enumerate()
        {
            let (_, f) = leaf_of(l4, 0x5010_0000 + i as u64 * 0x1000).unwrap();
            assert!(f.contains(PageTableFlags::PRESENT), "prot {prot}");
            assert_eq!(f.contains(PageTableFlags::USER_ACCESSIBLE), *expect_user);
            assert_eq!(f.contains(PageTableFlags::WRITABLE), *expect_write);
            assert!(!f.contains(PageTableFlags::NO_EXECUTE));
        }
        assert!(unmap_user(l4, 0x5010_0000, 0x5010_4000).is_ok());

        assert_eq!(
            protect_user(l4, BASE + 0x2000, BASE + 0x4000, 1),
            Err(crate::linux::ENOMEM)
        );
        assert!(leaf_of(l4, BASE + 0x2000)
            .unwrap()
            .1
            .contains(PageTableFlags::WRITABLE));

        assert!(protect_user(l4, BASE + 0x1000, BASE + 0x2000, 1).is_ok());
        let (_, f) = leaf_of(l4, BASE + 0x1000).unwrap();
        assert!(f.contains(PageTableFlags::PRESENT));
        assert!(f.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(!f.contains(PageTableFlags::WRITABLE));
        assert!(!f.contains(PageTableFlags::NO_EXECUTE));

        assert!(protect_user(l4, BASE + 0x1000, BASE + 0x2000, 0).is_ok());
        let (_, f) = leaf_of(l4, BASE + 0x1000).unwrap();
        assert!(f.contains(PageTableFlags::PRESENT));
        assert!(!f.contains(PageTableFlags::USER_ACCESSIBLE));

        assert!(protect_user(l4, BASE + 0x1000, BASE + 0x2000, 3).is_ok());
        let (_, f) = leaf_of(l4, BASE + 0x1000).unwrap();
        assert!(f.contains(PageTableFlags::WRITABLE) && f.contains(PageTableFlags::USER_ACCESSIBLE));

        assert!(protect_user(l4, BASE + 0x1000, BASE + 0x2000, 4).is_ok());
        let (_, f) = leaf_of(l4, BASE + 0x1000).unwrap();
        assert!(f.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(!f.contains(PageTableFlags::WRITABLE));
        assert!(!f.contains(PageTableFlags::NO_EXECUTE));
        assert!(protect_user(l4, BASE + 0x1000, BASE + 0x2000, 3).is_ok());

        assert_eq!(
            unmap_user(l4, BASE + 0x1001, BASE + 0x2000),
            Err(crate::linux::EINVAL)
        );
        assert!(leaf_of(l4, BASE + 0x1000).is_some());
        assert!(unmap_user(l4, BASE + 0x3000, BASE + 0x4000).is_ok());

        plant_huge_pde(l4, 0x5020_0000);
        assert_eq!(
            unmap_user(l4, 0x5020_0000, 0x5020_1000),
            Err(crate::linux::EINVAL)
        );
        assert_eq!(leaf_of(l4, BASE).unwrap().0, phys[0]);
        assert_eq!(leaf_of(l4, BASE + 0x1000).unwrap().0, phys[1]);
        assert_eq!(leaf_of(l4, BASE + 0x2000).unwrap().0, phys[2]);

        x86_64::instructions::interrupts::disable();
        assert!(unmap_user(l4, BASE + 0x1000, BASE + 0x2000).is_ok());
        assert!(leaf_of(l4, BASE + 0x1000).is_none());
        assert_eq!(leaf_of(l4, BASE).unwrap().0, phys[0]);
        assert_eq!(leaf_of(l4, BASE + 0x2000).unwrap().0, phys[2]);
        let got = crate::memory::with_frame_allocator(|fa| {
            fa.allocate_frame()
                .expect("reuse")
                .start_address()
                .as_u64()
        });
        assert!(unmap_user(l4, BASE, BASE + 0x1000).is_ok());
        assert!(unmap_user(l4, BASE + 0x2000, BASE + 0x3000).is_ok());
        let uniq = crate::memory::with_frame_allocator(|fa| {
            free_user_space(l4, fa);
            let mut out = [0u64; 8];
            for slot in &mut out {
                *slot = fa
                    .allocate_frame()
                    .expect("frame")
                    .start_address()
                    .as_u64();
            }
            out
        });
        x86_64::instructions::interrupts::enable();
        assert_eq!(got, phys[1]);
        for i in 0..uniq.len() {
            assert_ne!(uniq[i], phys[1]);
            for j in 0..i {
                assert_ne!(uniq[i], uniq[j]);
            }
        }
        serial_println!("[ok]");
    }
}
