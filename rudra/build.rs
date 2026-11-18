use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    write_handoff_elfs(Path::new(&out_dir));

    // 1) User-программы: копируем ELF'ы (build.sh собирает их до ядра).
    for name in ["shell", "hello", "counter", "fizzbuzz", "threads", "signal", "tick", "intr", "epoll", "cred", "seccomp", "init", "fs", "tcp", "seek", "proc", "mode", "smp"] {
        let src = Path::new("target/x86_64-unknown-none/release").join(name);
        let out = Path::new(&out_dir).join(format!("{name}.elf"));
        if src.exists() {
            std::fs::copy(&src, &out).expect("copy user elf");
        } else {
            std::fs::write(&out, b"").expect("write placeholder");
        }
        println!("cargo:rerun-if-changed={}", src.display());
    }

    // 2) Ramdisk-образ из rootfs (pack_rfs.py, нужен python3 в PATH).
    let img = Path::new(&out_dir).join("rfs.img");
    let status = Command::new("python")
        .args(["scripts/pack_rfs.py", "rootfs"])
        .arg(&img)
        .status()
        .expect("run pack_rfs.py (python not in PATH?)");
    assert!(status.success(), "pack_rfs.py failed");
    println!("cargo:rerun-if-changed=scripts/pack_rfs.py");
    println!("cargo:rerun-if-changed=rootfs");
    for entry in std::fs::read_dir("rootfs").unwrap() {
        let p = entry.unwrap().path();
        println!("cargo:rerun-if-changed={}", p.display());
    }
}

/// Два крошечных ET_EXEC. `dyn.elf` просит `/bin/interp.elf` и сам сделал бы
/// `exit(2)`. Интерпретатор печатает `interp-ok` только если в auxv
/// `AT_ENTRY == 0x4000c0` и `AT_BASE == 0`.
fn write_handoff_elfs(out_dir: &Path) {
    let interp_code: &[u8] = &[
        0x45, 0x31, 0xf6, 0x48, 0x89, 0xe3, 0x48, 0x8b, 0x03, 0x48, 0x83, 0xc3, 0x08, 0x48, 0xff,
        0xc0, 0x48, 0xc1, 0xe0, 0x03, 0x48, 0x01, 0xc3, 0x48, 0x8b, 0x03, 0x48, 0x83, 0xc3, 0x08,
        0x48, 0x85, 0xc0, 0x75, 0xf4, 0x4d, 0x31, 0xe4, 0x4d, 0x31, 0xed, 0x48, 0x8b, 0x03, 0x48,
        0x8b, 0x53, 0x08, 0x48, 0x83, 0xc3, 0x10, 0x48, 0x85, 0xc0, 0x74, 0x1e, 0x48, 0x83, 0xf8,
        0x09, 0x75, 0x09, 0x49, 0x89, 0xd4, 0x41, 0x83, 0xce, 0x01, 0xeb, 0xe1, 0x48, 0x83, 0xf8,
        0x07, 0x75, 0xdb, 0x49, 0x89, 0xd5, 0x41, 0x83, 0xce, 0x02, 0xeb, 0xd2, 0x41, 0x83, 0xfe,
        0x03, 0x75, 0x2e, 0xb8, 0xc0, 0x00, 0x40, 0x00, 0x49, 0x39, 0xc4, 0x75, 0x24, 0x4d, 0x85,
        0xed, 0x75, 0x1f, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe, 0x25,
        0x01, 0x80, 0x00, 0xba, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00, 0x00,
        0x31, 0xff, 0x0f, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe,
        0x2f, 0x01, 0x80, 0x00, 0xba, 0x0b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
        0x00, 0xbf, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x05, b'i', b'n', b't', b'e', b'r', b'p', b'-',
        b'o', b'k', b'\n', b'i', b'n', b't', b'e', b'r', b'p', b'-', b'b', b'a', b'd', b'\n',
    ];
    // Код dyn.elf: mov eax, 60; mov edi, 2; syscall. Смещение 192, адрес 0x4000c0.
    let dyn_code: &[u8] = &[0xb8, 0x3c, 0, 0, 0, 0xbf, 2, 0, 0, 0, 0x0f, 0x05];
    let interp_path = b"/bin/interp.elf\0";

    let mut interp = Vec::new();
    interp.extend_from_slice(&elf_header(2, 0x800078, 64, 1));
    interp.extend_from_slice(&phdr(1, 5, 0, 0x800000, 0, 0, 0x1000));
    interp.extend_from_slice(interp_code);
    let interp_len = interp.len() as u64;
    patch_phdr_sizes(&mut interp, 64, interp_len, interp_len);

    let mut dyn_elf = Vec::new();
    dyn_elf.extend_from_slice(&elf_header(2, 0x4000c0, 64, 2));
    dyn_elf.extend_from_slice(&phdr(1, 5, 0, 0x400000, 0, 0, 0x1000));
    dyn_elf.extend_from_slice(&phdr(3, 4, 176, 0x400000 + 176, interp_path.len() as u64, interp_path.len() as u64, 1));
    dyn_elf.extend_from_slice(interp_path);
    dyn_elf.extend_from_slice(dyn_code);
    let dyn_len = dyn_elf.len() as u64;
    patch_phdr_sizes(&mut dyn_elf, 64, dyn_len, dyn_len);

    std::fs::write(out_dir.join("interp.elf"), &interp).expect("write interp.elf");
    std::fs::write(out_dir.join("dyn.elf"), &dyn_elf).expect("write dyn.elf");
    std::fs::write(out_dir.join("dsym.elf"), &dsym_elf()).expect("write dsym.elf");
}

/// ET_DYN с .dynsym/.dynstr/.hash и одной релокацией `R_X86_64_64` на
/// символ `exported_fn` (st_value 0x1234, addend 0x10, слот по vaddr 0x210).
/// Код на входе сравнивает [0x400210] с 0x401244 (S+A+bias): совпало —
/// печатает `dsym-ok` и exit(0), иначе exit(3). Файловые смещения = vaddr.
fn dsym_elf() -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&elf_header(3, 0x1c0, 64, 2));
    e.extend_from_slice(&phdr(1, 7, 0, 0, 0, 0, 0x1000));
    e.extend_from_slice(&phdr(2, 4, 0x100, 0x100, 128, 128, 8));

    // 0x0B0: dynstr.
    e.resize(0xb0, 0);
    e.extend_from_slice(b"\0exported_fn\0");
    // 0x0C0: .dynsym (2 записи по 24 байт).
    e.resize(0xc0, 0);
    e.extend_from_slice(&[0u8; 24]);
    e.extend_from_slice(&1u32.to_le_bytes()); // st_name
    e.push(0x12); // st_info
    e.push(0); // st_other
    e.extend_from_slice(&1u16.to_le_bytes()); // st_shndx (определён)
    e.extend_from_slice(&0x1234u64.to_le_bytes()); // st_value
    e.extend_from_slice(&0u64.to_le_bytes()); // st_size
    // 0x100: .dynamic — 8 записей.
    e.resize(0x100, 0);
    for (tag, val) in [
        (5u64, 0xb0u64),  // DT_STRTAB
        (6, 0xc0),        // DT_SYMTAB
        (11, 24),         // DT_SYMENT
        (4, 0x180),       // DT_HASH
        (7, 0x1a0),       // DT_RELA
        (8, 24),          // DT_RELASZ
        (9, 24),          // DT_RELAENT
        (0, 0),           // DT_NULL
    ] {
        e.extend_from_slice(&tag.to_le_bytes());
        e.extend_from_slice(&val.to_le_bytes());
    }
    // 0x180: SysV .hash — nbucket=1, nchain=2, bucket[0]=1, chain=[0, 0].
    e.resize(0x180, 0);
    for v in [1u32, 2, 1, 0, 0] {
        e.extend_from_slice(&v.to_le_bytes());
    }
    // 0x1A0: .rela.dyn — R_X86_64_64, символ 1, слот 0x210, addend 0x10.
    e.resize(0x1a0, 0);
    e.extend_from_slice(&0x210u64.to_le_bytes());
    e.extend_from_slice(&((1u64 << 32) | 1).to_le_bytes());
    e.extend_from_slice(&0x10u64.to_le_bytes());
    // 0x1C0: код.
    e.resize(0x1c0, 0);
    let code: &[u8] = &[
        0x48, 0xa1, 0x10, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax,[0x400210]
        0x48, 0x3d, 0x44, 0x12, 0x40, 0x00, // cmp rax,0x401244
        0x75, 0x1f, // jne exit3 (0x1f2)
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (write)
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi,1
        0xbe, 0xfe, 0x01, 0x40, 0x00, // mov esi,msg (0x401fe)
        0xba, 0x08, 0x00, 0x00, 0x00, // mov edx,8
        0x0f, 0x05, // syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax,60
        0x31, 0xff, // xor edi,edi
        0x0f, 0x05, // syscall
        // exit3:
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax,60
        0xbf, 0x03, 0x00, 0x00, 0x00, // mov edi,3
        0x0f, 0x05, // syscall
        b'd', b's', b'y', b'm', b'-', b'o', b'k', b'\n',
    ];
    e.extend_from_slice(code);
    // 0x210: слот под релокацию.
    e.resize(0x210, 0);
    e.extend_from_slice(&0u64.to_le_bytes());

    let len = e.len() as u64;
    patch_phdr_sizes(&mut e, 64, len, len);
    e
}

fn elf_header(kind: u16, entry: u64, phoff: u64, phnum: u16) -> [u8; 64] {
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[6] = 1;
    h[16..18].copy_from_slice(&kind.to_le_bytes());
    h[18..20].copy_from_slice(&62u16.to_le_bytes());
    h[20..24].copy_from_slice(&1u32.to_le_bytes());
    h[24..32].copy_from_slice(&entry.to_le_bytes());
    h[32..40].copy_from_slice(&phoff.to_le_bytes());
    h[52..54].copy_from_slice(&64u16.to_le_bytes());
    h[54..56].copy_from_slice(&56u16.to_le_bytes());
    h[56..58].copy_from_slice(&phnum.to_le_bytes());
    h
}

fn phdr(typ: u32, flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> [u8; 56] {
    let mut p = [0u8; 56];
    p[0..4].copy_from_slice(&typ.to_le_bytes());
    p[4..8].copy_from_slice(&flags.to_le_bytes());
    p[8..16].copy_from_slice(&off.to_le_bytes());
    p[16..24].copy_from_slice(&vaddr.to_le_bytes());
    p[24..32].copy_from_slice(&vaddr.to_le_bytes());
    p[32..40].copy_from_slice(&filesz.to_le_bytes());
    p[40..48].copy_from_slice(&memsz.to_le_bytes());
    p[48..56].copy_from_slice(&align.to_le_bytes());
    p
}

fn patch_phdr_sizes(buf: &mut [u8], phdr_off: usize, filesz: u64, memsz: u64) {
    buf[phdr_off + 32..phdr_off + 40].copy_from_slice(&filesz.to_le_bytes());
    buf[phdr_off + 40..phdr_off + 48].copy_from_slice(&memsz.to_le_bytes());
}
