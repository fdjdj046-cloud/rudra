use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // 1) User-программы: копируем ELF'ы (build.sh собирает их до ядра).
    for name in ["shell", "hello", "counter", "fizzbuzz", "threads"] {
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
