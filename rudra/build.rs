use std::path::Path;

fn main() {
    // User-программа собирается build.sh до ядра. Копируем её ELF в OUT_DIR,
    // чтобы include_bytes! работал и без неё (пустой файл = scheduler off).
    let src = Path::new("target/x86_64-unknown-none/release/user");
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("user.elf");
    if src.exists() {
        std::fs::copy(src, &out).expect("copy user.elf");
    } else {
        std::fs::write(&out, b"").expect("write placeholder");
    }
    println!("cargo:rerun-if-changed={}", src.display());
}
