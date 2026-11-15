use std::path::Path;

fn main() {
    // User-программы собираются build.sh до ядра. Копируем их ELF'ы в OUT_DIR;
    // если какой-то отсутствует — пустой файл (программа будет недоступна).
    for name in ["shell", "hello", "counter"] {
        let src = Path::new("target/x86_64-unknown-none/release").join(name);
        let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join(format!("{name}.elf"));
        if src.exists() {
            std::fs::copy(&src, &out).expect("copy user elf");
        } else {
            std::fs::write(&out, b"").expect("write placeholder");
        }
        println!("cargo:rerun-if-changed={}", src.display());
    }
}
