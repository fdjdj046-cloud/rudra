use std::path::{Path, PathBuf};

fn main() {
    // Режим тестов: builder <kernel-elf> <out-img> — BIOS-образ для isa-debug-exit.
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 {
        let kernel = PathBuf::from(&args[1]);
        let out = PathBuf::from(&args[2]);
        bootloader::BiosBoot::new(&kernel)
            .create_disk_image(&out)
            .expect("failed to create test disk image");
        println!("test image: {}", out.display());
        return;
    }

    // Обычный режим: собрать boot-образы ядра (BIOS + UEFI).
    // Путь к ELF ядра подставляет cargo (artifact dependency).
    let kernel_binary_path = env!("CARGO_BIN_FILE_RUDRA_rudra");

    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("images");
    std::fs::create_dir_all(&out_dir).unwrap();

    let uefi_path = out_dir.join("rudra-uefi.img");
    let bios_path = out_dir.join("rudra-bios.img");

    bootloader::UefiBoot::new(Path::new(kernel_binary_path))
        .create_disk_image(&uefi_path)
        .expect("failed to create UEFI disk image");
    bootloader::BiosBoot::new(Path::new(kernel_binary_path))
        .create_disk_image(&bios_path)
        .expect("failed to create BIOS disk image");

    println!("UEFI image: {}", uefi_path.display());
    println!("BIOS image: {}", bios_path.display());
}
