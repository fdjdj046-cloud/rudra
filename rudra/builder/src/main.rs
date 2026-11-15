use std::path::PathBuf;

fn main() {
    // Путь к ELF ядра подставляет cargo (artifact dependency).
    let kernel_binary_path = env!("CARGO_BIN_FILE_RUDRA_rudra");

    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("images");
    std::fs::create_dir_all(&out_dir).unwrap();

    let uefi_path = out_dir.join("rudra-uefi.img");
    let bios_path = out_dir.join("rudra-bios.img");

    bootloader::UefiBoot::new(kernel_binary_path)
        .create_disk_image(&uefi_path)
        .expect("failed to create UEFI disk image");
    bootloader::BiosBoot::new(kernel_binary_path)
        .create_disk_image(&bios_path)
        .expect("failed to create BIOS disk image");

    println!("UEFI image: {}", uefi_path.display());
    println!("BIOS image: {}", bios_path.display());
}
