fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let ld = format!("{}/user.ld", manifest.replace('\\', "/"));
    println!("cargo:rustc-link-arg=-T{}", ld);
    println!("cargo:rerun-if-changed=user.ld");
}
