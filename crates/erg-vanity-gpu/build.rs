//! Find libOpenCL when distros ship only `libOpenCL.so.1`.
//! Author: arkadianet

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let dirs = [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
        "/usr/local/lib",
    ];
    for dir in dirs {
        if std::path::Path::new(&format!("{dir}/libOpenCL.so")).exists() {
            return;
        }
        let so1 = format!("{dir}/libOpenCL.so.1");
        if std::path::Path::new(&so1).exists() {
            let out = std::env::var("OUT_DIR").expect("OUT_DIR");
            let link = format!("{out}/libOpenCL.so");
            let _ = std::fs::remove_file(&link);
            let _ = std::os::unix::fs::symlink(&so1, &link);
            println!("cargo:rustc-link-search=native={out}");
            return;
        }
    }
}
