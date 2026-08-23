//! Build script: generate CUDA PTX from the OpenCL kernel sources.
//!
//! The .cl sources are portable C99; a small shim header plus three textual
//! rewrites make them valid CUDA C. When `nvcc` is available at build time we
//! emit `$OUT_DIR/vanity_cuda.ptx` and the CUDA backend is compiled in.
//! Without nvcc the crate still builds (OpenCL-only); the CUDA runtime module
//! reports itself unavailable.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const KERNEL_DIR: &str = "kernels";
/// Same order and membership as GpuProgram::vanity().
const VANITY_ORDER: &[&str] = &[
    "sha256",
    "sha512",
    "hmac_sha512",
    "pbkdf2",
    "secp256k1_fe",
    "secp256k1_scalar",
    "g_table",
    "secp256k1_point",
    "blake2b",
    "base58",
    "bip39",
    "bip32",
    "vanity",
    // Benchmark kernels (used by --bench on both backends).
    "bench",
];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(no_cuda_backend)");
    for name in VANITY_ORDER {
        println!("cargo:rerun-if-changed={KERNEL_DIR}/{name}.cl");
    }
    println!("cargo:rerun-if-changed={KERNEL_DIR}/cuda_shim.cuh");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let Some(nvcc) = find_nvcc() else {
        eprintln!("cargo:warning=nvcc not found; building without the CUDA backend");
        let flag = out_dir.join("no_cuda.flag");
        fs::write(&flag, b"").expect("write no_cuda flag");
        println!("cargo:rustc-cfg=no_cuda_backend");
        return;
    };

    // 1. Concatenate + transform (mirrors tools/gen logic; keep in sync).
    let mut combined = String::from("#include \"cuda_shim.cuh\"\n");
    for name in VANITY_ORDER {
        let src = fs::read_to_string(format!("{KERNEL_DIR}/{name}.cl")).expect("read kernel");
        combined.push_str(&format!("// === {name}.cl ===\n"));
        for line in src.lines() {
            let mut line = line.replace("(ulong8)(", "make_ulong8(");
            if line.starts_with("__constant") {
                line = format!("__constant__{}", &line["__constant".len()..]);
            } else if line.starts_with("static inline ") || line.starts_with("inline ") {
                line = format!("__device__ {line}");
            }
            line = line
                .replace("__constant const ", "")
                .replace("__constant ", "");
            combined.push_str(&line);
            combined.push('\n');
        }
    }

    let build_dir = out_dir.join("cuda_build");
    fs::create_dir_all(&build_dir).expect("create cuda_build dir");
    let cu_path = build_dir.join("vanity_cuda.cu");
    let shim_src = fs::read_to_string(format!("{KERNEL_DIR}/cuda_shim.cuh")).expect("shim");
    fs::write(build_dir.join("cuda_shim.cuh"), shim_src).expect("write shim");
    fs::write(&cu_path, combined).expect("write .cu");

    // 2. Compile to PTX for a generic target so the driver JITs per-device.
    let ptx_path = out_dir.join("vanity_cuda.ptx");
    // Compute capability: honor an override, else compute_75 - the oldest
    // target CUDA 13 still accepts; the driver JITs it at load time.
    let arch = env::var("ERG_CUDA_ARCH").unwrap_or_else(|_| "compute_75".to_string());

    // nvcc rejects very new host GCCs; pick the newest supported one present.
    let mut cmd = Command::new(&nvcc);
    for cc in ["g++-15", "g++-14", "g++-13", "g++-12"] {
        if Command::new(cc).arg("--version").output().is_ok() {
            cmd.arg("-ccbin").arg(cc);
            break;
        }
    }
    if let Ok(cc) = env::var("ERG_CUDA_CCBIN") {
        cmd.arg("-ccbin").arg(cc);
    }
    let status = cmd
        .args([
            "-O3",
            "--ptx",
            "-arch",
            &arch,
            "-o",
            ptx_path.to_str().expect("ptx path"),
            cu_path.to_str().expect("cu path"),
        ])
        .status()
        .expect("spawn nvcc");
    if !status.success() {
        panic!("nvcc failed to compile the CUDA kernel source ({arch})");
    }
    println!("cargo:rerun-if-env-changed=ERG_CUDA_ARCH");
}

fn find_nvcc() -> Option<PathBuf> {
    if let Ok(p) = env::var("ERG_CUDA_NVCC") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    for candidate in [
        "/usr/local/cuda/bin/nvcc",
        "/usr/local/cuda-12/bin/nvcc",
        "/opt/cuda/bin/nvcc",
    ] {
        let pb = PathBuf::from(candidate);
        if pb.exists() {
            return Some(pb);
        }
    }
    let ok = Command::new("nvcc").arg("--version").output().is_ok();
    if ok {
        return Some(PathBuf::from("nvcc"));
    }
    None
}
