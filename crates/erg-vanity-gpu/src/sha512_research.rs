//! Research-only HMAC-64 A/B on GPU. Not used by vanity search.
//!
//! Author: arkadianet

use crate::context::{GpuContext, GpuError};
use erg_vanity_crypto::sha512_isa::{hmac64_specialized, hmac_mids, pack_be8, unpack_be8};
use ocl::enums::ProfilingInfo;
use ocl::{Buffer, Event, Kernel, MemFlags, Program};

const SRC: &str = include_str!("../kernels/sha512_circuit_research.cl");

#[derive(Clone, Debug)]
pub struct VariantResult {
    pub name: &'static str,
    pub variant: u32,
    pub build_log: String,
    pub ns_per_seed: f64,
    pub runs: u32,
    pub exact: bool,
}

fn compile(ctx: &GpuContext, variant: u32) -> Result<(Program, String), GpuError> {
    let is_nvidia = ctx.info().vendor.to_uppercase().contains("NVIDIA");
    let mut opts = format!("-cl-std=CL1.2 -D RESEARCH_VARIANT={variant}");
    if is_nvidia {
        opts.push_str(" -cl-nv-verbose");
    }
    let source = SRC.to_owned();
    let device = ctx.device();
    let cl_ctx = ctx.context().clone();
    let program = std::thread::Builder::new()
        .name("cl-research".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            Program::builder()
                .src(source)
                .devices(device)
                .cmplr_opt(&opts)
                .build(&cl_ctx)
        })
        .map_err(|e| GpuError::Other(format!("spawn compile: {e}")))?
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))?;

    let log = program
        .build_info(ctx.device(), ocl::enums::ProgramBuildInfo::BuildLog)
        .map(|i| i.to_string())
        .unwrap_or_default();
    Ok((program, log))
}

fn extract_ns(event: &Event, info: ProfilingInfo) -> Result<u64, GpuError> {
    use ocl::enums::ProfilingInfoResult;
    match event.profiling_info(info)? {
        ProfilingInfoResult::Queued(ns)
        | ProfilingInfoResult::Submit(ns)
        | ProfilingInfoResult::Start(ns)
        | ProfilingInfoResult::End(ns) => Ok(ns),
    }
}

/// Compile and time one variant. `batch` work items, `iters` HMAC-64 steps (2048 = full BIP39).
pub fn run_variant(
    ctx: &GpuContext,
    variant: u32,
    name: &'static str,
    batch: usize,
    iters: u32,
    warmup: u32,
    timed: u32,
) -> Result<VariantResult, GpuError> {
    let (program, build_log) = compile(ctx, variant)?;
    let queue = ctx.queue();
    let password = b"password";
    let (inner, outer) = hmac_mids(password);

    let mut u0 = vec![0u64; batch * 8];
    let mut expect = vec![0u8; 64];
    for gid in 0..batch {
        let mut msg = [0u8; 64];
        msg[0] = (gid as u8).wrapping_add(1);
        msg[1] = (gid >> 8) as u8;
        let words = pack_be8(&msg);
        for k in 0..8 {
            u0[gid * 8 + k] = words[k];
        }
        if gid == 0 {
            let mut acc = words;
            let mut u = words;
            for _ in 1..iters {
                u = hmac64_specialized(inner, outer, u);
                for k in 0..8 {
                    acc[k] ^= u[k];
                }
            }
            expect = unpack_be8(acc).to_vec();
        }
    }

    let inner_buf = Buffer::<u64>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().read_only())
        .len(8)
        .copy_host_slice(&inner)
        .build()?;
    let outer_buf = Buffer::<u64>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().read_only())
        .len(8)
        .copy_host_slice(&outer)
        .build()?;
    let u0_buf = Buffer::<u64>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().read_only())
        .len(batch * 8)
        .copy_host_slice(&u0)
        .build()?;
    let out_buf = Buffer::<u64>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().read_write())
        .len(batch * 8)
        .build()?;

    let kernel = Kernel::builder()
        .program(&program)
        .name("research_hmac64_loop")
        .queue(queue.clone())
        .global_work_size(batch)
        .arg(&inner_buf)
        .arg(&outer_buf)
        .arg(&u0_buf)
        .arg(iters)
        .arg(&out_buf)
        .build()?;

    for _ in 0..warmup {
        let mut ev = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut ev).enq()?;
        }
        ev.wait_for().map_err(ocl::Error::from)?;
    }

    let mut total_ns = 0u64;
    for _ in 0..timed {
        let mut ev = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut ev).enq()?;
        }
        ev.wait_for().map_err(ocl::Error::from)?;
        let start = extract_ns(&ev, ProfilingInfo::Start)?;
        let end = extract_ns(&ev, ProfilingInfo::End)?;
        if end <= start {
            return Err(GpuError::Other("invalid profiling timestamps".into()));
        }
        total_ns += end - start;
    }

    let mut got = vec![0u64; 8];
    out_buf.read(&mut got).len(8).enq()?;
    queue.finish()?;
    let exact = unpack_be8(got.try_into().unwrap()) == expect.as_slice();
    Ok(VariantResult {
        name,
        variant,
        build_log,
        ns_per_seed: total_ns as f64 / (timed as f64 * batch as f64),
        runs: timed,
        exact,
    })
}

pub fn run_all(
    batch: usize,
    iters: u32,
    warmup: u32,
    timed: u32,
) -> Result<Vec<VariantResult>, GpuError> {
    let ctx = GpuContext::with_device_profiling(0)?;
    let mut out = Vec::new();
    for (v, name) in [
        (0u32, "prod_rotate_generic"),
        (1u32, "shf_rotate_generic"),
        (2u32, "shf_bitselect_hmac64"),
    ] {
        out.push(run_variant(&ctx, v, name, batch, iters, warmup, timed)?);
    }
    Ok(out)
}
