//! Research-only HMAC-64 A/B on GPU. Not used by vanity search.
//!
//! Author: arkadianet

use crate::context::{DeviceInfo, GpuContext, GpuError};
use crate::kernel::GpuProgram;
use crate::wordlist::WordlistBuffers;
use erg_vanity_crypto::sha512_isa::{hmac64_specialized, hmac_mids, pack_be8, unpack_be8};
use ocl::enums::{
    KernelWorkGroupInfo, KernelWorkGroupInfoResult, ProfilingInfo, ProgramInfo, ProgramInfoResult,
};
use ocl::{Buffer, Event, Kernel, MemFlags, Program};

const SRC: &str = include_str!("../kernels/sha512_circuit_research.cl");

/// Ampere GA10x-class occupancy model (regs/SM, max warps/SM).
const AMPERE_REGS_PER_SM: u32 = 65536;
const AMPERE_MAX_WARPS: u32 = 48;
const AMPERE_MAX_THREADS: u32 = 1536;

#[derive(Clone, Debug, Default)]
pub struct NvResources {
    pub registers: Option<u32>,
    pub spill_store: Option<u32>,
    pub spill_load: Option<u32>,
    pub stack_frame: Option<u32>,
    pub smem: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct PtxMix {
    pub shf: u32,
    pub iadd3: u32,
    pub lop3: u32,
    pub shr_b64: u32,
    pub shl_b64: u32,
    pub or_b64: u32,
    pub has_ptx: bool,
}

impl PtxMix {
    /// Clean SHF rotate path: funnel-shift present, no 64-bit shr/shl pair.
    pub fn looks_like_shf_floor(&self) -> bool {
        self.has_ptx && self.shf > 0 && self.shr_b64 == 0 && self.shl_b64 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recommendation {
    Implement,
    Stop,
    Continue,
}

impl Recommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implement => "IMPLEMENT",
            Self::Stop => "STOP",
            Self::Continue => "CONTINUE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct VariantResult {
    pub name: &'static str,
    pub variant: u32,
    pub build_log: String,
    pub samples_ns: Vec<f64>,
    pub median_ns: f64,
    pub min_ns: f64,
    pub max_ns: f64,
    pub stdev_ns: f64,
    pub runs: u32,
    pub exact: bool,
    pub exact_checked: usize,
    pub nv: NvResources,
    pub ptx: PtxMix,
    pub work_group_size: Option<usize>,
    pub preferred_wg_multiple: Option<usize>,
    pub private_mem: Option<u64>,
    pub occupancy_warps: Option<u32>,
    pub occupancy_pct: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ProdBaseline {
    pub median_ns: f64,
    pub min_ns: f64,
    pub max_ns: f64,
    pub stdev_ns: f64,
    pub samples_ns: Vec<f64>,
    pub nv: NvResources,
    pub build_log: String,
}

#[derive(Clone, Debug)]
pub struct BenchReport {
    pub device: DeviceInfo,
    pub batch: usize,
    pub iters: u32,
    pub warmup: u32,
    pub timed: u32,
    pub local: Option<usize>,
    pub variants: Vec<VariantResult>,
    pub prod_pbkdf2: Option<ProdBaseline>,
    pub recommendation: Recommendation,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct BenchConfig {
    pub batch: usize,
    pub iters: u32,
    pub warmup: u32,
    pub timed: u32,
    pub local: Option<usize>,
    pub time_prod: bool,
}

impl BenchConfig {
    /// Production-scale isolated launch. 4096 work items would underfill an RTX.
    pub fn production_scale() -> Self {
        Self {
            batch: 1 << 18,
            iters: 2048,
            warmup: 5,
            timed: 12,
            local: None,
            time_prod: true,
        }
    }

    pub fn from_env_args() -> Self {
        let mut cfg = Self::production_scale();
        let mut args = std::env::args().skip(1);
        if let Some(v) = args.next() {
            if let Ok(n) = v.parse() {
                cfg.batch = n;
            }
        }
        if let Some(v) = args.next() {
            if let Ok(n) = v.parse() {
                cfg.iters = n;
            }
        }
        if let Some(v) = args.next() {
            if let Ok(n) = v.parse() {
                cfg.warmup = n;
            }
        }
        if let Some(v) = args.next() {
            if let Ok(n) = v.parse() {
                cfg.timed = n;
            }
        }
        if let Ok(v) = std::env::var("SHA512_BENCH_BATCH") {
            if let Ok(n) = v.parse() {
                cfg.batch = n;
            }
        }
        if let Ok(v) = std::env::var("SHA512_BENCH_ITERS") {
            if let Ok(n) = v.parse() {
                cfg.iters = n;
            }
        }
        if let Ok(v) = std::env::var("SHA512_BENCH_WARMUP") {
            if let Ok(n) = v.parse() {
                cfg.warmup = n;
            }
        }
        if let Ok(v) = std::env::var("SHA512_BENCH_TIMED") {
            if let Ok(n) = v.parse() {
                cfg.timed = n;
            }
        }
        if let Ok(v) = std::env::var("SHA512_BENCH_LOCAL") {
            if let Ok(n) = v.parse::<usize>() {
                if n > 0 {
                    cfg.local = Some(n);
                }
            }
        }
        if std::env::var("SHA512_BENCH_SKIP_PROD").ok().as_deref() == Some("1") {
            cfg.time_prod = false;
        }
        cfg
    }
}

pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

pub fn stdev(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = xs.iter().sum::<f64>() / xs.len() as f64;
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (xs.len() - 1) as f64;
    var.sqrt()
}

pub fn occupancy_from_regs(regs: u32) -> (u32, f64) {
    if regs == 0 {
        return (0, 0.0);
    }
    let threads = ((AMPERE_REGS_PER_SM / regs) / 32) * 32;
    let threads = threads.min(AMPERE_MAX_THREADS);
    let warps = threads / 32;
    (warps, (warps as f64 / f64::from(AMPERE_MAX_WARPS)) * 100.0)
}

/// Parse NVIDIA `-cl-nv-verbose` / ptxas lines for regs and spills.
pub fn parse_nv_resources(log: &str) -> NvResources {
    let mut out = NvResources::default();
    let mut after_kernel = false;
    for line in log.lines() {
        let l = line.trim();
        if l.contains("research_hmac64_loop") || l.contains("bench_pbkdf2") {
            after_kernel = true;
        }
        if let Some(rest) = l.split("Used ").nth(1) {
            if rest.contains("register") {
                if let Some(n) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) {
                    if after_kernel || out.registers.is_none() {
                        out.registers = Some(n);
                    }
                }
                if let Some(idx) = rest.find("bytes smem") {
                    let head = &rest[..idx];
                    if let Some(n) = head
                        .split(',')
                        .last()
                        .and_then(|s| s.split_whitespace().next())
                        .and_then(|s| s.parse().ok())
                    {
                        out.smem = Some(n);
                    }
                }
            }
        }
        if l.contains("spill stores") && l.contains("spill loads") {
            let nums: Vec<u32> = l
                .split(|c: char| !c.is_ascii_digit())
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() >= 3 {
                out.stack_frame = Some(nums[0]);
                out.spill_store = Some(nums[1]);
                out.spill_load = Some(nums[2]);
            }
        }
    }
    out
}

fn count_ascii_ci(hay: &[u8], needle: &[u8]) -> u32 {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    let mut n = 0u32;
    let last = hay.len() - needle.len();
    for i in 0..=last {
        if hay[i..i + needle.len()]
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            n += 1;
        }
    }
    n
}

/// Count PTX-like tokens in an NVIDIA program binary (PTX is often embedded).
pub fn scan_ptx_mix(bin: &[u8]) -> PtxMix {
    let has_ptx = count_ascii_ci(bin, b".version") > 0
        || count_ascii_ci(bin, b"shf.r") > 0
        || count_ascii_ci(bin, b"shr.b64") > 0;
    PtxMix {
        shf: count_ascii_ci(bin, b"shf.r") + count_ascii_ci(bin, b"shf.l"),
        iadd3: count_ascii_ci(bin, b"iadd3"),
        lop3: count_ascii_ci(bin, b"lop3"),
        shr_b64: count_ascii_ci(bin, b"shr.b64"),
        shl_b64: count_ascii_ci(bin, b"shl.b64"),
        or_b64: count_ascii_ci(bin, b"or.b64"),
        has_ptx,
    }
}

fn merge_ptx(bins: &[Vec<u8>]) -> PtxMix {
    let mut acc = PtxMix::default();
    for b in bins {
        let p = scan_ptx_mix(b);
        acc.shf += p.shf;
        acc.iadd3 += p.iadd3;
        acc.lop3 += p.lop3;
        acc.shr_b64 += p.shr_b64;
        acc.shl_b64 += p.shl_b64;
        acc.or_b64 += p.or_b64;
        acc.has_ptx |= p.has_ptx;
    }
    acc
}

fn program_binaries(program: &Program) -> Vec<Vec<u8>> {
    match program.info(ProgramInfo::Binaries) {
        Ok(ProgramInfoResult::Binaries(v)) => v,
        _ => Vec::new(),
    }
}

fn lowering_looks_like_floor(r: &VariantResult) -> bool {
    if r.ptx.looks_like_shf_floor() {
        return true;
    }
    let log = r.build_log.to_ascii_lowercase();
    log.contains("shf") && (log.contains("iadd3") || log.contains("lop3"))
}

/// Decision from measured A/B. Unmeasured GPU / missing SASS stays CONTINUE.
pub fn recommend(rows: &[VariantResult]) -> (Recommendation, String) {
    if rows.is_empty() {
        return (
            Recommendation::Continue,
            "no variant timings (no GPU or compile failed)".into(),
        );
    }
    if let Some(bad) = rows.iter().find(|r| !r.exact) {
        return (
            Recommendation::Continue,
            format!("{} failed bit-exact check; do not ship", bad.name),
        );
    }
    let Some(base) = rows.iter().find(|r| r.variant == 0) else {
        return (Recommendation::Continue, "missing prod_rotate_generic".into());
    };
    let best = rows
        .iter()
        .min_by(|a, b| a.median_ns.partial_cmp(&b.median_ns).unwrap())
        .unwrap();
    if !base.median_ns.is_finite() || base.median_ns <= 0.0 {
        return (Recommendation::Continue, "invalid baseline median".into());
    }
    let speedup = base.median_ns / best.median_ns;
    if speedup >= 1.10 && best.variant != 0 {
        return (
            Recommendation::Implement,
            format!(
                "{} is {:.1}% faster than prod_rotate_generic (exact)",
                best.name,
                (speedup - 1.0) * 100.0
            ),
        );
    }
    let all_close = rows.iter().all(|r| {
        (r.median_ns - base.median_ns).abs() / base.median_ns <= 0.03
    });
    let have_lowering = rows.iter().any(|r| r.ptx.has_ptx || !r.build_log.is_empty());
    let floor = rows.iter().all(lowering_looks_like_floor);
    if all_close && have_lowering && floor {
        return (
            Recommendation::Stop,
            "variants within 3% and lowering already looks like SHF floor".into(),
        );
    }
    if all_close && !floor {
        return (
            Recommendation::Continue,
            "variants within noise but SHF/IADD3 floor not confirmed in PTX/log".into(),
        );
    }
    if speedup > 1.0 && speedup < 1.10 && best.variant != 0 {
        return (
            Recommendation::Continue,
            format!(
                "{} wins {:.1}% — below the 10% bar",
                best.name,
                (speedup - 1.0) * 100.0
            ),
        );
    }
    (
        Recommendation::Continue,
        "no ≥10% win; compiler floor not confirmed".into(),
    )
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

fn expect_acc(inner: [u64; 8], outer: [u64; 8], gid: usize, iters: u32) -> [u8; 64] {
    let mut msg = [0u8; 64];
    msg[0] = (gid as u8).wrapping_add(1);
    msg[1] = (gid >> 8) as u8;
    let words = pack_be8(&msg);
    let mut acc = words;
    let mut u = words;
    for _ in 1..iters {
        u = hmac64_specialized(inner, outer, u);
        for k in 0..8 {
            acc[k] ^= u[k];
        }
    }
    unpack_be8(acc)
}

/// Compile and time one variant. `iters` HMAC-64 steps (2048 = full BIP39 loop).
pub fn run_variant(
    ctx: &GpuContext,
    variant: u32,
    name: &'static str,
    cfg: &BenchConfig,
) -> Result<VariantResult, GpuError> {
    let batch = cfg.batch;
    let iters = cfg.iters;
    let (program, build_log) = compile(ctx, variant)?;
    let ptx = merge_ptx(&program_binaries(&program));
    let nv = parse_nv_resources(&build_log);
    let (occupancy_warps, occupancy_pct) = match nv.registers {
        Some(r) => {
            let (w, p) = occupancy_from_regs(r);
            (Some(w), Some(p))
        }
        None => (None, None),
    };

    let queue = ctx.queue();
    let password = b"password";
    let (inner, outer) = hmac_mids(password);
    let check_n = batch.min(8);

    let mut u0 = vec![0u64; batch * 8];
    let mut expect = vec![[0u8; 64]; check_n];
    for gid in 0..batch {
        let mut msg = [0u8; 64];
        msg[0] = (gid as u8).wrapping_add(1);
        msg[1] = (gid >> 8) as u8;
        let words = pack_be8(&msg);
        u0[gid * 8..gid * 8 + 8].copy_from_slice(&words);
        if gid < check_n {
            expect[gid] = expect_acc(inner, outer, gid, iters);
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

    let mut kb = Kernel::builder();
    kb.program(&program)
        .name("research_hmac64_loop")
        .queue(queue.clone())
        .global_work_size(batch)
        .arg(&inner_buf)
        .arg(&outer_buf)
        .arg(&u0_buf)
        .arg(iters)
        .arg(&out_buf);
    if let Some(local) = cfg.local {
        kb.local_work_size(local);
    }
    let kernel = kb.build()?;

    let mut work_group_size = None;
    let mut preferred_wg_multiple = None;
    let mut private_mem = None;
    if let Ok(KernelWorkGroupInfoResult::WorkGroupSize(n)) =
        kernel.wg_info(ctx.device(), KernelWorkGroupInfo::WorkGroupSize)
    {
        work_group_size = Some(n);
    }
    if let Ok(KernelWorkGroupInfoResult::PreferredWorkGroupSizeMultiple(n)) =
        kernel.wg_info(ctx.device(), KernelWorkGroupInfo::PreferredWorkGroupSizeMultiple)
    {
        preferred_wg_multiple = Some(n);
    }
    if let Ok(KernelWorkGroupInfoResult::PrivateMemSize(n)) =
        kernel.wg_info(ctx.device(), KernelWorkGroupInfo::PrivateMemSize)
    {
        private_mem = Some(n);
    }

    for _ in 0..cfg.warmup {
        let mut ev = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut ev).enq()?;
        }
        ev.wait_for().map_err(ocl::Error::from)?;
    }

    let mut samples_ns = Vec::with_capacity(cfg.timed as usize);
    for _ in 0..cfg.timed {
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
        samples_ns.push((end - start) as f64 / batch as f64);
    }

    let mut got = vec![0u64; check_n * 8];
    out_buf.read(&mut got).len(check_n * 8).enq()?;
    queue.finish()?;
    let mut exact = true;
    for gid in 0..check_n {
        let words: [u64; 8] = got[gid * 8..gid * 8 + 8].try_into().unwrap();
        if unpack_be8(words) != expect[gid] {
            exact = false;
        }
    }

    Ok(VariantResult {
        name,
        variant,
        build_log,
        median_ns: median(&samples_ns),
        min_ns: samples_ns.iter().copied().fold(f64::INFINITY, f64::min),
        max_ns: samples_ns.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        stdev_ns: stdev(&samples_ns),
        samples_ns,
        runs: cfg.timed,
        exact,
        exact_checked: check_n,
        nv,
        ptx,
        work_group_size,
        preferred_wg_multiple,
        private_mem,
        occupancy_warps,
        occupancy_pct,
    })
}

pub fn run_prod_pbkdf2(ctx: &GpuContext, cfg: &BenchConfig) -> Result<ProdBaseline, GpuError> {
    let program = GpuProgram::bench(ctx)?;
    let queue = ctx.queue();
    let salt_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().read_only())
        .len(32)
        .build()?;
    let checksum_buf = Buffer::<u32>::builder()
        .queue(queue.clone())
        .flags(MemFlags::new().write_only())
        .len(cfg.batch)
        .build()?;
    let wordlist = WordlistBuffers::upload(queue)?;
    let salt = [0x42u8; 32];
    salt_buf.write(&salt[..]).enq()?;
    queue.finish()?;

    let mut kb = Kernel::builder();
    kb.program(program.program())
        .name("bench_pbkdf2")
        .queue(queue.clone())
        .global_work_size(cfg.batch)
        .arg(&salt_buf)
        .arg(0u64)
        .arg(&wordlist.words8)
        .arg(&wordlist.lens)
        .arg(1u32)
        .arg(&checksum_buf);
    if let Some(local) = cfg.local {
        kb.local_work_size(local);
    }
    let kernel = kb.build()?;

    let build_log = program
        .program()
        .build_info(ctx.device(), ocl::enums::ProgramBuildInfo::BuildLog)
        .map(|i| i.to_string())
        .unwrap_or_default();
    let nv = parse_nv_resources(&build_log);

    for iter in 0..cfg.warmup {
        kernel.set_arg(1, (iter as u64) * (cfg.batch as u64))?;
        let mut ev = Event::empty();
        unsafe {
            kernel.cmd().enew(&mut ev).enq()?;
        }
        ev.wait_for().map_err(ocl::Error::from)?;
    }

    let mut samples_ns = Vec::with_capacity(cfg.timed as usize);
    for iter in 0..cfg.timed {
        kernel.set_arg(
            1,
            (u64::from(cfg.warmup) + u64::from(iter)) * (cfg.batch as u64),
        )?;
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
        samples_ns.push((end - start) as f64 / cfg.batch as f64);
    }

    Ok(ProdBaseline {
        median_ns: median(&samples_ns),
        min_ns: samples_ns.iter().copied().fold(f64::INFINITY, f64::min),
        max_ns: samples_ns.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        stdev_ns: stdev(&samples_ns),
        samples_ns,
        nv,
        build_log,
    })
}

pub fn run_report(cfg: &BenchConfig) -> Result<BenchReport, GpuError> {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ctx = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        GpuContext::with_device_profiling(0)
    }));
    std::panic::set_hook(prev_hook);
    let ctx = match ctx {
        Ok(Ok(ctx)) => ctx,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(GpuError::Other(
                "OpenCL runtime panicked (no ICD / no platform)".into(),
            ));
        }
    };
    let mut variants = Vec::new();
    for (v, name) in [
        (0u32, "prod_rotate_generic"),
        (1u32, "shf_rotate_generic"),
        (2u32, "shf_bitselect_hmac64"),
    ] {
        variants.push(run_variant(&ctx, v, name, cfg)?);
    }
    let prod_pbkdf2 = if cfg.time_prod {
        Some(run_prod_pbkdf2(&ctx, cfg)?)
    } else {
        None
    };
    let (recommendation, reason) = recommend(&variants);
    Ok(BenchReport {
        device: ctx.info().clone(),
        batch: cfg.batch,
        iters: cfg.iters,
        warmup: cfg.warmup,
        timed: cfg.timed,
        local: cfg.local,
        variants,
        prod_pbkdf2,
        recommendation,
        reason,
    })
}

pub fn format_report(r: &BenchReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "device={} vendor={} CUs={} clock_mhz={:?} mem_mb={}\n",
        r.device.device_name.trim(),
        r.device.vendor.trim(),
        r.device.compute_units,
        r.device.max_clock_mhz,
        r.device.global_mem_size / (1024 * 1024)
    ));
    s.push_str(&format!(
        "launch batch={} iters={} warmup={} timed={} local={:?}\n",
        r.batch, r.iters, r.warmup, r.timed, r.local
    ));
    if let Some(p) = &r.prod_pbkdf2 {
        s.push_str(&format!(
            "prod bench_pbkdf2  median={:.1} ns/seed  min={:.1} max={:.1} stdev={:.1}  regs={:?} spills={:?}/{:?}\n",
            p.median_ns, p.min_ns, p.max_ns, p.stdev_ns, p.nv.registers, p.nv.spill_store, p.nv.spill_load
        ));
    } else {
        s.push_str("prod bench_pbkdf2  skipped\n");
    }
    for v in &r.variants {
        s.push_str(&format!(
            "{:<24}  median={:7.1} ns/seed  min={:.1} max={:.1} stdev={:.1}  exact={} ({})  regs={:?} occ={:?}%  ptx shf={} iadd3={} lop3={} shr.b64={} shl.b64={}\n",
            v.name,
            v.median_ns,
            v.min_ns,
            v.max_ns,
            v.stdev_ns,
            v.exact,
            v.exact_checked,
            v.nv.registers,
            v.occupancy_pct.map(|p| format!("{p:.0}")),
            v.ptx.shf,
            v.ptx.iadd3,
            v.ptx.lop3,
            v.ptx.shr_b64,
            v.ptx.shl_b64
        ));
    }
    if let (Some(base), Some(best)) = (
        r.variants.first(),
        r.variants
            .iter()
            .min_by(|a, b| a.median_ns.partial_cmp(&b.median_ns).unwrap()),
    ) {
        let speedup = base.median_ns / best.median_ns;
        s.push_str(&format!(
            "best={}  speedup vs prod_rotate_generic={:.3}x ({:.1}%)\n",
            best.name,
            speedup,
            (speedup - 1.0) * 100.0
        ));
    }
    s.push_str(&format!(
        "=== DECISION ===\nrecommendation={}\nreason={}\n",
        r.recommendation.as_str(),
        r.reason
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ptxas_regs_and_spills() {
        let log = "\
ptxas info    : Compiling entry function 'research_hmac64_loop' for 'sm_86'
ptxas info    : Used 56 registers, 0 bytes smem, 360 bytes cmem[0]
    16 bytes stack frame, 8 bytes spill stores, 8 bytes spill loads
";
        let nv = parse_nv_resources(log);
        assert_eq!(nv.registers, Some(56));
        assert_eq!(nv.smem, Some(0));
        assert_eq!(nv.stack_frame, Some(16));
        assert_eq!(nv.spill_store, Some(8));
        assert_eq!(nv.spill_load, Some(8));
    }

    #[test]
    fn scans_ptx_tokens() {
        let ptx = b".version 7.8\nshf.r.clamp.b32 r1, r2, r3, 14;\nlop3.b32 r4, r5, r6, r7, 0xCA;\nshr.b64 rd1, rd2, 7;\n";
        let m = scan_ptx_mix(ptx);
        assert!(m.has_ptx);
        assert_eq!(m.shf, 1);
        assert_eq!(m.lop3, 1);
        assert_eq!(m.shr_b64, 1);
        assert!(!m.looks_like_shf_floor());
    }

    #[test]
    fn occupancy_tracks_reg_pressure() {
        let (w56, p56) = occupancy_from_regs(56);
        let (w128, p128) = occupancy_from_regs(128);
        assert!(w56 > w128);
        assert!(p56 > p128);
        assert!(p56 <= 100.0);
    }

    #[test]
    fn recommend_implement_on_ten_percent() {
        let mk = |variant: u32, name: &'static str, ns: f64| VariantResult {
            name,
            variant,
            build_log: String::new(),
            samples_ns: vec![ns],
            median_ns: ns,
            min_ns: ns,
            max_ns: ns,
            stdev_ns: 0.0,
            runs: 1,
            exact: true,
            exact_checked: 8,
            nv: NvResources::default(),
            ptx: PtxMix::default(),
            work_group_size: None,
            preferred_wg_multiple: None,
            private_mem: None,
            occupancy_warps: None,
            occupancy_pct: None,
        };
        let (rec, _) = recommend(&[
            mk(0, "prod_rotate_generic", 1600.0),
            mk(1, "shf_rotate_generic", 1400.0),
            mk(2, "shf_bitselect_hmac64", 1550.0),
        ]);
        assert_eq!(rec, Recommendation::Implement);
    }

    #[test]
    fn recommend_stop_when_floor_and_tied() {
        let ptx = PtxMix {
            shf: 10,
            iadd3: 0,
            lop3: 4,
            shr_b64: 0,
            shl_b64: 0,
            or_b64: 0,
            has_ptx: true,
        };
        let mk = |variant: u32, name: &'static str| VariantResult {
            name,
            variant,
            build_log: "ptxas info : Used 48 registers".into(),
            samples_ns: vec![1600.0],
            median_ns: 1600.0,
            min_ns: 1600.0,
            max_ns: 1600.0,
            stdev_ns: 0.0,
            runs: 1,
            exact: true,
            exact_checked: 8,
            nv: NvResources {
                registers: Some(48),
                ..NvResources::default()
            },
            ptx: ptx.clone(),
            work_group_size: None,
            preferred_wg_multiple: None,
            private_mem: None,
            occupancy_warps: None,
            occupancy_pct: None,
        };
        let (rec, reason) = recommend(&[
            mk(0, "prod_rotate_generic"),
            mk(1, "shf_rotate_generic"),
            mk(2, "shf_bitselect_hmac64"),
        ]);
        assert_eq!(rec, Recommendation::Stop, "{reason}");
    }

    #[test]
    fn recommend_continue_without_floor_evidence() {
        let mk = |variant: u32, name: &'static str| VariantResult {
            name,
            variant,
            build_log: String::new(),
            samples_ns: vec![1600.0],
            median_ns: 1600.0,
            max_ns: 1600.0,
            min_ns: 1600.0,
            stdev_ns: 0.0,
            runs: 1,
            exact: true,
            exact_checked: 8,
            nv: NvResources::default(),
            ptx: PtxMix::default(),
            work_group_size: None,
            preferred_wg_multiple: None,
            private_mem: None,
            occupancy_warps: None,
            occupancy_pct: None,
        };
        let (rec, _) = recommend(&[
            mk(0, "prod_rotate_generic"),
            mk(1, "shf_rotate_generic"),
            mk(2, "shf_bitselect_hmac64"),
        ]);
        assert_eq!(rec, Recommendation::Continue);
    }
}
