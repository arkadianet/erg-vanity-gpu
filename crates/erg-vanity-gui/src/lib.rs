//! Desktop UI for vanity search.

use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, RichText, Stroke};
use erg_vanity_cpu::MatchType;
use erg_vanity_engine::{
    estimate_pattern, format_time, list_gpu_devices, run_search, Backend, Hit, SearchEvent,
    SearchRequest, CPU_ASSUMED_RATE, GPU_ASSUMED_RATE,
};
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BG: Color32 = Color32::from_rgb(14, 12, 10);
const PANEL: Color32 = Color32::from_rgb(22, 18, 14);
const CREAM: Color32 = Color32::from_rgb(236, 220, 188);
const DIM: Color32 = Color32::from_rgb(140, 124, 100);
const AMBER: Color32 = Color32::from_rgb(232, 148, 42);
const LIVE: Color32 = Color32::from_rgb(72, 196, 120);
const WARN: Color32 = Color32::from_rgb(196, 140, 64);
const ERR: Color32 = Color32::from_rgb(208, 88, 64);

const COMPILE_HINT: &str = "Compiling OpenCL (first run after a kernel change can take a minute)…";

/// Launch the native window.
pub fn run() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([920.0, 600.0])
            .with_title("erg-vanity"),
        ..Default::default()
    };
    eframe::run_native(
        "erg-vanity",
        options,
        Box::new(|cc| Ok(Box::new(VanityApp::new(cc)))),
    )
}

struct GuiHit {
    hit: Hit,
    pattern: String,
    revealed: bool,
}

struct VanityApp {
    patterns: String,
    match_mode: usize,
    ignore_case: bool,
    num_indices: u32,
    max_results: usize,
    devices: String,
    batch_size: String,
    status: String,
    estimate_text: String,
    running: bool,
    stopping: bool,
    checked: u64,
    rate: f64,
    found: usize,
    results: Vec<GuiHit>,
    search_patterns: Vec<String>,
    stop: Option<Arc<AtomicBool>>,
    rx: Option<Receiver<SearchEvent>>,
    worker: Option<JoinHandle<()>>,
    devices_hint: String,
    gpu_present: bool,
    started_at: Option<Instant>,
    elapsed: Duration,
    rate_hist: VecDeque<f32>,
    had_error: bool,
    secret_notice: Option<(String, Instant)>,
    save_draft: Option<SaveDraft>,
}

struct SaveDraft {
    address: String,
    pattern: String,
    mnemonic: String,
    address_index: u32,
    dest: String,
}

impl VanityApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(CREAM);
        visuals.widgets.noninteractive.bg_fill = PANEL;
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(32, 26, 20);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(48, 36, 24);
        visuals.widgets.active.bg_fill = Color32::from_rgb(56, 40, 22);
        visuals.selection.bg_fill = Color32::from_rgb(92, 56, 16);
        visuals.panel_fill = BG;
        visuals.window_fill = BG;
        visuals.extreme_bg_color = Color32::from_rgb(10, 9, 8);
        visuals.faint_bg_color = PANEL;
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, DIM);
        cc.egui_ctx.set_visuals(visuals);

        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        cc.egui_ctx.set_style(style);

        let (gpu_present, devices_hint) = match list_gpu_devices() {
            Ok(list) if list.is_empty() => (
                false,
                "No OpenCL GPU — prefix search falls back to CPU.".into(),
            ),
            Ok(list) => (true, list.join("  ·  ")),
            Err(e) => (false, format!("OpenCL: {e}")),
        };

        Self {
            patterns: "9err".into(),
            match_mode: 0,
            ignore_case: false,
            num_indices: 1,
            max_results: 1,
            devices: "auto".into(),
            batch_size: String::new(),
            status: "Idle — Start searches the default 9err prefix.".into(),
            estimate_text: String::new(),
            running: false,
            stopping: false,
            checked: 0,
            rate: 0.0,
            found: 0,
            results: Vec::new(),
            search_patterns: Vec::new(),
            stop: None,
            rx: None,
            worker: None,
            devices_hint,
            gpu_present,
            started_at: None,
            elapsed: Duration::ZERO,
            rate_hist: VecDeque::with_capacity(48),
            had_error: false,
            secret_notice: None,
            save_draft: None,
        }
    }

    fn match_type(&self) -> MatchType {
        match self.match_mode {
            1 => MatchType::Suffix,
            2 => MatchType::Contains,
            _ => MatchType::Prefix,
        }
    }

    fn backend(&self) -> Result<Backend, String> {
        let n = self.devices.trim().to_ascii_lowercase();
        if n.is_empty() || n == "auto" {
            return Ok(Backend::Auto);
        }
        if n == "cpu" {
            return Ok(Backend::Cpu);
        }
        if n == "all" {
            return Ok(Backend::Gpu {
                devices: Vec::new(),
            });
        }
        let mut parsed = Vec::new();
        for part in self.devices.split(',') {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            parsed.push(
                t.parse::<usize>()
                    .map_err(|_| format!("invalid device '{t}'"))?,
            );
        }
        if parsed.is_empty() {
            return Ok(Backend::Auto);
        }
        Ok(Backend::Gpu { devices: parsed })
    }

    fn uses_gpu(&self) -> bool {
        if !matches!(self.match_type(), MatchType::Prefix) {
            return false;
        }
        if !self.gpu_present {
            return false;
        }
        !matches!(self.backend(), Ok(Backend::Cpu))
    }

    fn assumed_rate(&self) -> f64 {
        if self.uses_gpu() {
            GPU_ASSUMED_RATE
        } else {
            CPU_ASSUMED_RATE
        }
    }

    fn display_rate(&self) -> f64 {
        if self.running && self.rate >= 1.0 {
            self.rate
        } else {
            self.assumed_rate()
        }
    }

    fn engine_label(&self) -> String {
        match self.match_type() {
            MatchType::Suffix => "CPU · suffix".into(),
            MatchType::Contains => "CPU · contains".into(),
            MatchType::Prefix if self.uses_gpu() => match self.backend() {
                Ok(Backend::Gpu { devices }) if !devices.is_empty() => {
                    format!("GPU · {}", self.devices.trim())
                }
                Ok(Backend::Gpu { .. }) => "GPU · all".into(),
                _ => "GPU · auto".into(),
            },
            MatchType::Prefix => "CPU · prefix".into(),
        }
    }

    fn pattern_list(&self) -> Vec<String> {
        self.patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn pattern_issue(&self) -> Option<String> {
        let patterns = self.pattern_list();
        if patterns.is_empty() {
            return Some("Enter a Base58 pattern (example: 9err).".into());
        }
        if let Err(e) = self.backend() {
            return Some(e);
        }
        if let Err(e) = self.parse_batch_size() {
            return Some(e);
        }
        let req = SearchRequest {
            patterns,
            match_type: self.match_type(),
            ignore_case: self.ignore_case,
            max_results: self.max_results.max(1),
            num_indices: self.num_indices.max(1),
            duration: None,
            backend: Backend::Auto,
            batch_size: None,
        };
        req.validate().err()
    }

    fn refresh_estimate(&mut self) {
        let mt = self.match_type();
        let rate = self.display_rate();
        let rate_note = if self.running && self.rate >= 1.0 {
            format!("{:.0}/s live", self.rate)
        } else if self.uses_gpu() {
            format!("{:.0}k/s assumed GPU", GPU_ASSUMED_RATE / 1000.0)
        } else {
            format!("{:.0}k/s assumed CPU", CPU_ASSUMED_RATE / 1000.0)
        };
        let mut lines = Vec::new();
        for p in self.pattern_list() {
            let est = estimate_pattern(&p, mt, self.ignore_case);
            if est.has_invalid_chars {
                let bad: String = est.invalid_chars.iter().collect();
                lines.push(format!("{p}: impossible (not Base58: {bad})"));
            } else {
                let left = if self.running {
                    (est.attempts_needed - self.checked as f64).max(0.0)
                } else {
                    est.attempts_needed
                };
                lines.push(format!(
                    "{p}: ~{:.0} attempts · {} ({rate_note})",
                    est.attempts_needed,
                    format_time(left / rate.max(1.0))
                ));
            }
        }
        if let Some(issue) = self.pattern_issue() {
            if lines.is_empty() {
                lines.push(issue);
            }
        }
        self.estimate_text = lines.join("\n");
    }

    fn easiest_attempts(&self) -> Option<f64> {
        let mt = self.match_type();
        let mut best = f64::INFINITY;
        for p in self.pattern_list() {
            let est = estimate_pattern(&p, mt, self.ignore_case);
            if !est.has_invalid_chars && est.attempts_needed < best {
                best = est.attempts_needed;
            }
        }
        if best.is_finite() {
            Some(best)
        } else {
            None
        }
    }

    fn eta_label(&self) -> String {
        if self.pattern_issue().is_some() {
            return "—".into();
        }
        let Some(attempts) = self.easiest_attempts() else {
            return "—".into();
        };
        let remaining = if self.running {
            (attempts - self.checked as f64).max(0.0)
        } else {
            attempts
        };
        format!("~{}", format_time(remaining / self.display_rate().max(1.0)))
    }

    fn hard_pattern_warning(&self) -> Option<String> {
        if self.pattern_issue().is_some() {
            return None;
        }
        let attempts = self.easiest_attempts()?;
        let secs = attempts / self.assumed_rate().max(1.0);
        if secs >= 86_400.0 {
            Some("This pattern is likely days or longer. Shorten it or expect a long run.".into())
        } else if secs >= 3_600.0 {
            Some("This pattern is likely an hour or more at typical rates.".into())
        } else {
            None
        }
    }

    fn parse_batch_size(&self) -> Result<Option<usize>, String> {
        let trimmed = self.batch_size.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let n: usize = trimmed
            .parse()
            .map_err(|_| format!("invalid batch size '{trimmed}'"))?;
        if n == 0 {
            return Err("batch size must be at least 1".into());
        }
        Ok(Some(n))
    }

    fn is_compiling(&self) -> bool {
        self.running
            && !self.stopping
            && self.checked == 0
            && self.uses_gpu()
            && self
                .started_at
                .is_some_and(|t| t.elapsed() >= Duration::from_millis(300))
    }

    fn refresh_run_status(&mut self) {
        if self.had_error || self.stopping || !self.running {
            return;
        }
        if self.is_compiling() {
            self.status = COMPILE_HINT.into();
        } else if self.status == COMPILE_HINT {
            self.status = format!("Searching · {}", self.engine_label());
        }
    }

    fn start(&mut self) {
        if self.running || self.stopping {
            return;
        }
        let patterns = self.pattern_list();
        let backend = match self.backend() {
            Ok(b) => b,
            Err(e) => {
                self.status = e;
                self.had_error = true;
                return;
            }
        };
        let batch_size = match self.parse_batch_size() {
            Ok(b) => b,
            Err(e) => {
                self.status = e;
                self.had_error = true;
                return;
            }
        };
        let req = SearchRequest {
            patterns: patterns.clone(),
            match_type: self.match_type(),
            ignore_case: self.ignore_case,
            max_results: self.max_results.max(1),
            num_indices: self.num_indices.max(1),
            duration: None,
            backend,
            batch_size,
        };
        if let Err(e) = req.validate() {
            self.status = e;
            self.had_error = true;
            return;
        }
        self.refresh_estimate();
        self.results.clear();
        self.search_patterns = patterns;
        self.found = 0;
        self.checked = 0;
        self.rate = 0.0;
        self.rate_hist.clear();
        self.had_error = false;
        self.stopping = false;
        self.status = format!("Searching · {}", self.engine_label());
        let now = Instant::now();
        self.started_at = Some(now);
        self.elapsed = Duration::ZERO;
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let stop_t = Arc::clone(&stop);
        let handle = std::thread::spawn(move || run_search(req, tx, stop_t));
        self.stop = Some(stop);
        self.rx = Some(rx);
        self.worker = Some(handle);
        self.running = true;
    }

    fn stop_search(&mut self) {
        if !self.running || self.stopping {
            return;
        }
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Relaxed);
        }
        self.stopping = true;
        self.status = "Stopping…".into();
    }

    fn finish(&mut self) {
        self.running = false;
        self.stopping = false;
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        self.stop = None;
        self.rx = None;
    }

    fn poll(&mut self) {
        let Some(rx) = self.rx.take() else {
            return;
        };
        while let Ok(ev) = rx.try_recv() {
            match ev {
                SearchEvent::Progress {
                    checked,
                    rate,
                    found,
                } => {
                    self.checked = checked;
                    self.rate = rate;
                    self.found = found;
                    self.rate_hist.push_back(rate as f32);
                    if self.rate_hist.len() > 48 {
                        self.rate_hist.pop_front();
                    }
                }
                SearchEvent::Hit(hit) => {
                    let pattern = self
                        .search_patterns
                        .get(hit.pattern_index as usize)
                        .cloned()
                        .unwrap_or_else(|| "—".into());
                    self.results.push(GuiHit {
                        hit,
                        pattern,
                        revealed: false,
                    });
                    self.found = self.results.len();
                }
                SearchEvent::Dropped { count, reason } => {
                    self.status =
                        reason.unwrap_or_else(|| format!("Dropped {count} overflow hits"));
                }
                SearchEvent::Error { message } => {
                    self.status = message;
                    self.had_error = true;
                }
                SearchEvent::Done {
                    checked,
                    found,
                    elapsed,
                } => {
                    self.checked = checked;
                    self.found = found;
                    self.elapsed = elapsed;
                    if !self.had_error {
                        let verb = if self.stopping { "Stopped" } else { "Done" };
                        self.status = format!("{verb} in {}", format_elapsed(elapsed));
                    }
                    self.running = false;
                    self.stopping = false;
                }
            }
        }
        let worker_done = self.worker.as_ref().is_some_and(|h| h.is_finished());
        if self.running && !worker_done {
            self.rx = Some(rx);
            return;
        }
        self.finish();
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let (escape, ctrl_enter) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::Escape),
                i.modifiers.command && i.key_pressed(egui::Key::Enter),
            )
        });
        if escape && self.running {
            self.stop_search();
        }
        if ctrl_enter && !self.running {
            self.start();
        }
    }
}

impl eframe::App for VanityApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.running {
            if let Some(start) = self.started_at {
                self.elapsed = start.elapsed();
            }
            ctx.request_repaint_after(Duration::from_millis(33));
        }
        self.refresh_run_status();
        self.refresh_estimate();
        self.handle_shortcuts(ctx);
        if let Some((_, t)) = self.secret_notice {
            if t.elapsed() > Duration::from_secs(8) {
                self.secret_notice = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }

        let issue = self.pattern_issue();
        let hard = self.hard_pattern_warning();
        let compiling = self.is_compiling();
        let locked = self.running;
        let status_color = if self.had_error {
            ERR
        } else if self.stopping || compiling {
            WARN
        } else {
            CREAM
        };

        egui::TopBottomPanel::top("masthead")
            .exact_height(52.0)
            .frame(
                egui::Frame::NONE
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(RichText::new("ERG-VANITY").color(AMBER).size(18.0).strong());
                    ui.add_space(10.0);
                    ui.label(RichText::new(self.engine_label()).color(DIM).size(12.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let pulse = if self.running && !self.stopping {
                            let t = self.elapsed.as_secs_f32();
                            0.35 + 0.65 * (t * 4.0).sin().abs()
                        } else {
                            0.15
                        };
                        let (dot, _) =
                            ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                        let live_color = if self.stopping {
                            WARN
                        } else if self.running {
                            LIVE.gamma_multiply(pulse)
                        } else {
                            DIM
                        };
                        ui.painter().circle_filled(dot.center(), 5.0, live_color);
                        let live_text = if self.stopping {
                            "STOPPING"
                        } else if self.running {
                            "LIVE"
                        } else {
                            "IDLE"
                        };
                        ui.label(
                            RichText::new(live_text)
                                .color(if self.stopping {
                                    WARN
                                } else if self.running {
                                    LIVE
                                } else {
                                    DIM
                                })
                                .size(12.0)
                                .strong(),
                        );
                        ui.add_space(12.0);
                        ui.label(RichText::new(&self.status).color(status_color).size(13.0));
                    });
                });
            });

        egui::TopBottomPanel::bottom("footer")
            .frame(
                egui::Frame::NONE
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ctx, |ui| {
                ui.label(RichText::new(&self.devices_hint).small().color(DIM));
                if let Some((notice, _)) = &self.secret_notice {
                    ui.label(RichText::new(notice).small().color(WARN));
                } else {
                    ui.label(
                        RichText::new(
                            "A match is a BIP39 wallet. Reveal only to copy. Verify in a trusted Ergo wallet before funding.",
                        )
                        .small()
                        .color(WARN),
                    );
                }
            });

        egui::SidePanel::left("settings")
            .resizable(false)
            .exact_width(320.0)
            .frame(
                egui::Frame::NONE
                    .fill(PANEL)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                ui.add_enabled_ui(!locked, |ui| {
                    ui.label(RichText::new("PATTERN").color(AMBER).size(11.0).strong());
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.patterns)
                            .desired_width(f32::INFINITY)
                            .hint_text("9err, 9ego")
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.label(
                        RichText::new("Comma-separated. Prefix must start 9e–9i (mainnet P2PK).")
                            .small()
                            .color(DIM),
                    );
                    if let Some(issue) = &issue {
                        ui.label(RichText::new(issue).small().color(ERR));
                    } else if let Some(hard) = &hard {
                        ui.label(RichText::new(hard).small().color(WARN));
                    }
                    ui.add_space(10.0);
                    ui.label(RichText::new("MATCH").color(AMBER).size(11.0).strong());
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.match_mode, 0, "Prefix")
                            .on_hover_text("GPU when OpenCL is available");
                        ui.selectable_value(&mut self.match_mode, 1, "Suffix")
                            .on_hover_text("CPU only");
                        ui.selectable_value(&mut self.match_mode, 2, "Contains")
                            .on_hover_text("CPU only");
                    });
                    ui.checkbox(&mut self.ignore_case, "Ignore case");
                    if !matches!(self.match_type(), MatchType::Prefix) {
                        ui.label(
                            RichText::new("Suffix and contains run on CPU only.")
                                .small()
                                .color(WARN),
                        );
                    } else if !self.gpu_present {
                        ui.label(
                            RichText::new("No GPU listed — prefix will use CPU.")
                                .small()
                                .color(WARN),
                        );
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new("INDICES / SEED").color(AMBER).size(11.0).strong());
                    ui.add(
                        egui::Slider::new(&mut self.num_indices, 1..=100)
                            .text("BIP44 slots")
                            .integer(),
                    )
                    .on_hover_text(
                        "How many receive addresses to derive from each mnemonic. Default 1. This is not a GPU count.",
                    );
                    let last = self.num_indices.saturating_sub(1);
                    let index_color = if self.num_indices > 1 { WARN } else { DIM };
                    ui.label(
                        RichText::new(format!("m/44'/429'/0'/0/{{0..{last}}}  ·  default 1"))
                            .small()
                            .color(index_color),
                    );
                    if self.num_indices > 1 {
                        ui.label(
                            RichText::new(
                                "Extra slots on the same seed. Raise only if you want those addresses.",
                            )
                            .small()
                            .color(WARN),
                        );
                    }
                    ui.add(egui::Slider::new(&mut self.max_results, 1..=20).text("max results"));
                    ui.add_space(8.0);
                    ui.label(RichText::new("DEVICES").color(AMBER).size(11.0).strong());
                    ui.label(RichText::new("auto · 0 · all · cpu").small().color(DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.devices)
                            .desired_width(f32::INFINITY)
                            .hint_text("auto"),
                    );
                    ui.label(RichText::new("BATCH").color(AMBER).size(11.0).strong());
                    ui.label(RichText::new("blank = device default").small().color(DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.batch_size)
                            .desired_width(f32::INFINITY)
                            .hint_text("device default"),
                    );
                });
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if !self.running {
                        let start = ui.add_enabled(
                            issue.is_none(),
                            egui::Button::new(RichText::new("Start").strong())
                                .min_size(egui::vec2(88.0, 32.0)),
                        );
                        if start.clicked() {
                            self.start();
                        }
                        if issue.is_some() {
                            start.on_hover_text("Fix the pattern or settings first");
                        } else {
                            start.on_hover_text("Ctrl+Enter");
                        }
                    } else {
                        let stop = ui.add_enabled(
                            !self.stopping,
                            egui::Button::new(RichText::new(if self.stopping {
                                "Stopping…"
                            } else {
                                "Stop"
                            })
                            .strong())
                            .min_size(egui::vec2(88.0, 32.0)),
                        );
                        if stop.clicked() {
                            self.stop_search();
                        }
                        stop.on_hover_text("Esc");
                    }
                });
                if !self.estimate_text.is_empty() {
                    ui.add_space(12.0);
                    ui.label(RichText::new("ESTIMATE").color(AMBER).size(11.0).strong());
                    ui.label(
                        RichText::new("Guess before/during search — not a timer guarantee.")
                            .small()
                            .color(DIM),
                    );
                    ui.label(RichText::new(&self.estimate_text).color(CREAM).small());
                }
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    stat_card(ui, "CHECKED", &format_count(self.checked), CREAM);
                    ui.add_space(8.0);
                    stat_card(
                        ui,
                        "RATE",
                        &if self.running && self.rate >= 1.0 {
                            format!("{:.0} /s", self.rate)
                        } else {
                            "—".into()
                        },
                        LIVE,
                    );
                    ui.add_space(8.0);
                    stat_card(ui, "ETA", &self.eta_label(), AMBER);
                    ui.add_space(8.0);
                    stat_card(ui, "ELAPSED", &format_elapsed(self.elapsed), AMBER);
                    ui.add_space(8.0);
                    stat_card(
                        ui,
                        "FOUND",
                        &format!("{}/{}", self.found, self.max_results.max(1)),
                        if self.found > 0 { LIVE } else { CREAM },
                    );
                });
                ui.add_space(10.0);
                draw_sparkline(ui, &self.rate_hist, self.running);
                ui.add_space(12.0);
                ui.label(RichText::new("HITS").color(AMBER).size(11.0).strong());
                ui.add_space(6.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    if self.results.is_empty() {
                        empty_hits(ui, self.running, compiling);
                    }
                    let mut copied = false;
                    let mut save_req: Option<(String, String, String, u32)> = None;
                    for (i, row) in self.results.iter_mut().enumerate() {
                        egui::Frame::NONE
                            .fill(PANEL)
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!("#{:02}", i + 1))
                                            .color(AMBER)
                                            .strong(),
                                    );
                                    ui.label(
                                        RichText::new(&row.pattern).color(AMBER).small().strong(),
                                    );
                                });
                                ui.label(
                                    RichText::new(&row.hit.address)
                                        .monospace()
                                        .color(CREAM)
                                        .size(15.0),
                                );
                                ui.label(
                                    RichText::new(format!(
                                        "{}  ·  m/44'/429'/0'/0/{}",
                                        row.hit.device_label, row.hit.address_index
                                    ))
                                    .small()
                                    .color(DIM),
                                );
                                ui.label(
                                    RichText::new("Verified (ergo-lib)")
                                        .small()
                                        .color(LIVE),
                                );
                                ui.label(
                                    RichText::new(format!(
                                        "Restore: 24 words, account 0, address index {}. Send dust and confirm before funding.",
                                        row.hit.address_index
                                    ))
                                    .small()
                                    .color(DIM),
                                );
                                ui.horizontal(|ui| {
                                    if row.revealed {
                                        ui.label(
                                            RichText::new("24-word spend key — do not screenshot")
                                                .small()
                                                .color(WARN),
                                        );
                                    }
                                });
                                if row.revealed {
                                    ui.label(
                                        RichText::new(&row.hit.mnemonic)
                                            .monospace()
                                            .small()
                                            .color(CREAM),
                                    );
                                }
                                ui.horizontal(|ui| {
                                    if row.revealed {
                                        if ui.button("Hide").clicked() {
                                            row.revealed = false;
                                        }
                                        if ui.button("Copy mnemonic").clicked() {
                                            ui.ctx().copy_text(row.hit.mnemonic.clone());
                                            copied = true;
                                        }
                                    } else if ui
                                        .button("Reveal mnemonic")
                                        .on_hover_text("Shows the 24-word spend key")
                                        .clicked()
                                    {
                                        row.revealed = true;
                                    }
                                    if ui.button("Copy address").clicked() {
                                        ui.ctx().copy_text(row.hit.address.clone());
                                    }
                                    if ui
                                        .button("Save")
                                        .on_hover_text(
                                            "Write address, path, pattern, and mnemonic to a file you choose",
                                        )
                                        .clicked()
                                    {
                                        save_req = Some((
                                            row.hit.address.clone(),
                                            row.pattern.clone(),
                                            row.hit.mnemonic.clone(),
                                            row.hit.address_index,
                                        ));
                                    }
                                });
                            });
                        ui.add_space(8.0);
                    }
                    if copied {
                        self.secret_notice = Some((
                            "Mnemonic is on the clipboard until you overwrite it.".into(),
                            Instant::now(),
                        ));
                    }
                    if let Some((address, pattern, mnemonic, index)) = save_req {
                        self.save_draft = Some(SaveDraft {
                            dest: suggested_save_path(&address),
                            address,
                            pattern,
                            mnemonic,
                            address_index: index,
                        });
                    }
                });
            });

        self.draw_save_dialog(ctx);
    }
}

impl VanityApp {
    fn draw_save_dialog(&mut self, ctx: &egui::Context) {
        let Some(draft) = self.save_draft.as_mut() else {
            return;
        };
        let mut open = true;
        let mut write = false;
        let mut cancel = false;
        egui::Window::new("Save hit")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label(
                    RichText::new("This file can spend funds. Choose where to write it.")
                        .color(WARN)
                        .small(),
                );
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(&mut draft.dest)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Write").strong())
                                .min_size(egui::vec2(72.0, 28.0)),
                        )
                        .clicked()
                    {
                        write = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if !open || cancel {
            self.save_draft = None;
            return;
        }
        if !write {
            return;
        }
        let Some(draft) = self.save_draft.take() else {
            return;
        };
        let dest = PathBuf::from(draft.dest.trim());
        if dest.as_os_str().is_empty() {
            self.secret_notice = Some(("Save needs a file path.".into(), Instant::now()));
            return;
        }
        match write_hit_file(
            &dest,
            &draft.address,
            &draft.pattern,
            &draft.mnemonic,
            draft.address_index,
        ) {
            Ok(acl_ok) => {
                let extra = if acl_ok && cfg!(windows) {
                    "ACL limited to your Windows user."
                } else if acl_ok {
                    "File mode set to 600."
                } else {
                    "Restrict that file yourself — it can spend funds."
                };
                self.secret_notice =
                    Some((format!("Saved {}. {extra}", dest.display()), Instant::now()));
            }
            Err(e) => {
                self.secret_notice = Some((format!("Save failed: {e}"), Instant::now()));
            }
        }
    }
}

fn empty_hits(ui: &mut egui::Ui, running: bool, compiling: bool) {
    if compiling {
        ui.label(RichText::new(COMPILE_HINT).color(WARN));
        return;
    }
    if running {
        ui.label(RichText::new("Listening for matches…").color(DIM));
        return;
    }
    ui.label(RichText::new("No matches yet.").color(DIM).size(14.0));
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "Prefix 9e–9i uses the GPU when OpenCL is available. Suffix and contains are CPU-only.",
        )
        .color(DIM),
    );
    ui.label(
        RichText::new(
            "Start runs a search. Estimate updates as you type. A hit is a wallet — leave the mnemonic hidden until you need it.",
        )
        .color(DIM),
    );
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, value_color: Color32) {
    egui::Frame::NONE
        .fill(PANEL)
        .inner_margin(egui::Margin::symmetric(10, 10))
        .show(ui, |ui| {
            ui.set_min_width(118.0);
            ui.label(RichText::new(label).color(DIM).size(10.0).strong());
            ui.label(RichText::new(value).color(value_color).size(20.0).strong());
        });
}

fn draw_sparkline(ui: &mut egui::Ui, hist: &VecDeque<f32>, running: bool) {
    let height = 56.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, PANEL);
    painter.rect_stroke(
        rect,
        0.0,
        Stroke::new(1.0_f32, Color32::from_rgb(40, 32, 24)),
        egui::StrokeKind::Inside,
    );
    painter.text(
        rect.left_top() + egui::vec2(10.0, 6.0),
        egui::Align2::LEFT_TOP,
        "ADDR / S",
        egui::FontId::proportional(10.0),
        DIM,
    );
    if hist.len() < 2 {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            if running {
                "waiting for samples…"
            } else {
                "rate history appears while searching"
            },
            egui::FontId::proportional(12.0),
            DIM,
        );
        return;
    }
    let max = hist.iter().copied().fold(1.0f32, f32::max);
    let n = (hist.len() - 1) as f32;
    let inset = rect.shrink2(egui::vec2(8.0, 16.0));
    let mut points: Vec<egui::Pos2> = hist
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = inset.left() + inset.width() * (i as f32 / n);
            let y = inset.bottom() - inset.height() * (*v / max);
            egui::pos2(x, y)
        })
        .collect();
    painter.add(egui::Shape::line(
        points.split_off(0),
        Stroke::new(1.6_f32, AMBER),
    ));
}

fn format_hit_file(address: &str, path: &str, pattern: &str, mnemonic: &str) -> String {
    format!("Address:  {address}\nPath:     {path}\nPattern:  {pattern}\nMnemonic: {mnemonic}\n")
}

fn suggested_save_path(address: &str) -> String {
    let prefix: String = address.chars().take(8).collect();
    let name = format!("erg-vanity-{prefix}.txt");
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    let docs = PathBuf::from(&home).join("Documents").join(&name);
    if docs.parent().is_some_and(|p| p.is_dir()) {
        docs.to_string_lossy().into_owned()
    } else {
        PathBuf::from(home)
            .join(name)
            .to_string_lossy()
            .into_owned()
    }
}

fn write_hit_file(
    dest: &Path,
    address: &str,
    pattern: &str,
    mnemonic: &str,
    address_index: u32,
) -> Result<bool, String> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let bip44 = format!("m/44'/429'/0'/0/{address_index}");
    let body = format_hit_file(address, &bip44, pattern, mnemonic);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(dest).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{} already exists — pick another path", dest.display())
        } else {
            e.to_string()
        }
    })?;
    f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    f.flush().map_err(|e| e.to_string())?;
    Ok(restrict_owner_acl(dest))
}

fn restrict_owner_acl(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let user = match (
            std::env::var("USERDOMAIN").ok().filter(|s| !s.is_empty()),
            std::env::var("USERNAME").ok().filter(|s| !s.is_empty()),
        ) {
            (Some(domain), Some(name)) => format!("{domain}\\{name}"),
            (_, Some(name)) => name,
            _ => return false,
        };
        std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{user}:(R,W)"))
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).is_ok()
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        false
    }
}

fn format_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn format_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m}:{sec:02}")
    }
}

fn install_fonts(ctx: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\cascadia.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ];
    for path in candidates {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let mut fonts = FontDefinitions::default();
        fonts
            .font_data
            .insert("mono".into(), FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "mono".into());
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "mono".into());
        ctx.set_fonts(fonts);
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_count_groups_thousands() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_234), "1,234");
        assert_eq!(format_count(1_000_000), "1,000,000");
    }

    #[test]
    fn format_elapsed_hms() {
        assert_eq!(format_elapsed(Duration::from_secs(5)), "0:05");
        assert_eq!(format_elapsed(Duration::from_secs(83)), "1:23");
        assert_eq!(format_elapsed(Duration::from_secs(3723)), "1:02:03");
    }

    #[test]
    fn hit_file_has_wallet_fields() {
        let text = format_hit_file(
            "9errExampleAddress",
            "m/44'/429'/0'/0/3",
            "9err",
            "abandon abandon about",
        );
        assert!(text.contains("Address:  9errExampleAddress"));
        assert!(text.contains("Path:     m/44'/429'/0'/0/3"));
        assert!(text.contains("Pattern:  9err"));
        assert!(text.contains("Mnemonic: abandon abandon about"));
    }

    #[test]
    fn write_hit_file_roundtrip() {
        let dest = std::env::temp_dir().join(format!(
            "erg-vanity-gui-hit-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&dest);
        write_hit_file(&dest, "9errAddr", "9err", "abandon abandon about", 2).unwrap();
        let text = std::fs::read_to_string(&dest).expect("read saved hit");
        let _ = std::fs::remove_file(&dest);
        assert!(text.contains("Address:  9errAddr"));
        assert!(text.contains("Path:     m/44'/429'/0'/0/2"));
        assert!(text.contains("Pattern:  9err"));
        assert!(text.contains("Mnemonic: abandon abandon about"));
    }
}
