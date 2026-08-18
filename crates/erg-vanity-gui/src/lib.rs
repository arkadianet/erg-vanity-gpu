//! Desktop UI for vanity search.

use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, RichText, Stroke};
use erg_vanity_cpu::MatchType;
use erg_vanity_engine::{
    estimate_pattern, format_time, list_gpu_devices, run_search, Backend, Hit, SearchEvent,
    SearchRequest,
};
use std::collections::VecDeque;
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

/// Launch the native window.
pub fn run() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 700.0])
            .with_min_inner_size([880.0, 560.0])
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
    checked: u64,
    rate: f64,
    found: usize,
    results: Vec<GuiHit>,
    stop: Option<Arc<AtomicBool>>,
    rx: Option<Receiver<SearchEvent>>,
    worker: Option<JoinHandle<()>>,
    devices_hint: String,
    started_at: Option<Instant>,
    elapsed: Duration,
    rate_hist: VecDeque<f32>,
    had_error: bool,
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
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, DIM);
        cc.egui_ctx.set_visuals(visuals);

        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        cc.egui_ctx.set_style(style);

        let devices_hint = match list_gpu_devices() {
            Ok(list) if list.is_empty() => {
                "No OpenCL GPU — prefix search falls back to CPU.".into()
            }
            Ok(list) => list.join("  ·  "),
            Err(e) => format!("OpenCL: {e}"),
        };

        Self {
            patterns: "9err".into(),
            match_mode: 0,
            ignore_case: false,
            num_indices: 1,
            max_results: 1,
            devices: "auto".into(),
            batch_size: String::new(),
            status: "Idle".into(),
            estimate_text: String::new(),
            running: false,
            checked: 0,
            rate: 0.0,
            found: 0,
            results: Vec::new(),
            stop: None,
            rx: None,
            worker: None,
            devices_hint,
            started_at: None,
            elapsed: Duration::ZERO,
            rate_hist: VecDeque::with_capacity(48),
            had_error: false,
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

    fn refresh_estimate(&mut self) {
        let mt = self.match_type();
        let mut lines = Vec::new();
        for p in self.pattern_list() {
            let est = estimate_pattern(&p, mt, self.ignore_case);
            if est.has_invalid_chars {
                lines.push(format!("{p}: impossible (invalid Base58)"));
            } else {
                lines.push(format!(
                    "{p}: ~{:.0} attempts · {}",
                    est.attempts_needed,
                    format_time(est.attempts_needed / 330_000.0)
                ));
            }
        }
        self.estimate_text = lines.join("\n");
    }

    fn pattern_list(&self) -> Vec<String> {
        self.patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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

    fn start(&mut self) {
        if self.running {
            return;
        }
        let patterns = self.pattern_list();
        let backend = match self.backend() {
            Ok(b) => b,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let batch_size = match self.parse_batch_size() {
            Ok(b) => b,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let req = SearchRequest {
            patterns,
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
            return;
        }
        self.refresh_estimate();
        self.results.clear();
        self.found = 0;
        self.checked = 0;
        self.rate = 0.0;
        self.rate_hist.clear();
        self.had_error = false;
        self.status = "Searching".into();
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
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Relaxed);
        }
    }

    fn finish(&mut self) {
        self.running = false;
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        self.stop = None;
        self.rx = None;
        if let Some(start) = self.started_at {
            self.elapsed = start.elapsed();
        }
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
                    self.results.push(GuiHit {
                        hit,
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
                        self.status = format!("Done in {:.1}s", elapsed.as_secs_f64());
                    }
                    self.running = false;
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
                    ui.label(RichText::new("  /  miner").color(DIM).size(14.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let pulse = if self.running {
                            let t = self.elapsed.as_secs_f32();
                            0.35 + 0.65 * (t * 4.0).sin().abs()
                        } else {
                            0.15
                        };
                        let (dot, _) =
                            ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                        ui.painter().circle_filled(
                            dot.center(),
                            5.0,
                            if self.running {
                                LIVE.gamma_multiply(pulse)
                            } else {
                                DIM
                            },
                        );
                        ui.label(
                            RichText::new(if self.running { "LIVE" } else { "IDLE" })
                                .color(if self.running { LIVE } else { DIM })
                                .size(12.0)
                                .strong(),
                        );
                        ui.add_space(12.0);
                        ui.label(RichText::new(&self.status).color(CREAM).size(13.0));
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
                ui.label(
                    RichText::new("Mnemonics can spend funds. Verify in a trusted Ergo wallet.")
                        .small()
                        .color(WARN),
                );
            });

        egui::SidePanel::left("settings")
            .resizable(false)
            .exact_width(300.0)
            .frame(
                egui::Frame::NONE
                    .fill(PANEL)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                ui.label(RichText::new("PATTERN").color(AMBER).size(11.0).strong());
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.patterns).desired_width(f32::INFINITY));
                ui.add_space(10.0);
                ui.label(RichText::new("MATCH").color(AMBER).size(11.0).strong());
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.match_mode, 0, "Prefix");
                    ui.selectable_value(&mut self.match_mode, 1, "Suffix");
                    ui.selectable_value(&mut self.match_mode, 2, "Contains");
                });
                ui.checkbox(&mut self.ignore_case, "Ignore case");
                ui.add_space(8.0);
                ui.add(egui::Slider::new(&mut self.num_indices, 1..=100).text("indices / seed"));
                ui.add(egui::Slider::new(&mut self.max_results, 1..=20).text("max results"));
                ui.add_space(8.0);
                ui.label(RichText::new("DEVICES").color(AMBER).size(11.0).strong());
                ui.label(RichText::new("auto · 0 · all · cpu").small().color(DIM));
                ui.add(egui::TextEdit::singleline(&mut self.devices).desired_width(f32::INFINITY));
                ui.label(RichText::new("BATCH").color(AMBER).size(11.0).strong());
                ui.label(RichText::new("blank = device default").small().color(DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut self.batch_size).desired_width(f32::INFINITY),
                );
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if !self.running {
                        if ui
                            .add_sized(
                                [88.0, 32.0],
                                egui::Button::new(RichText::new("Start").strong()),
                            )
                            .clicked()
                        {
                            self.start();
                        }
                    } else if ui
                        .add_sized(
                            [88.0, 32.0],
                            egui::Button::new(RichText::new("Stop").strong()),
                        )
                        .clicked()
                    {
                        self.stop_search();
                    }
                    if ui
                        .add_sized([88.0, 32.0], egui::Button::new("Estimate"))
                        .clicked()
                    {
                        self.refresh_estimate();
                    }
                });
                if !self.estimate_text.is_empty() {
                    ui.add_space(12.0);
                    ui.label(RichText::new("ESTIMATE").color(AMBER).size(11.0).strong());
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
                    stat_card(ui, "RATE", &format!("{:.0} /s", self.rate), LIVE);
                    ui.add_space(8.0);
                    stat_card(
                        ui,
                        "ELAPSED",
                        &format!("{:.1}s", self.elapsed.as_secs_f64()),
                        AMBER,
                    );
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
                        ui.label(
                            RichText::new(if self.running {
                                "Listening for matches…"
                            } else {
                                "No matches yet."
                            })
                            .color(DIM),
                        );
                    }
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
                                        RichText::new(&row.hit.address)
                                            .monospace()
                                            .color(CREAM)
                                            .size(15.0),
                                    );
                                });
                                ui.label(
                                    RichText::new(format!(
                                        "{}  ·  m/44'/429'/0'/0/{}",
                                        row.hit.device_label, row.hit.address_index
                                    ))
                                    .small()
                                    .color(DIM),
                                );
                                ui.horizontal(|ui| {
                                    if row.revealed {
                                        ui.label(
                                            RichText::new(&row.hit.mnemonic).monospace().small(),
                                        );
                                        if ui.button("Copy mnemonic").clicked() {
                                            ui.ctx().copy_text(row.hit.mnemonic.clone());
                                        }
                                    } else if ui.button("Reveal").clicked() {
                                        row.revealed = true;
                                    }
                                    if ui.button("Copy address").clicked() {
                                        ui.ctx().copy_text(row.hit.address.clone());
                                    }
                                });
                            });
                        ui.add_space(8.0);
                    }
                });
            });
    }
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, value_color: Color32) {
    egui::Frame::NONE
        .fill(PANEL)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_min_width(140.0);
            ui.label(RichText::new(label).color(DIM).size(10.0).strong());
            ui.label(RichText::new(value).color(value_color).size(22.0).strong());
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
        Stroke::new(1.0, Color32::from_rgb(40, 32, 24)),
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
        Stroke::new(1.6, AMBER),
    ));
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
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
            .insert("miner".into(), FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "miner".into());
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "miner".into());
        ctx.set_fonts(fonts);
        return;
    }
}
