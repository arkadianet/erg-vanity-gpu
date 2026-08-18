//! Desktop UI for vanity search.

use eframe::egui::{self, Color32, RichText};
use erg_vanity_cpu::MatchType;
use erg_vanity_engine::{
    estimate_pattern, format_time, list_gpu_devices, run_search, Backend, Hit, SearchEvent,
    SearchRequest,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Launch the native window.
pub fn run() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 640.0])
            .with_min_inner_size([820.0, 520.0])
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
}

impl VanityApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(Color32::from_rgb(220, 214, 200));
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(22, 24, 22);
        visuals.panel_fill = Color32::from_rgb(18, 20, 18);
        visuals.window_fill = Color32::from_rgb(18, 20, 18);
        visuals.selection.bg_fill = Color32::from_rgb(46, 92, 58);
        cc.egui_ctx.set_visuals(visuals);

        let devices_hint = match list_gpu_devices() {
            Ok(list) if list.is_empty() => "No OpenCL GPU — searches will use CPU.".into(),
            Ok(list) => list.join("\n"),
            Err(e) => format!("OpenCL: {e}"),
        };

        Self {
            patterns: "9err".into(),
            match_mode: 0,
            ignore_case: false,
            num_indices: 1,
            max_results: 1,
            devices: "0".into(),
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
            let est = estimate_pattern(&p, mt);
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
        let batch_size = if self.batch_size.trim().is_empty() {
            None
        } else {
            self.batch_size.trim().parse().ok()
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
        self.status = "Searching…".into();
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
                }
                SearchEvent::Hit(hit) => {
                    self.results.push(GuiHit {
                        hit,
                        revealed: false,
                    });
                    self.found = self.results.len();
                }
                SearchEvent::Dropped { count } => {
                    self.status = format!("Dropped {count} overflow hits");
                }
                SearchEvent::Error { message } => {
                    self.status = message;
                }
                SearchEvent::Done {
                    checked,
                    found,
                    elapsed,
                } => {
                    self.checked = checked;
                    self.found = found;
                    self.status = format!("Done in {:.1}s", elapsed.as_secs_f64());
                    self.running = false;
                }
            }
        }
        if self.running {
            self.rx = Some(rx);
        } else {
            if let Some(h) = self.worker.take() {
                let _ = h.join();
            }
            self.stop = None;
        }
    }
}

impl eframe::App for VanityApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.running {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new(&self.devices_hint).small().weak());
            ui.label(
                RichText::new("Mnemonics can spend funds. Verify in a trusted Ergo wallet.")
                    .small()
                    .color(Color32::from_rgb(196, 140, 64)),
            );
            ui.add_space(4.0);
        });

        egui::SidePanel::left("settings")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.heading("Search");
                ui.add_space(8.0);
                ui.label("Patterns (comma-separated)");
                ui.text_edit_singleline(&mut self.patterns);
                ui.add_space(6.0);
                ui.label("Match");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.match_mode, 0, "Prefix");
                    ui.selectable_value(&mut self.match_mode, 1, "Suffix");
                    ui.selectable_value(&mut self.match_mode, 2, "Contains");
                });
                ui.checkbox(&mut self.ignore_case, "Ignore case");
                ui.add(egui::Slider::new(&mut self.num_indices, 1..=100).text("indices / seed"));
                ui.add(egui::Slider::new(&mut self.max_results, 1..=20).text("max results"));
                ui.label("Devices (0, all, cpu)");
                ui.text_edit_singleline(&mut self.devices);
                ui.label("Batch size (blank = default)");
                ui.text_edit_singleline(&mut self.batch_size);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if !self.running && ui.button("Start").clicked() {
                        self.start();
                    }
                    if self.running && ui.button("Stop").clicked() {
                        self.stop_search();
                    }
                    if ui.button("Estimate").clicked() {
                        self.refresh_estimate();
                    }
                });
                if !self.estimate_text.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Estimate").strong());
                    ui.label(&self.estimate_text);
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Results");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!(
                        "{} · {:.0} addr/s · {} found",
                        self.checked, self.rate, self.found
                    ));
                });
            });
            ui.label(&self.status);
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, row) in self.results.iter_mut().enumerate() {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("Match {}", i + 1)).strong());
                        ui.monospace(&row.hit.address);
                        ui.label(format!(
                            "{}  ·  m/44'/429'/0'/0/{}",
                            row.hit.device_label, row.hit.address_index
                        ));
                        ui.horizontal(|ui| {
                            if row.revealed {
                                ui.monospace(&row.hit.mnemonic);
                                if ui.button("Copy mnemonic").clicked() {
                                    ui.ctx().copy_text(row.hit.mnemonic.clone());
                                }
                            } else {
                                ui.label("Mnemonic hidden");
                                if ui.button("Reveal").clicked() {
                                    row.revealed = true;
                                }
                            }
                            if ui.button("Copy address").clicked() {
                                ui.ctx().copy_text(row.hit.address.clone());
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
            });
        });
    }
}
