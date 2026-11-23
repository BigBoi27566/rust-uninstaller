use bcu_core::automation::run_automation_cycle;
use bcu_core::export::export_to_csv;
use bcu_core::junk::scan_disk_junk;
use bcu_core::models::{ApplicationEntry, ConfidenceLevel, JunkItem};
use bcu_core::recycle::clean_junk_items;
use bcu_core::registry::scan_registry_uninstallers;
use bcu_core::registry_deep::{clean_registry_remnants, scan_deep_registry, RegistryRemnant};
use bcu_core::store::scan_store_apps;
use eframe::egui::{self, Color32};
use egui_extras::{Column, TableBuilder};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::process::{Child, Command};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOption {
    NameAsc,
    NameDesc,
    SizeDesc,
    SizeAsc,
}

pub enum AppEvent {
    AppsLoaded(Vec<ApplicationEntry>),
    JunkLoaded(Vec<JunkItem>),
    RegistryLoaded(Vec<RegistryRemnant>),
}

pub struct BcuApp {
    pub search_query: String,
    pub include_store: bool,
    pub sort_option: SortOption,
    pub auto_click_helper: bool,
    pub apps: Vec<ApplicationEntry>,
    pub selected_index: Option<usize>,
    pub checked_indices: HashSet<usize>,
    pub is_scanning: bool,
    pub is_scanning_junk: bool,
    pub is_scanning_registry: bool,
    pub junk_items: Vec<JunkItem>,
    pub registry_remnants: Vec<RegistryRemnant>,
    pub status_text: String,
    sender: Sender<AppEvent>,
    receiver: Receiver<AppEvent>,
}

impl Default for BcuApp {
    fn default() -> Self {
        let (sender, receiver) = channel();
        Self {
            search_query: String::new(),
            include_store: false,
            sort_option: SortOption::NameAsc,
            auto_click_helper: false,
            apps: Vec::new(),
            selected_index: None,
            checked_indices: HashSet::new(),
            is_scanning: false,
            is_scanning_junk: false,
            is_scanning_registry: false,
            junk_items: Vec::new(),
            registry_remnants: Vec::new(),
            status_text: "Initializing...".into(),
            sender,
            receiver,
        }
    }
}

impl BcuApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();

        // Check for --scan-dir CLI parameter (Explorer context menu)
        let args: Vec<String> = env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--scan-dir" || a == "-d") {
            if let Some(dir) = args.get(pos + 1) {
                app.search_query = dir.clone();
            }
        }

        app.start_scan();
        app
    }

    pub fn start_scan(&mut self) {
        self.is_scanning = true;
        self.status_text = "Scanning registry and installed applications...".into();
        self.selected_index = None;
        self.checked_indices.clear();
        self.junk_items.clear();
        self.registry_remnants.clear();

        let tx = self.sender.clone();
        let include_store = self.include_store;

        thread::spawn(move || {
            let mut list = scan_registry_uninstallers();
            if include_store {
                list.extend(scan_store_apps());
            }
            let _ = tx.send(AppEvent::AppsLoaded(list));
        });
    }

    pub fn start_junk_scan(&mut self, app_name: String, install_dir: Option<std::path::PathBuf>) {
        self.is_scanning_junk = true;
        self.junk_items.clear();
        let tx = self.sender.clone();

        thread::spawn(move || {
            let junk = scan_disk_junk(&app_name, install_dir.as_deref());
            let _ = tx.send(AppEvent::JunkLoaded(junk));
        });
    }

    pub fn start_registry_scan(&mut self, app: ApplicationEntry) {
        self.is_scanning_registry = true;
        self.registry_remnants.clear();
        let tx = self.sender.clone();

        thread::spawn(move || {
            let remnants = scan_deep_registry(&app);
            let _ = tx.send(AppEvent::RegistryLoaded(remnants));
        });
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        let q = self.search_query.trim().to_lowercase();
        let mut indices: Vec<usize> = self.apps
            .iter()
            .enumerate()
            .filter_map(|(idx, app)| {
                if q.is_empty() {
                    Some(idx)
                } else {
                    let matches = app.display_name.to_lowercase().contains(&q)
                        || app
                            .publisher
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q);
                    if matches {
                        Some(idx)
                    } else {
                        None
                    }
                }
            })
            .collect();

        match self.sort_option {
            SortOption::NameAsc => {
                indices.sort_by(|&a, &b| {
                    self.apps[a].display_name.to_lowercase().cmp(&self.apps[b].display_name.to_lowercase())
                });
            }
            SortOption::NameDesc => {
                indices.sort_by(|&a, &b| {
                    self.apps[b].display_name.to_lowercase().cmp(&self.apps[a].display_name.to_lowercase())
                });
            }
            SortOption::SizeDesc => {
                indices.sort_by(|&a, &b| {
                    let sa = self.apps[a].estimated_size_bytes.unwrap_or(0);
                    let sb = self.apps[b].estimated_size_bytes.unwrap_or(0);
                    sb.cmp(&sa)
                });
            }
            SortOption::SizeAsc => {
                indices.sort_by(|&a, &b| {
                    let sa = self.apps[a].estimated_size_bytes.unwrap_or(0);
                    let sb = self.apps[b].estimated_size_bytes.unwrap_or(0);
                    sa.cmp(&sb)
                });
            }
        }

        indices
    }

    #[allow(dead_code)]
    pub fn filter_applications(&self) -> Vec<(usize, &ApplicationEntry)> {
        let q = self.search_query.trim().to_lowercase();
        self.apps
            .iter()
            .enumerate()
            .filter(|(_, app)| {
                if q.is_empty() {
                    true
                } else {
                    app.display_name.to_lowercase().contains(&q)
                        || app
                            .publisher
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q)
                }
            })
            .collect()
    }

    fn check_events(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                AppEvent::AppsLoaded(list) => {
                    self.apps = list;
                    self.is_scanning = false;
                    self.status_text = format!("Ready: {} applications loaded.", self.apps.len());
                }
                AppEvent::JunkLoaded(items) => {
                    self.junk_items = items;
                    self.is_scanning_junk = false;
                }
                AppEvent::RegistryLoaded(remnants) => {
                    self.registry_remnants = remnants;
                    self.is_scanning_registry = false;
                }
            }
        }
    }
}

impl eframe::App for BcuApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_events();

        // Top Toolbar
        egui::TopBottomPanel::top("top_toolbar").show(ctx, |ui| {
            ui.add_space(4.0);

            // Row 1: Header title on the left, live status text on the right
            ui.horizontal(|ui| {
                ui.heading("⚡ RustUninstaller");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.is_scanning {
                        ui.spinner();
                    }
                    ui.colored_label(Color32::from_rgb(170, 205, 230), &self.status_text);
                });
            });

            ui.add_space(2.0);
            ui.separator();
            ui.add_space(2.0);

            // Row 2: Search, sort options, filters and action buttons
            ui.horizontal(|ui| {
                ui.label("🔍 Search:");
                let search_box = ui.text_edit_singleline(&mut self.search_query);
                if search_box.changed() {
                    self.selected_index = None;
                }

                ui.separator();

                // Sort Selector
                ui.label("Sort:");
                egui::ComboBox::from_id_salt("sort_combo")
                    .selected_text(match self.sort_option {
                        SortOption::NameAsc => "🔤 Name (A → Z)",
                        SortOption::NameDesc => "🔤 Name (Z → A)",
                        SortOption::SizeDesc => "📦 Size (High → Low)",
                        SortOption::SizeAsc => "📦 Size (Low → High)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.sort_option, SortOption::NameAsc, "🔤 Name (A → Z)");
                        ui.selectable_value(&mut self.sort_option, SortOption::NameDesc, "🔤 Name (Z → A)");
                        ui.selectable_value(&mut self.sort_option, SortOption::SizeDesc, "📦 Size (High → Low)");
                        ui.selectable_value(&mut self.sort_option, SortOption::SizeAsc, "📦 Size (Low → High)");
                    });

                ui.separator();

                if ui.checkbox(&mut self.include_store, "Store Apps").changed() {
                    self.start_scan();
                }

                // Opt-in Quiet Automation Helper
                ui.checkbox(&mut self.auto_click_helper, "🤖 Auto-Click");

                ui.separator();

                if ui.button("🔄 Refresh").clicked() {
                    self.start_scan();
                }

                if ui.button("📄 Export CSV").clicked() {
                    let csv = export_to_csv(&self.apps);
                    let _ = fs::write("installed_apps.csv", csv);
                    self.status_text = "Exported list to 'installed_apps.csv'".into();
                }

                let checked_count = self.checked_indices.len();
                if checked_count > 0 {
                    ui.separator();
                    if ui.button(format!("⚡ Uninstall Selected ({})", checked_count)).clicked() {
                        let auto_click = self.auto_click_helper;
                        let mut launched = 0;
                        let mut errors = Vec::new();

                        for &idx in &self.checked_indices {
                            if let Some(app) = self.apps.get(idx) {
                                // Prefer quiet command if available, otherwise fall back to normal uninstall string
                                let cmd_to_run = app.quiet_uninstall_string.as_deref()
                                    .or(app.uninstall_string.as_deref());

                                if let Some(raw_cmd) = cmd_to_run {
                                    match launch_uninstall_command(raw_cmd) {
                                        Ok(mut child) => {
                                            launched += 1;
                                            let sender = self.sender.clone();
                                            let include_store = self.include_store;
                                            let pid = child.id();

                                            thread::spawn(move || {
                                                if auto_click {
                                                    let auto_thread = thread::spawn(move || {
                                                        for _ in 0..15 {
                                                            thread::sleep(Duration::from_millis(800));
                                                            let _ = run_automation_cycle(pid);
                                                        }
                                                    });
                                                    let _ = child.wait();
                                                    let _ = auto_thread.join();
                                                } else {
                                                    let _ = child.wait();
                                                }

                                                // Brief delay to ensure Windows Registry flush
                                                thread::sleep(Duration::from_millis(600));
                                                let mut apps = scan_registry_uninstallers();
                                                if include_store {
                                                    apps.extend(scan_store_apps());
                                                }
                                                let _ = sender.send(AppEvent::AppsLoaded(apps));
                                            });
                                        }
                                        Err(e) => {
                                            errors.push(format!("{}: {}", app.display_name, e));
                                        }
                                    }
                                } else {
                                    errors.push(format!("{}: No uninstall command found", app.display_name));
                                }
                            }
                        }

                        self.checked_indices.clear();
                        self.selected_index = None;

                        if errors.is_empty() {
                            self.status_text = format!("Uninstalling {} app(s)... list will refresh automatically.", launched);
                        } else if launched > 0 {
                            self.status_text = format!("Uninstalling {} app(s)... Errors: {}", launched, errors.join("; "));
                        } else {
                            self.status_text = format!("Failed to launch uninstaller: {}", errors.join("; "));
                        }
                    }
                }
            });
            ui.add_space(4.0);
        });

        // Bottom status / detail panel
        let selected_app = self.selected_index.and_then(|idx| self.apps.get(idx)).cloned();

        if let Some(app) = selected_app {
            egui::TopBottomPanel::bottom("detail_panel")
                .resizable(true)
                .default_height(260.0)
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.heading(format!("📦 {}", app.display_name));
                        ui.separator();

                        if let Some(ref quiet) = app.quiet_uninstall_string {
                            if ui.button("⚡ Run Quiet Uninstall").clicked() {
                                let parts: Vec<&str> = quiet.split_whitespace().collect();
                                if !parts.is_empty() {
                                    if let Ok(child) = Command::new(parts[0]).args(&parts[1..]).spawn() {
                                        if self.auto_click_helper {
                                            let pid = child.id();
                                            thread::spawn(move || {
                                                for _ in 0..15 {
                                                    thread::sleep(Duration::from_millis(800));
                                                    let _ = run_automation_cycle(pid);
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                        }

                        if ui.button("🧹 Scan Leftover Junk").clicked() {
                            let name = app.display_name.clone();
                            let dir = app.install_location.clone();
                            self.start_junk_scan(name, dir);
                        }

                        if !self.junk_items.is_empty() {
                            if ui.button("🗑️ Send Safe Junk to Recycle Bin").clicked() {
                                let (cleaned, errors) = clean_junk_items(&self.junk_items, false);
                                self.status_text = format!("Recycled {} item(s) to Recycle Bin.", cleaned);
                                for err in errors {
                                    eprintln!("{}", err);
                                }
                                self.junk_items.clear();
                            }
                        }

                        if ui.button("🔍 Scan Deep Registry").clicked() {
                            self.start_registry_scan(app.clone());
                        }

                        if !self.registry_remnants.is_empty() {
                            if ui.button("🛡️ Create .reg Backup & Clean").clicked() {
                                match clean_registry_remnants(&self.registry_remnants, None, &app.id) {
                                    Ok(backup_path) => {
                                        self.status_text = format!(
                                            "Cleaned {} registry remnant(s)! Backup: {}",
                                            self.registry_remnants.len(),
                                            backup_path.display()
                                        );
                                        self.registry_remnants.clear();
                                    }
                                    Err(err) => {
                                        self.status_text = format!("Error cleaning registry: {}", err);
                                    }
                                }
                            }
                        }

                        if self.is_scanning_junk || self.is_scanning_registry {
                            ui.spinner();
                            ui.label("Scanning...");
                        }
                    });

                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(format!("ID: {}", app.id));
                            ui.label(format!("Version: {}", app.display_version.as_deref().unwrap_or("-")));
                            ui.label(format!("Publisher: {}", app.publisher.as_deref().unwrap_or("-")));
                            ui.label(format!("Type: {:?}", app.uninstaller_kind));
                            ui.label(format!(
                                "Install Path: {}",
                                app.install_location
                                    .as_ref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "-".into())
                            ));
                            ui.label(format!("Estimated Size: {}", format_size(app.estimated_size_bytes)));
                            ui.label(format!("Quiet Command: {}", app.quiet_uninstall_string.as_deref().unwrap_or("-")));
                        });

                        ui.separator();

                        ui.vertical(|ui| {
                            ui.strong(format!("Leftover Disk Files ({}):", self.junk_items.len()));
                            if self.junk_items.is_empty() {
                                if !self.is_scanning_junk {
                                    ui.label("Click 'Scan Leftover Junk' to find remnants on disk.");
                                }
                            } else {
                                egui::ScrollArea::vertical().id_salt("junk_scroll").max_height(100.0).show(ui, |ui| {
                                    for item in &self.junk_items {
                                        ui.horizontal(|ui| {
                                            match item.confidence {
                                                ConfidenceLevel::Safe => {
                                                    ui.colored_label(Color32::from_rgb(46, 204, 113), "[SAFE]");
                                                }
                                                ConfidenceLevel::Questionable => {
                                                    ui.colored_label(Color32::from_rgb(241, 196, 15), "[QUESTIONABLE]");
                                                }
                                                ConfidenceLevel::Dangerous => {
                                                    ui.colored_label(Color32::from_rgb(231, 76, 60), "[DANGEROUS]");
                                                }
                                            }
                                            ui.label(item.path.display().to_string());
                                        });
                                    }
                                });
                            }
                        });

                        ui.separator();

                        ui.vertical(|ui| {
                            ui.strong(format!("Deep Registry Remnants ({}):", self.registry_remnants.len()));
                            if self.registry_remnants.is_empty() {
                                if !self.is_scanning_registry {
                                    ui.label("Click 'Scan Deep Registry' to find residual keys/MuiCache.");
                                }
                            } else {
                                egui::ScrollArea::vertical().id_salt("reg_scroll").max_height(100.0).show(ui, |ui| {
                                    for rem in &self.registry_remnants {
                                        ui.horizontal(|ui| {
                                            match rem.confidence {
                                                ConfidenceLevel::Safe => {
                                                    ui.colored_label(Color32::from_rgb(46, 204, 113), "[SAFE]");
                                                }
                                                ConfidenceLevel::Questionable => {
                                                    ui.colored_label(Color32::from_rgb(241, 196, 15), "[QUESTIONABLE]");
                                                }
                                                ConfidenceLevel::Dangerous => {
                                                    ui.colored_label(Color32::from_rgb(231, 76, 60), "[DANGEROUS]");
                                                }
                                            }
                                            let target = if let Some(ref vn) = rem.value_name {
                                                format!(r"{}\{} -> {}", rem.hive, rem.subkey, vn)
                                            } else {
                                                format!(r"{}\{}", rem.hive, rem.subkey)
                                            };
                                            ui.label(target);
                                        });
                                    }
                                });
                            }
                        });
                    });
                });
        }

        // Central Panel
        egui::CentralPanel::default().show(ctx, |ui| {
            let indices = self.filtered_indices();
            self.render_table(ui, &indices);
        });
    }
}

impl BcuApp {
    fn render_table(&mut self, ui: &mut egui::Ui, indices: &[usize]) {
        let mut newly_selected = None;
        let mut toggled_checked = None;
        let mut new_sort = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(35.0))
            .column(Column::initial(280.0).at_least(140.0))
            .column(Column::initial(95.0).at_least(75.0))
            .column(Column::initial(90.0).at_least(60.0))
            .column(Column::initial(100.0).at_least(75.0))
            .column(Column::initial(65.0).at_least(50.0))
            .column(Column::remainder())
            .header(24.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Sel");
                });

                header.col(|ui| {
                    let name_label = match self.sort_option {
                        SortOption::NameAsc => "Display Name 🔼",
                        SortOption::NameDesc => "Display Name 🔽",
                        _ => "Display Name",
                    };
                    if ui.selectable_label(matches!(self.sort_option, SortOption::NameAsc | SortOption::NameDesc), name_label).clicked() {
                        new_sort = Some(if self.sort_option == SortOption::NameAsc {
                            SortOption::NameDesc
                        } else {
                            SortOption::NameAsc
                        });
                    }
                });

                header.col(|ui| {
                    let size_label = match self.sort_option {
                        SortOption::SizeDesc => "Size 🔽",
                        SortOption::SizeAsc => "Size 🔼",
                        _ => "Size",
                    };
                    if ui.selectable_label(matches!(self.sort_option, SortOption::SizeDesc | SortOption::SizeAsc), size_label).clicked() {
                        new_sort = Some(if self.sort_option == SortOption::SizeDesc {
                            SortOption::SizeAsc
                        } else {
                            SortOption::SizeDesc
                        });
                    }
                });

                header.col(|ui| {
                    ui.strong("Version");
                });
                header.col(|ui| {
                    ui.strong("Kind");
                });
                header.col(|ui| {
                    ui.strong("Quiet?");
                });
                header.col(|ui| {
                    ui.strong("Publisher");
                });
            })
            .body(|body| {
                body.rows(22.0, indices.len(), |mut row| {
                    let row_index = row.index();
                    if let Some(&original_index) = indices.get(row_index) {
                        if let Some(app) = self.apps.get(original_index) {
                            let is_selected = self.selected_index == Some(original_index);
                            let is_checked = self.checked_indices.contains(&original_index);

                            row.col(|ui| {
                                let mut checked = is_checked;
                                if ui.checkbox(&mut checked, "").changed() {
                                    toggled_checked = Some((original_index, checked));
                                }
                            });

                            row.col(|ui| {
                                let label = ui.selectable_label(is_selected, &app.display_name);
                                if label.clicked() {
                                    newly_selected = Some(original_index);
                                }
                            });

                            row.col(|ui| {
                                let size_text = format_size(app.estimated_size_bytes);
                                if app.estimated_size_bytes.is_some() {
                                    ui.colored_label(Color32::from_rgb(100, 200, 255), size_text);
                                } else {
                                    ui.colored_label(Color32::GRAY, size_text);
                                }
                            });

                            row.col(|ui| {
                                ui.label(app.display_version.as_deref().unwrap_or("-"));
                            });

                            row.col(|ui| {
                                ui.label(format!("{:?}", app.uninstaller_kind));
                            });

                            row.col(|ui| {
                                if app.quiet_uninstall_string.is_some() {
                                    ui.colored_label(Color32::from_rgb(46, 204, 113), "YES");
                                } else {
                                    ui.colored_label(Color32::GRAY, "NO");
                                }
                            });

                            row.col(|ui| {
                                ui.label(app.publisher.as_deref().unwrap_or("-"));
                            });
                        }
                    }
                });
            });

        if let Some(sort) = new_sort {
            self.sort_option = sort;
        }

        if let Some((idx, checked)) = toggled_checked {
            if checked {
                self.checked_indices.insert(idx);
            } else {
                self.checked_indices.remove(&idx);
            }
        }

        if let Some(idx) = newly_selected {
            self.selected_index = Some(idx);
            self.junk_items.clear();
            self.registry_remnants.clear();
        }
    }
}

fn format_size(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) if b >= 1024 * 1024 * 1024 => format!("{:.2} GB", b as f64 / (1024.0 * 1024.0 * 1024.0)),
        Some(b) if b >= 1024 * 1024 => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
        Some(b) if b >= 1024 => format!("{} KB", b / 1024),
        Some(b) if b > 0 => format!("{} B", b),
        _ => "-".to_string(),
    }
}

fn launch_uninstall_command(cmd: &str) -> std::io::Result<Child> {
    if let Some((exe, args)) = bcu_core::heuristics::parse_command_line(cmd) {
        if let Ok(child) = Command::new(&exe).args(&args).spawn() {
            return Ok(child);
        }
    }
    // Fallback: run via Windows command shell if direct binary execution fails
    Command::new("cmd").args(["/C", cmd]).spawn()
}

