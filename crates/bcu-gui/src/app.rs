use crate::cleanup_modal::{CleanupAction, CleanupModalState};
use crate::treemap::{render_treemap, SquarifiedTreeMap, TreeMapItem};
use bcu_core::automation::run_automation_cycle;
use bcu_core::export::export_to_csv;
use bcu_core::junk::{scan_disk_junk, scan_disk_junk_deep};
use bcu_core::models::{ApplicationEntry, ConfidenceLevel, JunkItem, UninstallerKind};
use bcu_core::queue::{TaskStatus, UninstallQueue};
use bcu_core::recycle::clean_junk_items;
use bcu_core::registry::scan_registry_uninstallers;
use bcu_core::registry_deep::{
    clean_registry_remnants, clean_registry_remnants_selective, force_remove_uninstall_entry,
    scan_deep_registry, RegistryRemnant,
};
use bcu_core::store::scan_store_apps;
use eframe::egui::{self, Color32, Response, Ui};
use egui_extras::{Column, TableBuilder};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::process::{Child, Command};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

/// Render an action tooltip with smooth fade-in/out transition under the target element
fn show_fade_tooltip(ui: &mut Ui, response: &Response, text: &str) {
    let hovered = response.hovered();
    let alpha = ui.ctx().animate_bool(response.id.with("fade_tip"), hovered);
    if alpha > 0.005 {
        // Use debug_painter() on ctx to render into Foreground layer above all panels and clip rects
        let painter = ui.ctx().debug_painter();
        let font_id = egui::TextStyle::Small.resolve(ui.style());
        let padding = egui::vec2(7.0, 4.0);
        let galley = painter.layout_no_wrap(text.to_owned(), font_id, Color32::from_white_alpha((240.0 * alpha) as u8));
        let tip_size = galley.size() + padding * 2.0;
        let tip_rect = egui::Rect::from_min_size(
            egui::pos2(response.rect.left(), response.rect.bottom() + 4.0),
            tip_size,
        );

        // Draw floating rounded tooltip above other UI layers
        painter.rect_filled(tip_rect, 4.0, Color32::from_rgba_premultiplied(24, 24, 24, (245.0 * alpha) as u8));
        painter.rect_stroke(tip_rect, 4.0, egui::Stroke::new(1.0_f32, Color32::from_rgba_premultiplied(100, 100, 100, (220.0 * alpha) as u8)));
        painter.galley(tip_rect.min + padding, galley, Color32::from_white_alpha((240.0 * alpha) as u8));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOption {
    NameAsc,
    NameDesc,
    SizeDesc,
    SizeAsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Table,
    DiskMap,
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    BatchUninstall {
        targets: Vec<ApplicationEntry>,
        skip_restore_point: bool,
    },
    ForceUninstall {
        app: ApplicationEntry,
        skip_restore_point: bool,
    },
    RestorePointFailed {
        error: String,
        next: Box<ConfirmAction>,
    },
}

pub enum AppEvent {
    AppsLoaded(Vec<ApplicationEntry>),
    BatchFinished {
        apps: Vec<ApplicationEntry>,
        status: String,
        removed_targets: Vec<ApplicationEntry>,
    },
    PostUninstallCleanupReady {
        app_names: Vec<String>,
        junk: Vec<JunkItem>,
        remnants: Vec<RegistryRemnant>,
    },
    RestorePointResult {
        res: Result<(), String>,
        next: ConfirmAction,
    },
    JunkLoaded(Vec<JunkItem>),
    RegistryLoaded(Vec<RegistryRemnant>),
}

pub struct BcuApp {
    pub search_query: String,
    pub scan_dir_filter: Option<String>,
    pub include_store: bool,
    pub show_system_components: bool,
    pub create_restore_point: bool,
    pub sort_option: SortOption,
    pub view_mode: ViewMode,
    pub auto_click_helper: bool,
    pub apps: Vec<ApplicationEntry>,
    pub cached_indices: Vec<usize>,
    pub selected_index: Option<usize>,
    pub checked_indices: HashSet<usize>,
    pub is_scanning: bool,
    pub is_scanning_junk: bool,
    pub is_scanning_registry: bool,
    pub junk_items: Vec<JunkItem>,
    pub registry_remnants: Vec<RegistryRemnant>,
    pub cleanup_modal: Option<CleanupModalState>,
    pub pending_confirm: Option<ConfirmAction>,
    pub status_text: String,
    sender: Sender<AppEvent>,
    receiver: Receiver<AppEvent>,
}

impl Default for BcuApp {
    fn default() -> Self {
        let (sender, receiver) = channel();
        Self {
            search_query: String::new(),
            scan_dir_filter: None,
            include_store: false,
            show_system_components: false,
            create_restore_point: false,
            sort_option: SortOption::NameAsc,
            view_mode: ViewMode::Table,
            auto_click_helper: false,
            apps: Vec::new(),
            cached_indices: Vec::new(),
            selected_index: None,
            checked_indices: HashSet::new(),
            is_scanning: false,
            is_scanning_junk: false,
            is_scanning_registry: false,
            junk_items: Vec::new(),
            registry_remnants: Vec::new(),
            cleanup_modal: None,
            pending_confirm: None,
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
                app.scan_dir_filter = Some(dir.clone());
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
            let _ = tx.send(AppEvent::AppsLoaded(rescan_all(include_store)));
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

    pub fn start_post_uninstall_scan(&self, targets: Vec<ApplicationEntry>) {
        let tx = self.sender.clone();
        thread::spawn(move || {
            let mut app_names = Vec::new();
            let mut all_junk = Vec::new();
            let mut all_remnants = Vec::new();
            let mut seen_paths = HashSet::new();
            let mut seen_regs = HashSet::new();

            for app in targets {
                app_names.push(app.display_name.clone());
                for item in scan_disk_junk_deep(
                    &app.display_name,
                    app.publisher.as_deref(),
                    app.install_location.as_deref(),
                ) {
                    if seen_paths.insert(item.path.clone()) {
                        all_junk.push(item);
                    }
                }
                for rem in scan_deep_registry(&app) {
                    let key = format!(
                        "{}:{}:{}",
                        rem.hive,
                        rem.subkey,
                        rem.value_name.as_deref().unwrap_or("")
                    );
                    if seen_regs.insert(key) {
                        all_remnants.push(rem);
                    }
                }
            }

            let _ = tx.send(AppEvent::PostUninstallCleanupReady {
                app_names,
                junk: all_junk,
                remnants: all_remnants,
            });
        });
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        let q = self.search_query.trim().to_lowercase();
        let mut indices: Vec<usize> = self.apps
            .iter()
            .enumerate()
            .filter_map(|(idx, app)| {
                if !self.show_system_components && app.is_system_component {
                    return None;
                }
                if let Some(ref target_dir) = self.scan_dir_filter {
                    if !matches_install_dir(app.install_location.as_deref(), target_dir) {
                        return None;
                    }
                }
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

    pub fn recompute_filtered_indices(&mut self) {
        self.cached_indices = self.filtered_indices();
    }

    pub fn clear_selection_and_details(&mut self) {
        self.selected_index = None;
        self.checked_indices.clear();
        self.junk_items.clear();
        self.registry_remnants.clear();
    }

    pub fn request_uninstall_targets(&mut self, targets: Vec<ApplicationEntry>) {
        self.clear_selection_and_details();
        if targets.is_empty() {
            return;
        }
        if targets.iter().any(|a| a.is_protected) {
            self.pending_confirm = Some(ConfirmAction::BatchUninstall {
                targets,
                skip_restore_point: false,
            });
        } else {
            self.execute_confirm_action(ConfirmAction::BatchUninstall {
                targets,
                skip_restore_point: false,
            });
        }
    }

    fn check_events(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                AppEvent::AppsLoaded(list) => {
                    self.apps = list;
                    self.is_scanning = false;
                    self.recompute_filtered_indices();
                    self.status_text = format!("Ready: {} applications loaded.", self.apps.len());
                }
                AppEvent::BatchFinished {
                    apps,
                    status,
                    removed_targets,
                } => {
                    self.apps = apps;
                    self.is_scanning = false;
                    self.clear_selection_and_details();
                    self.recompute_filtered_indices();
                    self.status_text = status;
                    if !removed_targets.is_empty() {
                        self.start_post_uninstall_scan(removed_targets);
                    }
                }
                AppEvent::RestorePointResult { res, next } => {
                    self.is_scanning = false;
                    match res {
                        Ok(()) => self.execute_confirm_action(next),
                        Err(err) => {
                            self.pending_confirm = Some(ConfirmAction::RestorePointFailed {
                                error: err,
                                next: Box::new(next),
                            });
                        }
                    }
                }
                AppEvent::PostUninstallCleanupReady {
                    app_names,
                    junk,
                    remnants,
                } => {
                    if !junk.is_empty() || !remnants.is_empty() {
                        self.cleanup_modal =
                            Some(CleanupModalState::from_results(app_names, junk, remnants));
                    }
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
                    self.recompute_filtered_indices();
                }

                if self.scan_dir_filter.is_some() && ui.button("✖ Dir Filter").clicked() {
                    self.scan_dir_filter = None;
                    self.recompute_filtered_indices();
                }

                ui.separator();

                // Sort Selector
                ui.label("Sort:");
                let prev_sort = self.sort_option;
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
                if self.sort_option != prev_sort {
                    self.recompute_filtered_indices();
                }

                ui.separator();

                ui.selectable_value(&mut self.view_mode, ViewMode::Table, "📋 Table");
                ui.selectable_value(&mut self.view_mode, ViewMode::DiskMap, "🗺 Disk Map");

                ui.separator();

                let store_cb = ui.checkbox(&mut self.include_store, "Store Apps");
                if store_cb.changed() {
                    self.start_scan();
                }
                show_fade_tooltip(ui, &store_cb, "Include Universal Windows Platform (UWP) apps");

                // Opt-in Quiet Automation Helper
                let auto_cb = ui.checkbox(&mut self.auto_click_helper, "🤖 Auto-Click");
                show_fade_tooltip(ui, &auto_cb, "Automatically confirm uninstaller dialogues");

                let sys_cb = ui.checkbox(&mut self.show_system_components, "Show System");
                if sys_cb.changed() {
                    self.recompute_filtered_indices();
                }
                show_fade_tooltip(ui, &sys_cb, "Show Windows SystemComponent entries");

                let rp_cb = ui.checkbox(&mut self.create_restore_point, "Restore Point");
                show_fade_tooltip(ui, &rp_cb, "Create a System Restore Point before batch/force uninstall");

                ui.separator();

                let refresh_btn = ui.button("🔄 Refresh");
                if refresh_btn.clicked() {
                    self.start_scan();
                }
                show_fade_tooltip(ui, &refresh_btn, "Rescan registry and installed applications");

                let export_btn = ui.button("📄 Export CSV");
                if export_btn.clicked() {
                    let csv = export_to_csv(&self.apps);
                    let _ = fs::write("installed_apps.csv", csv);
                    self.status_text = "Exported list to 'installed_apps.csv'".into();
                }
                show_fade_tooltip(ui, &export_btn, "Save application inventory to CSV spreadsheet");

                let checked_count = self.checked_indices.len();
                if checked_count > 0 {
                    ui.separator();
                    let uninstall_btn = ui.button(format!("⚡ Uninstall Selected ({})", checked_count));
                    show_fade_tooltip(ui, &uninstall_btn, "Launch silent uninstaller for checked programs");
                    if uninstall_btn.clicked() {
                        let mut targets = Vec::new();
                        let mut errors = Vec::new();

                        for &idx in &self.checked_indices {
                            if let Some(app) = self.apps.get(idx).cloned() {
                                if app.quiet_uninstall_string.is_some() || app.uninstall_string.is_some() {
                                    targets.push(app);
                                } else {
                                    errors.push(format!("{}: No uninstall command found", app.display_name));
                                }
                            }
                        }

                        if targets.is_empty() {
                            self.clear_selection_and_details();
                            self.status_text = format!("Failed to launch uninstaller: {}", errors.join("; "));
                        } else {
                            self.request_uninstall_targets(targets);
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
                        if app.is_protected {
                            ui.colored_label(Color32::from_rgb(241, 196, 15), "[PROTECTED]");
                        }
                        if is_uninstaller_missing(&app) {
                            ui.colored_label(Color32::from_rgb(231, 76, 60), "[BROKEN]");
                        }
                        ui.separator();

                        if app.uninstaller_kind != UninstallerKind::StoreApp && app.registry_location.is_some() {
                            let force_btn = ui.button("🔨 Force Uninstall");
                            show_fade_tooltip(ui, &force_btn, "Remove Uninstall registry entry and scan leftovers");
                            if force_btn.clicked() {
                                self.pending_confirm = Some(ConfirmAction::ForceUninstall {
                                    app: app.clone(),
                                    skip_restore_point: false,
                                });
                            }
                        }

                        if app.quiet_uninstall_string.is_some() {
                            let quiet_btn = ui.button("⚡ Run Quiet Uninstall");
                            show_fade_tooltip(ui, &quiet_btn, "Run vendor uninstaller in silent/unattended mode");
                            if quiet_btn.clicked() {
                                self.request_uninstall_targets(vec![app.clone()]);
                            }
                        }

                        let junk_btn = ui.button("🧹 Scan Leftover Junk");
                        show_fade_tooltip(ui, &junk_btn, "Detect orphaned folders and files in ProgramFiles/AppData");
                        if junk_btn.clicked() {
                            let name = app.display_name.clone();
                            let dir = app.install_location.clone();
                            self.start_junk_scan(name, dir);
                        }

                        if !self.junk_items.is_empty() {
                            let recycle_btn = ui.button("🗑️ Send Safe Junk to Recycle Bin");
                            show_fade_tooltip(ui, &recycle_btn, "Move safe leftover files to Windows Recycle Bin");
                            if recycle_btn.clicked() {
                                let (cleaned, errors) = clean_junk_items(&self.junk_items, false);
                                self.status_text = format!("Recycled {} item(s) to Recycle Bin.", cleaned);
                                for err in errors {
                                    eprintln!("{}", err);
                                }
                                self.junk_items.clear();
                            }
                        }

                        let reg_btn = ui.button("🔍 Scan Deep Registry");
                        show_fade_tooltip(ui, &reg_btn, "Search HKCU/HKLM for leftover keys and values");
                        if reg_btn.clicked() {
                            self.start_registry_scan(app.clone());
                        }

                        if !self.registry_remnants.is_empty() {
                            let clean_reg_btn = ui.button("🛡️ Create .reg Backup & Clean");
                            show_fade_tooltip(ui, &clean_reg_btn, "Export rollback backup .reg before cleaning remnants");
                            if clean_reg_btn.clicked() {
                                match clean_registry_remnants(&self.registry_remnants, None, &app.id) {
                                    Ok((backup_path, deleted, errors)) => {
                                        self.status_text = if errors.is_empty() {
                                            format!(
                                                "Cleaned {} registry remnant(s)! Backup: {}",
                                                deleted,
                                                backup_path.display()
                                            )
                                        } else {
                                            format!(
                                                "Cleaned {} remnant(s), {} failed (try Run as Administrator). Backup: {}",
                                                deleted,
                                                errors.len(),
                                                backup_path.display()
                                            )
                                        };
                                        if deleted > 0 {
                                            self.registry_remnants.clear();
                                        }
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
            let indices = self.cached_indices.clone();
            match self.view_mode {
                ViewMode::Table => {
                    self.render_table(ui, &indices);
                }
                ViewMode::DiskMap => {
                    self.render_disk_map(ui, &indices);
                }
            }
        });

        if let Some(mut modal) = self.cleanup_modal.take() {
            match modal.show(ctx) {
                Some(CleanupAction::Clean { junk, remnants }) => {
                    let (disk_cleaned, disk_errors) = if junk.is_empty() {
                        (0, Vec::new())
                    } else {
                        clean_junk_items(&junk, true)
                    };
                    let reg_res = if remnants.is_empty() {
                        None
                    } else {
                        let id = modal.app_names.first().map(|s| s.as_str()).unwrap_or("cleanup");
                        Some(clean_registry_remnants_selective(&remnants, true, None, id))
                    };
                    self.status_text = format_cleanup_status(disk_cleaned, &disk_errors, reg_res);
                }
                Some(CleanupAction::Skip) => {
                    self.status_text = "Skipped post-uninstall leftover cleanup.".into();
                }
                None => {
                    self.cleanup_modal = Some(modal);
                }
            }
        }
        if let Some(confirm) = self.pending_confirm.take() {
            let mut keep_open = true;
            egui::Window::new("⚠️ Confirmation")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    match &confirm {
                        ConfirmAction::BatchUninstall { targets, .. } => {
                            ui.label(format!(
                                "Selection includes protected (NoRemove) app(s). Uninstall {} app(s)?",
                                targets.len()
                            ));
                        }
                        ConfirmAction::ForceUninstall { app, .. } => {
                            ui.label(format!(
                                "Force-remove '{}' from the Uninstall registry and scan leftovers?",
                                app.display_name
                            ));
                            if app.is_protected {
                                ui.colored_label(
                                    Color32::from_rgb(241, 196, 15),
                                    "Warning: This entry is marked Protected (NoRemove=1).",
                                );
                            }
                        }
                        ConfirmAction::RestorePointFailed { error, .. } => {
                            ui.colored_label(
                                Color32::from_rgb(231, 76, 60),
                                format!("System Restore Point failed: {}", error),
                            );
                            ui.label("Continue uninstalling without a Restore Point?");
                        }
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Continue").clicked() {
                            keep_open = false;
                            let next = match confirm.clone() {
                                ConfirmAction::RestorePointFailed { next, .. } => *next,
                                other => other,
                            };
                            self.execute_confirm_action(next);
                        }
                        if ui.button("Cancel").clicked() {
                            keep_open = false;
                            self.status_text = "Action cancelled.".into();
                        }
                    });
                });
            if keep_open {
                self.pending_confirm = Some(confirm);
            }
        }
    }
}

impl BcuApp {
    fn execute_confirm_action(&mut self, action: ConfirmAction) {
        let needs_rp = self.create_restore_point
            && matches!(
                action,
                ConfirmAction::BatchUninstall {
                    skip_restore_point: false,
                    ..
                } | ConfirmAction::ForceUninstall {
                    skip_restore_point: false,
                    ..
                }
            );

        if needs_rp {
            let next = match action {
                ConfirmAction::BatchUninstall { targets, .. } => ConfirmAction::BatchUninstall {
                    targets,
                    skip_restore_point: true,
                },
                ConfirmAction::ForceUninstall { app, .. } => ConfirmAction::ForceUninstall {
                    app,
                    skip_restore_point: true,
                },
                other => other,
            };
            let sender = self.sender.clone();
            self.is_scanning = true;
            self.status_text = "Creating System Restore Point...".into();
            thread::spawn(move || {
                let res = create_system_restore_point();
                let _ = sender.send(AppEvent::RestorePointResult { res, next });
            });
            return;
        }

        match action {
            ConfirmAction::BatchUninstall { targets, .. } => {
                self.start_batch_uninstall(targets);
            }
            ConfirmAction::ForceUninstall { app, .. } => {
                match force_remove_uninstall_entry(&app, None) {
                    Ok(backup_path) => {
                        self.clear_selection_and_details();
                        self.apps = rescan_all(self.include_store);
                        self.recompute_filtered_indices();
                        self.status_text = format!(
                            "Force-removed '{}'. Backup: {}",
                            app.display_name,
                            backup_path.display()
                        );
                        self.start_post_uninstall_scan(vec![app]);
                    }
                    Err(e) => {
                        self.status_text = format!("Force Uninstall failed: {}", e);
                    }
                }
            }
            ConfirmAction::RestorePointFailed { next, .. } => {
                self.execute_confirm_action(*next);
            }
        }
    }

    fn start_batch_uninstall(&mut self, targets: Vec<ApplicationEntry>) {
        let auto_click = self.auto_click_helper;
        let include_store = self.include_store;
        let sender = self.sender.clone();
        let queued = targets.len();
        let mut queue = UninstallQueue::new();
        for app in &targets {
            queue.add(app.clone());
        }

        self.is_scanning = true;
        self.status_text = format!("Queued {} app(s) for uninstall...", queued);

        thread::spawn(move || {
            let (tx, rx) = channel::<(String, String, std::io::Result<()>)>();
            let mut in_flight = 0usize;
            let mut errors = Vec::new();

            loop {
                while let Some(task) = queue.next_runnable_task().cloned() {
                    let id = task.app.id.clone();
                    let name = task.app.display_name.clone();
                    let cmd = task
                        .app
                        .quiet_uninstall_string
                        .or(task.app.uninstall_string)
                        .unwrap_or_default();

                    queue.set_status(&id, TaskStatus::Running);
                    in_flight += 1;
                    let worker_tx = tx.clone();

                    thread::spawn(move || {
                        let res = run_uninstall_and_wait(&cmd, auto_click);
                        let _ = worker_tx.send((id, name, res));
                    });
                }

                if in_flight == 0 {
                    break;
                }

                if let Ok((done_id, name, res)) = rx.recv() {
                    in_flight -= 1;
                    match res {
                        Ok(()) => queue.set_status(&done_id, TaskStatus::Completed),
                        Err(e) => {
                            queue.set_status(&done_id, TaskStatus::Failed);
                            errors.push(format!("{}: {}", name, e));
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(600));
            let apps = rescan_all(include_store);
            let removed_targets = filter_removed_targets(targets, &apps);
            let status = if errors.is_empty() {
                format!("Finished uninstalling {} app(s). {} apps remaining.", queued, apps.len())
            } else {
                format!("Uninstall finished with errors: {}", errors.join("; "))
            };
            let _ = sender.send(AppEvent::BatchFinished {
                apps,
                status,
                removed_targets,
            });
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
            self.recompute_filtered_indices();
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

    fn render_disk_map(&mut self, ui: &mut egui::Ui, indices: &[usize]) {
        const PALETTE: &[Color32] = &[
            Color32::from_rgb(52, 152, 219),
            Color32::from_rgb(46, 204, 113),
            Color32::from_rgb(155, 89, 182),
            Color32::from_rgb(230, 126, 34),
            Color32::from_rgb(26, 188, 156),
            Color32::from_rgb(231, 76, 60),
        ];

        let items: Vec<TreeMapItem> = indices
            .iter()
            .enumerate()
            .filter_map(|(pos, &orig_idx)| {
                let app = self.apps.get(orig_idx)?;
                Some(TreeMapItem {
                    original_index: orig_idx,
                    label: app.display_name.clone(),
                    sublabel: app.publisher.clone().unwrap_or_default(),
                    size_bytes: app.estimated_size_bytes.unwrap_or(0),
                    color: PALETTE[pos % PALETTE.len()],
                })
            })
            .collect();

        let bounds = ui.available_rect_before_wrap();
        let tiles = SquarifiedTreeMap::compute_layout(&items, bounds);
        if let Some(clicked_idx) = render_treemap(ui, &tiles, self.selected_index) {
            self.selected_index = Some(clicked_idx);
            self.junk_items.clear();
            self.registry_remnants.clear();
        }
    }
}

fn format_cleanup_status(
    disk_cleaned: usize,
    disk_errors: &[String],
    reg_res: Option<std::io::Result<(std::path::PathBuf, usize, Vec<String>)>>,
) -> String {
    let mut parts = vec![format!("recycled {} disk item(s)", disk_cleaned)];
    let mut err_count = disk_errors.len();
    let mut backup_note = String::new();

    match reg_res {
        Some(Ok((backup_path, reg_cleaned, reg_errors))) => {
            parts.push(format!("cleaned {} registry remnant(s)", reg_cleaned));
            err_count += reg_errors.len();
            backup_note = format!(" Backup: {}", backup_path.display());
        }
        Some(Err(e)) => {
            err_count += 1;
            parts.push(format!("registry cleanup failed ({})", e));
        }
        None => {}
    }

    if err_count > 0 {
        format!(
            "Post-uninstall cleanup: {}, {} failed (try Run as Administrator).{}",
            parts.join(", "),
            err_count,
            backup_note
        )
    } else {
        format!("Post-uninstall cleanup: {}.{}", parts.join(", "), backup_note)
    }
}

fn matches_install_dir(install_location: Option<&std::path::Path>, target_dir: &str) -> bool {
    let Some(loc) = install_location else {
        return false;
    };
    let norm = |s: &str| s.trim().trim_end_matches(['\\', '/']).to_lowercase();
    let target = norm(target_dir);
    !target.is_empty() && norm(&loc.to_string_lossy()) == target
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

fn rescan_all(include_store: bool) -> Vec<ApplicationEntry> {
    let mut apps = scan_registry_uninstallers();
    if include_store {
        apps.extend(scan_store_apps());
    }
    apps
}

fn is_uninstaller_missing(app: &ApplicationEntry) -> bool {
    if app.uninstaller_kind == UninstallerKind::StoreApp {
        return false;
    }
    let Some(ref raw_cmd) = app.uninstall_string else {
        return false;
    };
    let Some((exe, _)) = bcu_core::heuristics::parse_command_line(raw_cmd) else {
        return false;
    };
    (exe.contains('\\') || exe.contains('/')) && !std::path::Path::new(&exe).exists()
}

fn create_system_restore_point() -> Result<(), String> {
    let output = Command::new("PowerShell.exe")
        .args([
            "-NonInteractive",
            "-NoProfile",
            "-Command",
            "Checkpoint-Computer -Description 'RustUninstaller' -RestorePointType 'APPLICATION_UNINSTALL'",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            format!("Exit code {} (Run as Administrator)", output.status)
        } else {
            stderr
        })
    }
}

fn filter_removed_targets(
    launched: Vec<ApplicationEntry>,
    current_apps: &[ApplicationEntry],
) -> Vec<ApplicationEntry> {
    launched
        .into_iter()
        .filter(|t| {
            !current_apps
                .iter()
                .any(|a| a.id == t.id && a.display_name == t.display_name)
        })
        .collect()
}

fn run_uninstall_and_wait(cmd: &str, auto_click: bool) -> std::io::Result<()> {
    let mut child = launch_uninstall_command(cmd)?;
    let pid = child.id();
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "Uninstaller exited with status {}",
                status
            )));
        }
        if auto_click {
            let _ = run_automation_cycle(pid);
        }
        thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcu_core::models::UninstallerKind;

    #[test]
    fn test_filter_removed_targets_skips_still_installed_apps() {
        let app = |id: &str, name: &str| ApplicationEntry {
            id: id.into(),
            display_name: name.into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: UninstallerKind::Nsis,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        };

        let cancelled = app("1", "CancelledApp");
        let removed = app("2", "RemovedApp");
        let res = filter_removed_targets(vec![cancelled.clone(), removed.clone()], &[cancelled]);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, "2");
    }

    #[test]
    fn test_has_broken_uninstaller_path() {
        let mut app = ApplicationEntry {
            id: "1".into(),
            display_name: "Broken".into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: Some(r#""C:\NonExistent_BCU_Dir_12345\unins000.exe" /S"#.into()),
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: UninstallerKind::InnoSetup,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        };
        assert!(is_uninstaller_missing(&app));

        app.uninstaller_kind = UninstallerKind::StoreApp;
        assert!(!is_uninstaller_missing(&app));
    }

    #[test]
    fn test_matches_scan_dir_normalizes_trailing_slash_and_case() {
        assert!(matches_install_dir(
            Some(std::path::Path::new(r"C:\Program Files\VLC")),
            r"c:\program files\vlc\"
        ));
        assert!(!matches_install_dir(None, r"C:\Program Files\VLC"));
    }

    #[test]
    fn test_clear_selection_and_protected_quiet_uninstall() {
        let mut gui = BcuApp::default();
        gui.selected_index = Some(0);
        gui.checked_indices.insert(1);
        let protected_app = ApplicationEntry {
            id: "p1".into(),
            display_name: "ProtectedApp".into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: Some("unins000.exe".into()),
            quiet_uninstall_string: Some("unins000.exe /VERYSILENT".into()),
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: UninstallerKind::InnoSetup,
            is_system_component: false,
            is_protected: true,
            registry_location: None,
        };
        gui.request_uninstall_targets(vec![protected_app]);
        assert!(gui.pending_confirm.is_some());
        assert!(gui.selected_index.is_none());
        assert!(gui.checked_indices.is_empty());
    }

    #[test]
    fn test_format_cleanup_status_surfaces_errors_and_backup() {
        let msg = format_cleanup_status(
            1,
            &["Access denied".into()],
            Some(Ok((std::path::PathBuf::from(r"C:\backup.reg"), 0, vec!["HKLM err".into()]))),
        );
        assert!(msg.contains("failed"));
        assert!(msg.contains("Run as Administrator"));
        assert!(msg.contains("backup.reg"));
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

