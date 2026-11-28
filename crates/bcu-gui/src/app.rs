use crate::cleanup_modal::{format_bytes, CleanupAction, CleanupModalState};
use crate::theme::{
    self, apply_theme, confidence_badge_colors, draw_monogram_icon, draw_pill,
    draw_top_progress_bar, kind_badge_colors, quiet_badge_colors, size_bar_ratio,
};
use bcu_core::icons::extract_app_icon_rgba;
use bcu_core::junk::{scan_disk_junk, scan_disk_junk_deep};
use bcu_core::models::{ApplicationEntry, ConfidenceLevel, JunkItem, UninstallerKind};
use bcu_core::queue::{TaskStatus, UninstallQueue};
use bcu_core::recycle::clean_junk_items;
use bcu_core::reg_backup::RegBackup;
use bcu_core::registry::scan_registry_uninstallers;
use bcu_core::registry_deep::{
    clean_registry_remnants, clean_registry_remnants_selective, force_remove_uninstall_entry,
    scan_deep_registry, RegistryRemnant,
};
use bcu_core::store::scan_store_apps;
use eframe::egui::{
    self, Color32, ColorImage, Id, Key, Pos2, Rect, Response, RichText, Rounding, Sense, Stroke,
    TextureHandle, TextureOptions, Ui, Vec2,
};
use egui_extras::{Column, TableBuilder};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
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

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    BatchUninstall {
        targets: Vec<ApplicationEntry>,
    },
    ForceUninstall {
        app: ApplicationEntry,
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
    IconsBatch(Vec<(String, Vec<u8>)>),
    JunkLoaded(Vec<JunkItem>),
    RegistryLoaded(Vec<RegistryRemnant>),
}

pub struct BcuApp {
    pub search_query: String,
    pub scan_dir_filter: Option<String>,
    pub include_store: bool,
    pub show_system_components: bool,
    pub sort_option: SortOption,
    pub apps: Vec<ApplicationEntry>,
    pub cached_indices: Vec<usize>,
    pub max_filtered_size_bytes: u64,
    pub total_filtered_bytes: u64,
    pub checked_total_bytes: u64,
    pub icon_textures: HashMap<String, TextureHandle>,
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
            sort_option: SortOption::NameAsc,
            apps: Vec::new(),
            cached_indices: Vec::new(),
            max_filtered_size_bytes: 0,
            total_filtered_bytes: 0,
            checked_total_bytes: 0,
            icon_textures: HashMap::new(),
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
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        let mut app = Self::default();

        // Check for --scan-dir CLI parameter (Explorer context menu)
        let args: Vec<String> = env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--scan-dir" || a == "-d") {
            if let Some(dir) = args.get(pos + 1).map(|s| s.trim()).filter(|s| !s.is_empty()) {
                app.scan_dir_filter = Some(dir.to_string());
            }
        }

        app.start_scan();
        app
    }

    pub fn start_scan(&mut self) {
        self.is_scanning = true;
        self.status_text = "Scanning registry and installed applications...".into();
        self.clear_selection_and_details();

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
        let mut max_size = 0u64;
        let mut total = 0u64;
        for &idx in &self.cached_indices {
            if let Some(size) = self.apps.get(idx).and_then(|a| a.estimated_size_bytes) {
                max_size = max_size.max(size);
                total = total.saturating_add(size);
            }
        }
        self.max_filtered_size_bytes = max_size;
        self.total_filtered_bytes = total;
        self.recompute_checked_bytes();
    }

    pub fn recompute_checked_bytes(&mut self) {
        self.checked_total_bytes = self
            .checked_indices
            .iter()
            .filter_map(|&idx| self.apps.get(idx).and_then(|a| a.estimated_size_bytes))
            .sum();
    }

    pub fn clear_selection_and_details(&mut self) {
        self.selected_index = None;
        self.checked_indices.clear();
        self.checked_total_bytes = 0;
        self.junk_items.clear();
        self.registry_remnants.clear();
    }

    fn start_icon_loader(&self, apps: Vec<ApplicationEntry>) {
        let tx = self.sender.clone();
        let missing: Vec<ApplicationEntry> = apps
            .into_iter()
            .filter(|a| !self.icon_textures.contains_key(&a.id))
            .collect();
        if missing.is_empty() {
            return;
        }
        thread::spawn(move || {
            let mut batch = Vec::with_capacity(16);
            for app in missing {
                if let Some(rgba) = extract_app_icon_rgba(&app) {
                    batch.push((app.id, rgba));
                    if batch.len() >= 16 {
                        let _ = tx.send(AppEvent::IconsBatch(std::mem::take(&mut batch)));
                    }
                }
            }
            if !batch.is_empty() {
                let _ = tx.send(AppEvent::IconsBatch(batch));
            }
        });
    }

    pub fn request_uninstall_targets(&mut self, targets: Vec<ApplicationEntry>) {
        self.clear_selection_and_details();
        if targets.is_empty() {
            return;
        }
        if targets.iter().any(|a| a.is_protected) {
            self.pending_confirm = Some(ConfirmAction::BatchUninstall { targets });
        } else {
            self.execute_confirm_action(ConfirmAction::BatchUninstall { targets });
        }
    }

    fn check_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                AppEvent::AppsLoaded(list) => {
                    self.start_icon_loader(list.clone());
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
                    self.start_icon_loader(apps.clone());
                    self.apps = apps;
                    self.is_scanning = false;
                    self.clear_selection_and_details();
                    self.recompute_filtered_indices();
                    self.status_text = status;
                    if !removed_targets.is_empty() {
                        self.start_post_uninstall_scan(removed_targets);
                    }
                }
                AppEvent::IconsBatch(items) => {
                    for (id, rgba) in items {
                        if rgba.len() == 16 * 16 * 4 {
                            let img = ColorImage::from_rgba_unmultiplied([16, 16], &rgba);
                            let tex = ctx.load_texture(format!("icon_{}", id), img, TextureOptions::LINEAR);
                            self.icon_textures.insert(id, tex);
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
        self.check_events(ctx);

        let search_id = Id::new("bcu_search_input");
        let (ctrl_f, f5, esc) = ctx.input(|i| {
            (
                i.modifiers.ctrl && i.key_pressed(Key::F),
                i.key_pressed(Key::F5),
                i.key_pressed(Key::Escape),
            )
        });
        if ctrl_f {
            ctx.memory_mut(|m| m.request_focus(search_id));
        }
        if f5 && !self.is_scanning {
            self.start_scan();
        }
        if esc {
            if self.cleanup_modal.is_some() {
                self.cleanup_modal = None;
                self.status_text = "Skipped post-uninstall leftover cleanup.".into();
            } else if self.pending_confirm.is_some() {
                self.pending_confirm = None;
                self.status_text = "Action cancelled.".into();
            } else if self.selected_index.is_some() {
                self.selected_index = None;
                self.junk_items.clear();
                self.registry_remnants.clear();
            }
        }

        // Top Toolbar
        let top_panel = egui::TopBottomPanel::top("top_toolbar").show(ctx, |ui| {
            ui.add_space(6.0);

            // Row 1: Header title on the left, footprint chip & status on the right
            ui.horizontal(|ui| {
                let (dot_rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 4.5, theme::ACCENT);
                ui.label(RichText::new("RustUninstaller").size(18.0).strong());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.is_scanning {
                        ui.spinner();
                    }
                    ui.colored_label(theme::TEXT_MUTED, &self.status_text);
                    if !self.cached_indices.is_empty() {
                        draw_pill(
                            ui,
                            &format!(
                                "{} apps · {}",
                                self.cached_indices.len(),
                                format_bytes(self.total_filtered_bytes)
                            ),
                            theme::BG_ELEVATED,
                            theme::TEXT_PRIMARY,
                        );
                    }
                });
            });

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            // Row 2: Search, sort options, filters and action buttons (wrapped so nothing clips at min width)
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(theme::TEXT_MUTED, "Search:");
                let search_box = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .id(search_id)
                        .desired_width(180.0)
                        .hint_text("Filter name or publisher (Ctrl+F)..."),
                );
                if search_box.changed() {
                    self.selected_index = None;
                    self.recompute_filtered_indices();
                }

                if self.scan_dir_filter.is_some() && ui.button("Clear Dir Filter").clicked() {
                    self.scan_dir_filter = None;
                    self.recompute_filtered_indices();
                }

                ui.separator();

                ui.colored_label(theme::TEXT_MUTED, "Sort:");
                let prev_sort = self.sort_option;
                egui::ComboBox::from_id_salt("sort_combo")
                    .selected_text(match self.sort_option {
                        SortOption::NameAsc => "Name (A-Z)",
                        SortOption::NameDesc => "Name (Z-A)",
                        SortOption::SizeDesc => "Size (High-Low)",
                        SortOption::SizeAsc => "Size (Low-High)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.sort_option, SortOption::NameAsc, "Name (A-Z)");
                        ui.selectable_value(&mut self.sort_option, SortOption::NameDesc, "Name (Z-A)");
                        ui.selectable_value(&mut self.sort_option, SortOption::SizeDesc, "Size (High-Low)");
                        ui.selectable_value(&mut self.sort_option, SortOption::SizeAsc, "Size (Low-High)");
                    });
                if self.sort_option != prev_sort {
                    self.recompute_filtered_indices();
                }

                ui.separator();

                let store_cb = ui
                    .add_enabled(!self.is_scanning, egui::Checkbox::new(&mut self.include_store, "Store Apps"));
                if store_cb.changed() {
                    self.start_scan();
                }
                show_fade_tooltip(ui, &store_cb, "Include Universal Windows Platform (UWP) apps");

                let sys_cb = ui.checkbox(&mut self.show_system_components, "Show System");
                if sys_cb.changed() {
                    self.recompute_filtered_indices();
                }
                show_fade_tooltip(ui, &sys_cb, "Show Windows SystemComponent entries");

                ui.separator();

                let refresh_btn = ui.add_enabled(!self.is_scanning, egui::Button::new("Refresh"));
                if refresh_btn.clicked() {
                    self.start_scan();
                }
                show_fade_tooltip(ui, &refresh_btn, "Rescan registry and installed applications (F5)");

                let checked_count = self.checked_indices.len();
                if checked_count > 0 {
                    ui.separator();
                    let label = if self.checked_total_bytes > 0 {
                        format!(
                            "Uninstall Selected ({} · {})",
                            checked_count,
                            format_bytes(self.checked_total_bytes)
                        )
                    } else {
                        format!("Uninstall Selected ({})", checked_count)
                    };
                    let uninstall_btn = ui.add_enabled(
                        !self.is_scanning,
                        egui::Button::new(RichText::new(label).color(Color32::WHITE).strong())
                            .fill(theme::DANGER_BTN),
                    );
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
            ui.add_space(6.0);
        });

        if self.is_scanning || self.is_scanning_junk || self.is_scanning_registry {
            draw_top_progress_bar(ctx, top_panel.response.rect);
        }

        // Bottom status / detail panel
        let selected_app = self.selected_index.and_then(|idx| self.apps.get(idx)).cloned();

        if let Some(app) = selected_app {
            egui::TopBottomPanel::bottom("detail_panel")
                .resizable(true)
                .default_height(260.0)
                .show(ctx, |ui| {
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        if let Some(tex) = self.icon_textures.get(&app.id) {
                            ui.image((tex.id(), Vec2::splat(18.0)));
                        } else {
                            draw_monogram_icon(ui, &app.display_name);
                        }
                        ui.label(RichText::new(&app.display_name).size(16.0).strong());
                        if app.is_protected {
                            draw_pill(ui, "PROTECTED", Color32::from_rgb(74, 54, 18), Color32::from_rgb(253, 224, 71));
                        }
                        if is_uninstaller_missing(&app) {
                            draw_pill(ui, "BROKEN", Color32::from_rgb(76, 29, 34), Color32::from_rgb(252, 165, 165));
                        }
                        ui.separator();

                        if let Some(ref loc) = app.install_location {
                            let exists = loc.exists();
                            let open_btn = ui.add_enabled(exists, egui::Button::new("Open Folder"));
                            show_fade_tooltip(ui, &open_btn, "Open installation folder in Windows Explorer");
                            if open_btn.clicked() {
                                let _ = Command::new("explorer.exe").arg(loc).spawn();
                            }
                        }

                        if app.uninstaller_kind != UninstallerKind::StoreApp && app.registry_location.is_some() {
                            let force_btn = ui.add_enabled(!self.is_scanning, egui::Button::new("Force Uninstall"));
                            show_fade_tooltip(ui, &force_btn, "Remove Uninstall registry entry and scan leftovers");
                            if force_btn.clicked() {
                                self.pending_confirm = Some(ConfirmAction::ForceUninstall { app: app.clone() });
                            }
                        }

                        if app.quiet_uninstall_string.is_some() {
                            let quiet_btn = ui.add_enabled(
                                !self.is_scanning,
                                egui::Button::new(RichText::new("Run Quiet Uninstall").color(Color32::WHITE))
                                    .fill(theme::ACCENT),
                            );
                            show_fade_tooltip(ui, &quiet_btn, "Run vendor uninstaller in silent/unattended mode");
                            if quiet_btn.clicked() {
                                self.request_uninstall_targets(vec![app.clone()]);
                            }
                        }

                        let junk_btn = ui.button("Scan Leftover Junk");
                        show_fade_tooltip(ui, &junk_btn, "Detect orphaned folders and files in ProgramFiles/AppData");
                        if junk_btn.clicked() {
                            let name = app.display_name.clone();
                            let dir = app.install_location.clone();
                            self.start_junk_scan(name, dir);
                        }

                        let reg_btn = ui.button("Scan Deep Registry");
                        show_fade_tooltip(ui, &reg_btn, "Search HKCU/HKLM for leftover keys and values");
                        if reg_btn.clicked() {
                            self.start_registry_scan(app.clone());
                        }
                    });

                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);

                    ui.columns(2, |cols| {
                        // Left inspector column: key-value metadata grid
                        egui::Grid::new("detail_meta_grid")
                            .num_columns(2)
                            .spacing([12.0, 5.0])
                            .show(&mut cols[0], |ui| {
                                let meta_row = |ui: &mut Ui, label: &str, val: &str| {
                                    ui.colored_label(theme::TEXT_MUTED, label);
                                    ui.label(val);
                                    ui.end_row();
                                };
                                meta_row(ui, "ID", &app.id);
                                meta_row(ui, "Version", app.display_version.as_deref().unwrap_or("-"));
                                meta_row(ui, "Publisher", app.publisher.as_deref().unwrap_or("-"));
                                meta_row(ui, "Installer", &format!("{:?}", app.uninstaller_kind));
                                meta_row(ui, "Estimated Size", &format_size(app.estimated_size_bytes));
                                let path_str = app
                                    .install_location
                                    .as_ref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "-".into());
                                meta_row(ui, "Install Path", &path_str);
                                meta_row(ui, "Quiet Command", app.quiet_uninstall_string.as_deref().unwrap_or("-"));
                            });

                        // Right inspector column: leftovers & registry remnants
                        cols[1].horizontal(|ui| {
                            ui.strong("Leftover Junk");
                            draw_pill(
                                ui,
                                &self.junk_items.len().to_string(),
                                theme::BG_ELEVATED,
                                theme::TEXT_PRIMARY,
                            );
                            if !self.junk_items.is_empty() {
                                let recycle_btn = ui.button("Send Safe Junk to Recycle Bin");
                                show_fade_tooltip(ui, &recycle_btn, "Move safe leftover files to Windows Recycle Bin");
                                if recycle_btn.clicked() {
                                    let safe_junk = filter_safe_junk(&self.junk_items);
                                    let (cleaned, errors) = clean_junk_items(&safe_junk, false);
                                    let summary = build_cleanup_summary(
                                        &[app.display_name.clone()],
                                        &safe_junk,
                                        &[],
                                        cleaned,
                                        &errors,
                                        0,
                                    );
                                    self.status_text = match maybe_create_desktop_zip(cleaned, None, &summary) {
                                        Some(Ok(zp)) => format!("Recycled {} item(s). Backup: {}", cleaned, zp.display()),
                                        Some(Err(e)) => format!("Recycled {} item(s). Zip backup failed: {}", cleaned, e),
                                        None if errors.is_empty() => format!("Recycled {} safe item(s).", cleaned),
                                        None => format!("Recycled 0 item(s), {} failed.", errors.len()),
                                    };
                                    if cleaned > 0 {
                                        self.junk_items.clear();
                                    }
                                }
                            }
                        });
                        if self.junk_items.is_empty() {
                            cols[1].colored_label(
                                theme::TEXT_MUTED,
                                if self.is_scanning_junk { "Scanning disk..." } else { "No disk remnants scanned yet." },
                            );
                        } else {
                            egui::ScrollArea::vertical().id_salt("junk_scroll").max_height(68.0).show(&mut cols[1], |ui| {
                                for item in &self.junk_items {
                                    ui.horizontal(|ui| {
                                        let (lbl, bg, fg) = confidence_badge_colors(&item.confidence);
                                        draw_pill(ui, lbl, bg, fg);
                                        ui.label(item.path.display().to_string());
                                    });
                                }
                            });
                        }

                        cols[1].add_space(6.0);
                        cols[1].horizontal(|ui| {
                            ui.strong("Deep Registry");
                            draw_pill(
                                ui,
                                &self.registry_remnants.len().to_string(),
                                theme::BG_ELEVATED,
                                theme::TEXT_PRIMARY,
                            );
                            if !self.registry_remnants.is_empty() {
                                let clean_reg_btn = ui.button("Backup & Clean Registry");
                                show_fade_tooltip(ui, &clean_reg_btn, "Export rollback backup .reg + Desktop .zip before cleaning");
                                if clean_reg_btn.clicked() {
                                    let safe_remnants = filter_safe_remnants(&self.registry_remnants);
                                    match clean_registry_remnants(&safe_remnants, None, &app.id) {
                                        Ok((backup_path, deleted, errors)) => {
                                            let summary = build_cleanup_summary(
                                                &[app.display_name.clone()],
                                                &[],
                                                &safe_remnants,
                                                0,
                                                &errors,
                                                deleted,
                                            );
                                            let zip_path = maybe_create_desktop_zip(
                                                deleted,
                                                Some(&backup_path),
                                                &summary,
                                            )
                                            .and_then(Result::ok);
                                            let shown_backup = zip_path.unwrap_or(backup_path);
                                            self.status_text = if errors.is_empty() {
                                                format!(
                                                    "Cleaned {} registry remnant(s)! Backup: {}",
                                                    deleted,
                                                    shown_backup.display()
                                                )
                                            } else {
                                                format!(
                                                    "Cleaned {} remnant(s), {} failed (try Run as Administrator). Backup: {}",
                                                    deleted,
                                                    errors.len(),
                                                    shown_backup.display()
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
                        });
                        if self.registry_remnants.is_empty() {
                            cols[1].colored_label(
                                theme::TEXT_MUTED,
                                if self.is_scanning_registry { "Scanning registry..." } else { "No registry remnants scanned yet." },
                            );
                        } else {
                            egui::ScrollArea::vertical().id_salt("reg_scroll").max_height(68.0).show(&mut cols[1], |ui| {
                                for rem in &self.registry_remnants {
                                    ui.horizontal(|ui| {
                                        let (lbl, bg, fg) = confidence_badge_colors(&rem.confidence);
                                        draw_pill(ui, lbl, bg, fg);
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
        }

        // Central Panel
        egui::CentralPanel::default().show(ctx, |ui| {
            let indices = self.cached_indices.clone();
            self.render_table(ui, &indices);
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
                    let reg_backup_path = reg_res.as_ref().and_then(|r| r.as_ref().ok()).map(|(p, _, _)| p.as_path());
                    let reg_cleaned = reg_res.as_ref().and_then(|r| r.as_ref().ok()).map(|(_, c, _)| *c).unwrap_or(0);
                    let mut all_errors = disk_errors.clone();
                    if let Some(Ok((_, _, ref reg_errs))) = reg_res {
                        all_errors.extend(reg_errs.iter().cloned());
                    }
                    let summary = build_cleanup_summary(
                        &modal.app_names,
                        &junk,
                        &remnants,
                        disk_cleaned,
                        &all_errors,
                        reg_cleaned,
                    );
                    let zip_path = maybe_create_desktop_zip(
                        disk_cleaned + reg_cleaned,
                        reg_backup_path,
                        &summary,
                    )
                    .and_then(Result::ok);
                    self.status_text = format_cleanup_status(disk_cleaned, &disk_errors, reg_res, zip_path);
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
            egui::Window::new("Confirmation")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    match &confirm {
                        ConfirmAction::BatchUninstall { targets } => {
                            ui.label(format!(
                                "Selection includes protected (NoRemove) app(s). Uninstall {} app(s)?",
                                targets.len()
                            ));
                        }
                        ConfirmAction::ForceUninstall { app } => {
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
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Continue").clicked() {
                            keep_open = false;
                            self.execute_confirm_action(confirm.clone());
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
        match action {
            ConfirmAction::BatchUninstall { targets } => {
                self.start_batch_uninstall(targets);
            }
            ConfirmAction::ForceUninstall { app } => {
                match force_remove_uninstall_entry(&app, None) {
                    Ok(backup_path) => {
                        let summary = format!(
                            "Force Uninstall: {}\r\nRegistry backup: {}\r\n",
                            app.display_name,
                            backup_path.display()
                        );
                        let zip_path = RegBackup::create_desktop_backup_zip(Some(&backup_path), &summary)
                            .unwrap_or(backup_path);
                        self.clear_selection_and_details();
                        self.apps = rescan_all(self.include_store);
                        self.recompute_filtered_indices();
                        self.status_text = format!(
                            "Force-removed '{}'. Backup: {}",
                            app.display_name,
                            zip_path.display()
                        );
                        self.start_post_uninstall_scan(vec![app]);
                    }
                    Err(e) => {
                        self.status_text = format!("Force Uninstall failed: {}", e);
                    }
                }
            }
        }
    }

    fn start_batch_uninstall(&mut self, targets: Vec<ApplicationEntry>) {
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
                        let res = run_uninstall_and_wait(&cmd);
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
            .header(28.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Sel");
                });

                header.col(|ui| {
                    let name_label = match self.sort_option {
                        SortOption::NameAsc => "Display Name ^",
                        SortOption::NameDesc => "Display Name v",
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
                        SortOption::SizeDesc => "Size v",
                        SortOption::SizeAsc => "Size ^",
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
                let max_size = self.max_filtered_size_bytes;
                body.rows(28.0, indices.len(), |mut row| {
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
                                let row_rect = ui.available_rect_before_wrap();
                                let resp = ui.interact(
                                    row_rect,
                                    ui.id().with(("name_cell", original_index)),
                                    Sense::click(),
                                );
                                let highlight = ui.ctx().animate_bool(
                                    ui.id().with(("row_anim", original_index)),
                                    resp.hovered() || is_selected,
                                );
                                if highlight > 0.01 {
                                    let alpha = if is_selected { 220 } else { (110.0 * highlight) as u8 };
                                    ui.painter().rect_filled(
                                        row_rect.shrink2(Vec2::new(2.0, 1.0)),
                                        Rounding::same(5.0),
                                        Color32::from_rgba_unmultiplied(41, 56, 82, alpha),
                                    );
                                    if is_selected {
                                        ui.painter().rect_stroke(
                                            row_rect.shrink2(Vec2::new(2.0, 1.0)),
                                            Rounding::same(5.0),
                                            Stroke::new(1.0_f32, theme::ACCENT),
                                        );
                                    }
                                }

                                ui.horizontal(|ui| {
                                    ui.add_space(4.0);
                                    if let Some(tex) = self.icon_textures.get(&app.id) {
                                        ui.image((tex.id(), Vec2::splat(16.0)));
                                    } else {
                                        draw_monogram_icon(ui, &app.display_name);
                                    }
                                    ui.add(
                                        egui::Label::new(RichText::new(&app.display_name).color(
                                            if is_selected { Color32::WHITE } else { theme::TEXT_PRIMARY },
                                        ))
                                        .truncate(),
                                    );
                                });

                                if resp.clicked() {
                                    newly_selected = Some(original_index);
                                }
                            });

                            row.col(|ui| {
                                let cell_rect = ui.available_rect_before_wrap();
                                let ratio = size_bar_ratio(app.estimated_size_bytes, max_size);
                                if ratio > 0.0 {
                                    let bar_w = (cell_rect.width() - 4.0) * ratio;
                                    let bar_rect = Rect::from_min_size(
                                        Pos2::new(cell_rect.left() + 2.0, cell_rect.top() + 4.0),
                                        Vec2::new(bar_w.max(3.0), (cell_rect.height() - 8.0).max(4.0)),
                                    );
                                    ui.painter().rect_filled(
                                        bar_rect,
                                        Rounding::same(3.0),
                                        Color32::from_rgba_unmultiplied(59, 130, 246, 48),
                                    );
                                }
                                let size_text = format_size(app.estimated_size_bytes);
                                let color = if app.estimated_size_bytes.is_some() {
                                    Color32::from_rgb(147, 197, 253)
                                } else {
                                    theme::TEXT_MUTED
                                };
                                ui.add_space(4.0);
                                ui.colored_label(color, size_text);
                            });

                            row.col(|ui| {
                                ui.colored_label(
                                    theme::TEXT_MUTED,
                                    app.display_version.as_deref().unwrap_or("-"),
                                );
                            });

                            row.col(|ui| {
                                let (bg, fg) = kind_badge_colors(&app.uninstaller_kind);
                                draw_pill(ui, &format!("{:?}", app.uninstaller_kind), bg, fg);
                            });

                            row.col(|ui| {
                                let has_quiet = app.quiet_uninstall_string.is_some();
                                let (bg, fg) = quiet_badge_colors(has_quiet);
                                draw_pill(ui, if has_quiet { "YES" } else { "NO" }, bg, fg);
                            });

                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(app.publisher.as_deref().unwrap_or("-"))
                                            .color(theme::TEXT_MUTED),
                                    )
                                    .truncate(),
                                );
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
            self.recompute_checked_bytes();
        }

        if let Some(idx) = newly_selected {
            self.selected_index = Some(idx);
            self.junk_items.clear();
            self.registry_remnants.clear();
        }
    }
}

fn filter_safe_junk(items: &[JunkItem]) -> Vec<JunkItem> {
    items
        .iter()
        .filter(|j| !j.is_registry && j.confidence == ConfidenceLevel::Safe)
        .cloned()
        .collect()
}

fn filter_safe_remnants(remnants: &[RegistryRemnant]) -> Vec<RegistryRemnant> {
    remnants
        .iter()
        .filter(|r| r.confidence == ConfidenceLevel::Safe)
        .cloned()
        .collect()
}

fn maybe_create_desktop_zip(
    deleted_count: usize,
    reg_backup_path: Option<&Path>,
    summary: &str,
) -> Option<std::io::Result<PathBuf>> {
    if deleted_count == 0 {
        return None;
    }
    Some(RegBackup::create_desktop_backup_zip(reg_backup_path, summary))
}

fn build_cleanup_summary(
    app_names: &[String],
    junk: &[JunkItem],
    remnants: &[RegistryRemnant],
    disk_cleaned: usize,
    errors: &[String],
    reg_cleaned: usize,
) -> String {
    let mut out = format!(
        "RustUninstaller Cleanup Backup\r\nApps: {}\r\nDisk recycled: {}\r\nRegistry cleaned: {}\r\n\r\n",
        if app_names.is_empty() { "Selected".into() } else { app_names.join(", ") },
        disk_cleaned,
        reg_cleaned
    );
    if !junk.is_empty() {
        out.push_str("Disk items:\r\n");
        for j in junk {
            out.push_str(&format!("- {}\r\n", j.path.display()));
        }
        out.push_str("\r\n");
    }
    if !remnants.is_empty() {
        out.push_str("Registry remnants:\r\n");
        for r in remnants {
            let target = match &r.value_name {
                Some(vn) => format!(r"{}\{} -> {}", r.hive, r.subkey, vn),
                None => format!(r"{}\{}", r.hive, r.subkey),
            };
            out.push_str(&format!("- {}\r\n", target));
        }
        out.push_str("\r\n");
    }
    if !errors.is_empty() {
        out.push_str("Errors:\r\n");
        for e in errors {
            out.push_str(&format!("- {}\r\n", e));
        }
    }
    out
}

fn format_cleanup_status(
    disk_cleaned: usize,
    disk_errors: &[String],
    reg_res: Option<std::io::Result<(PathBuf, usize, Vec<String>)>>,
    zip_backup_path: Option<PathBuf>,
) -> String {
    let mut parts = vec![format!("recycled {} disk item(s)", disk_cleaned)];
    let mut err_count = disk_errors.len();
    let mut backup_note = zip_backup_path
        .map(|zp| format!(" Backup: {}", zp.display()))
        .unwrap_or_default();

    match reg_res {
        Some(Ok((backup_path, reg_cleaned, reg_errors))) => {
            parts.push(format!("cleaned {} registry remnant(s)", reg_cleaned));
            err_count += reg_errors.len();
            if backup_note.is_empty() {
                backup_note = format!(" Backup: {}", backup_path.display());
            }
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
    let norm = |s: &str| {
        s.trim()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase()
    };
    let target = norm(target_dir);
    !target.is_empty() && norm(&loc.to_string_lossy()) == target
}

fn format_size(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) if b > 0 => format_bytes(b),
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
    // shortcut: unexpanded %VAR% paths assumed valid, expand via ExpandEnvironmentStringsW if needed later
    if exe.contains('%') {
        return false;
    }
    (exe.contains('\\') || exe.contains('/')) && !std::path::Path::new(&exe).exists()
}

fn is_uninstall_success(code: Option<i32>) -> bool {
    matches!(code, Some(0 | 3010))
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

fn run_uninstall_and_wait(cmd: &str) -> std::io::Result<()> {
    let mut child = launch_uninstall_command(cmd)?;
    loop {
        if let Some(status) = child.try_wait()? {
            if is_uninstall_success(status.code()) {
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "Uninstaller exited with status {}",
                status
            )));
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
            display_icon: None,
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
            display_icon: None,
        };
        assert!(is_uninstaller_missing(&app));

        app.uninstall_string = Some(r#""%LocalAppData%\Discord\Update.exe" --uninstall"#.into());
        assert!(!is_uninstaller_missing(&app));

        app.uninstaller_kind = UninstallerKind::StoreApp;
        assert!(!is_uninstaller_missing(&app));
    }

    #[test]
    fn test_is_uninstall_success_accepts_zero_and_3010() {
        assert!(is_uninstall_success(Some(0)));
        assert!(is_uninstall_success(Some(3010)));
        assert!(!is_uninstall_success(Some(1603)));
        assert!(!is_uninstall_success(None));
    }

    #[test]
    fn test_matches_scan_dir_normalizes_trailing_slash_and_case() {
        assert!(matches_install_dir(
            Some(std::path::Path::new(r"C:\Program Files\VLC")),
            r"c:\program files\vlc\"
        ));
        assert!(matches_install_dir(
            Some(std::path::Path::new(r"C:\Program Files\VLC")),
            "c:/program files/vlc/"
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
            display_icon: None,
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
            Some(Ok((PathBuf::from(r"C:\backup.reg"), 0, vec!["HKLM err".into()]))),
            Some(PathBuf::from(r"C:\Users\Admin\Desktop\backup(2026-11-28_16-10-00).zip")),
        );
        assert!(msg.contains("failed"));
        assert!(msg.contains("Run as Administrator"));
        assert!(msg.contains("backup(2026-11-28_16-10-00).zip"));
    }

    #[test]
    fn test_safe_junk_filter_excludes_questionable_and_dangerous() {
        let items = vec![
            JunkItem {
                path: PathBuf::from(r"C:\Safe"),
                is_registry: false,
                confidence: ConfidenceLevel::Safe,
                reason: "safe".into(),
                size_bytes: Some(10),
            },
            JunkItem {
                path: PathBuf::from(r"C:\Maybe"),
                is_registry: false,
                confidence: ConfidenceLevel::Questionable,
                reason: "maybe".into(),
                size_bytes: Some(20),
            },
            JunkItem {
                path: PathBuf::from(r"C:\Windows"),
                is_registry: false,
                confidence: ConfidenceLevel::Dangerous,
                reason: "danger".into(),
                size_bytes: None,
            },
        ];
        let safe = filter_safe_junk(&items);
        assert_eq!(safe.len(), 1);
        assert_eq!(safe[0].path, PathBuf::from(r"C:\Safe"));
        assert!(maybe_create_desktop_zip(0, None, "none").is_none());
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

