use bcu_core::models::{ConfidenceLevel, JunkItem};
use bcu_core::registry_deep::RegistryRemnant;
use eframe::egui::{self, Color32};

/// Formats a byte count into a human-readable B/KB/MB/GB string.
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

pub enum CleanupAction {
    Clean {
        junk: Vec<JunkItem>,
        remnants: Vec<RegistryRemnant>,
    },
    Skip,
}

pub struct CleanupModalState {
    pub app_names: Vec<String>,
    pub junk_items: Vec<JunkItem>,
    pub junk_checked: Vec<bool>,
    pub registry_remnants: Vec<RegistryRemnant>,
    pub reg_checked: Vec<bool>,
}

impl CleanupModalState {
    pub fn from_results(
        app_names: Vec<String>,
        junk_items: Vec<JunkItem>,
        registry_remnants: Vec<RegistryRemnant>,
    ) -> Self {
        let junk_checked = junk_items
            .iter()
            .map(|j| j.confidence == ConfidenceLevel::Safe)
            .collect();
        let reg_checked = registry_remnants
            .iter()
            .map(|r| r.confidence == ConfidenceLevel::Safe)
            .collect();
        Self {
            app_names,
            junk_items,
            junk_checked,
            registry_remnants,
            reg_checked,
        }
    }

    pub fn reclaimable_bytes(&self) -> u64 {
        self.junk_items
            .iter()
            .zip(&self.junk_checked)
            .filter(|(item, &checked)| checked && item.confidence != ConfidenceLevel::Dangerous)
            .filter_map(|(item, _)| item.size_bytes)
            .sum()
    }

    pub fn show(&mut self, ctx: &egui::Context) -> Option<CleanupAction> {
        let mut action = None;
        let title = format!(
            "🧹 Leftover Cleanup ({})",
            if self.app_names.is_empty() {
                "Uninstalled App".to_string()
            } else {
                self.app_names.join(", ")
            }
        );

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_width(640.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(format!(
                    "Found {} disk item(s) and {} registry remnant(s). Reclaimable: {}",
                    self.junk_items.len(),
                    self.registry_remnants.len(),
                    format_bytes(self.reclaimable_bytes())
                ));
                ui.separator();

                if !self.junk_items.is_empty() {
                    ui.strong("Leftover Files & Shortcuts (moved to Recycle Bin):");
                    egui::ScrollArea::vertical()
                        .id_salt("cleanup_modal_junk")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            for (i, item) in self.junk_items.iter().enumerate() {
                                let is_dangerous = item.confidence == ConfidenceLevel::Dangerous;
                                ui.horizontal(|ui| {
                                    ui.add_enabled_ui(!is_dangerous, |ui| {
                                        ui.checkbox(&mut self.junk_checked[i], "");
                                    });
                                    confidence_badge(ui, &item.confidence);
                                    let size_label = item
                                        .size_bytes
                                        .map(format_bytes)
                                        .unwrap_or_else(|| "-".into());
                                    ui.label(format!("{} ({})", item.path.display(), size_label));
                                });
                            }
                        });
                    ui.add_space(6.0);
                }

                if !self.registry_remnants.is_empty() {
                    ui.strong("Registry Remnants (auto-backed up to .reg):");
                    egui::ScrollArea::vertical()
                        .id_salt("cleanup_modal_reg")
                        .max_height(140.0)
                        .show(ui, |ui| {
                            for (i, rem) in self.registry_remnants.iter().enumerate() {
                                let is_dangerous = rem.confidence == ConfidenceLevel::Dangerous;
                                ui.horizontal(|ui| {
                                    ui.add_enabled_ui(!is_dangerous, |ui| {
                                        ui.checkbox(&mut self.reg_checked[i], "");
                                    });
                                    confidence_badge(ui, &rem.confidence);
                                    let target = match &rem.value_name {
                                        Some(vn) => format!(r"{}\{} -> {}", rem.hive, rem.subkey, vn),
                                        None => format!(r"{}\{}", rem.hive, rem.subkey),
                                    };
                                    ui.label(target);
                                });
                            }
                        });
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("🗑️ Clean Selected").clicked() {
                        let junk = self
                            .junk_items
                            .iter()
                            .zip(&self.junk_checked)
                            .filter(|(item, &c)| c && item.confidence != ConfidenceLevel::Dangerous)
                            .map(|(item, _)| item.clone())
                            .collect();
                        let remnants = self
                            .registry_remnants
                            .iter()
                            .zip(&self.reg_checked)
                            .filter(|(rem, &c)| c && rem.confidence != ConfidenceLevel::Dangerous)
                            .map(|(rem, _)| rem.clone())
                            .collect();
                        action = Some(CleanupAction::Clean { junk, remnants });
                    }
                    if ui.button("Skip").clicked() {
                        action = Some(CleanupAction::Skip);
                    }
                });
            });

        action
    }
}

fn confidence_badge(ui: &mut egui::Ui, level: &ConfidenceLevel) {
    match level {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcu_core::models::{ConfidenceLevel, JunkItem};
    use std::path::PathBuf;

    #[test]
    fn test_cleanup_modal_defaults_and_reclaimable_bytes() {
        let junk = vec![
            JunkItem {
                path: PathBuf::from(r"C:\AppData\SafeApp"),
                is_registry: false,
                confidence: ConfidenceLevel::Safe,
                reason: "exact".into(),
                size_bytes: Some(1024),
            },
            JunkItem {
                path: PathBuf::from(r"C:\AppData\MaybeApp"),
                is_registry: false,
                confidence: ConfidenceLevel::Questionable,
                reason: "partial".into(),
                size_bytes: Some(2048),
            },
            JunkItem {
                path: PathBuf::from(r"C:\Windows\System32"),
                is_registry: false,
                confidence: ConfidenceLevel::Dangerous,
                reason: "protected".into(),
                size_bytes: None,
            },
        ];

        let state = CleanupModalState::from_results(vec!["SafeApp".into()], junk, Vec::new());
        assert_eq!(state.junk_checked, vec![true, false, false]);
        assert_eq!(state.reclaimable_bytes(), 1024);
    }
}
