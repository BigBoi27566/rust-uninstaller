use bcu_core::models::{ConfidenceLevel, UninstallerKind};
use eframe::egui::{self, Color32, Pos2, Rect, Rounding, Stroke, Ui, Vec2};

pub const BG_BASE: Color32 = Color32::from_rgb(18, 20, 24);
pub const BG_SURFACE: Color32 = Color32::from_rgb(25, 28, 34);
pub const BG_ELEVATED: Color32 = Color32::from_rgb(33, 38, 48);
pub const BG_HOVER: Color32 = Color32::from_rgb(41, 48, 61);
pub const BORDER: Color32 = Color32::from_rgb(42, 48, 60);
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(232, 236, 244);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(154, 164, 184);
pub const ACCENT: Color32 = Color32::from_rgb(59, 130, 246);
pub const ACCENT_FILL: Color32 = Color32::from_rgb(29, 44, 68);
pub const DANGER_BTN: Color32 = Color32::from_rgb(185, 28, 28);

/// Applies the 3-layer dark desktop theme to `egui::Context`.
pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.dark_mode = true;
    visuals.panel_fill = BG_SURFACE;
    visuals.window_fill = BG_SURFACE;
    visuals.extreme_bg_color = BG_BASE;
    visuals.faint_bg_color = Color32::from_rgb(21, 24, 30);
    visuals.window_rounding = Rounding::same(8.0);
    visuals.window_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.override_text_color = Some(TEXT_PRIMARY);

    visuals.selection.bg_fill = ACCENT_FILL;
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);

    visuals.widgets.noninteractive.bg_fill = BG_SURFACE;
    visuals.widgets.noninteractive.weak_bg_fill = BG_SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_MUTED);
    visuals.widgets.noninteractive.rounding = Rounding::same(6.0);

    visuals.widgets.inactive.bg_fill = BG_ELEVATED;
    visuals.widgets.inactive.weak_bg_fill = BG_ELEVATED;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.inactive.rounding = Rounding::same(6.0);

    visuals.widgets.hovered.bg_fill = BG_HOVER;
    visuals.widgets.hovered.weak_bg_fill = BG_HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.hovered.rounding = Rounding::same(6.0);

    visuals.widgets.active.bg_fill = ACCENT_FILL;
    visuals.widgets.active.weak_bg_fill = ACCENT_FILL;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.active.rounding = Rounding::same(6.0);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 4.0);
    style.spacing.indent = 16.0;
    ctx.set_style(style);
}

/// Computes normalized width ratio (0.0..=1.0) for inline size bars.
pub fn size_bar_ratio(size_bytes: Option<u64>, max_size_bytes: u64) -> f32 {
    match size_bytes {
        Some(b) if b > 0 && max_size_bytes > 0 => ((b as f64) / (max_size_bytes as f64)).clamp(0.0, 1.0) as f32,
        _ => 0.0,
    }
}

/// Renders a compact rounded semantic pill badge.
pub fn draw_pill(ui: &mut Ui, text: &str, bg: Color32, fg: Color32) {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, fg);
    let size = Vec2::new(galley.size().x + 12.0, 18.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().rect_filled(rect, Rounding::same(9.0), bg);
    let text_pos = Pos2::new(rect.left() + 6.0, rect.center().y - galley.size().y * 0.5);
    ui.painter().galley(text_pos, galley, fg);
}

pub fn kind_badge_colors(kind: &UninstallerKind) -> (Color32, Color32) {
    match kind {
        UninstallerKind::Msi => (Color32::from_rgb(30, 58, 95), Color32::from_rgb(147, 197, 253)),
        UninstallerKind::InnoSetup => (Color32::from_rgb(58, 42, 82), Color32::from_rgb(216, 180, 254)),
        UninstallerKind::Nsis => (Color32::from_rgb(24, 60, 68), Color32::from_rgb(103, 232, 249)),
        UninstallerKind::InstallShield | UninstallerKind::AdvancedInstaller => {
            (Color32::from_rgb(68, 52, 24), Color32::from_rgb(253, 224, 71))
        }
        UninstallerKind::StoreApp => (Color32::from_rgb(28, 52, 78), Color32::from_rgb(125, 211, 252)),
        UninstallerKind::Unknown => (Color32::from_rgb(40, 44, 52), Color32::from_rgb(156, 163, 175)),
    }
}

pub fn quiet_badge_colors(has_quiet: bool) -> (Color32, Color32) {
    if has_quiet {
        (Color32::from_rgb(22, 58, 42), Color32::from_rgb(110, 231, 183))
    } else {
        (Color32::from_rgb(42, 46, 56), Color32::from_rgb(156, 163, 175))
    }
}

pub fn confidence_badge_colors(level: &ConfidenceLevel) -> (&'static str, Color32, Color32) {
    match level {
        ConfidenceLevel::Safe => ("SAFE", Color32::from_rgb(22, 58, 42), Color32::from_rgb(110, 231, 183)),
        ConfidenceLevel::Questionable => {
            ("MAYBE", Color32::from_rgb(74, 54, 18), Color32::from_rgb(253, 224, 71))
        }
        ConfidenceLevel::Dangerous => ("LOCKED", Color32::from_rgb(76, 29, 34), Color32::from_rgb(252, 165, 165)),
    }
}

/// Draws a smooth 2px indeterminate scanning bar along the bottom edge of `panel_rect`.
pub fn draw_top_progress_bar(ctx: &egui::Context, panel_rect: Rect) {
    let t = ctx.input(|i| i.time) as f32;
    let width = panel_rect.width();
    if width <= 10.0 {
        return;
    }
    let bar_w = (width * 0.24).clamp(80.0, 220.0);
    let travel = width + bar_w;
    let offset = (t * 420.0) % travel - bar_w;
    let bar_rect = Rect::from_min_max(
        Pos2::new((panel_rect.left() + offset).max(panel_rect.left()), panel_rect.bottom() - 2.0),
        Pos2::new(
            (panel_rect.left() + offset + bar_w).min(panel_rect.right()),
            panel_rect.bottom(),
        ),
    );
    let painter = ctx.debug_painter();
    painter.rect_filled(bar_rect, Rounding::ZERO, ACCENT);
    ctx.request_repaint();
}

/// Draws a deterministic 16x16 monogram badge when an app icon cannot be extracted.
pub fn draw_monogram_icon(ui: &mut Ui, app_name: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), egui::Sense::hover());
    let first = app_name
        .trim()
        .chars()
        .find(|c| c.is_alphanumeric())
        .unwrap_or('A')
        .to_ascii_uppercase();
    let palette = [
        Color32::from_rgb(37, 99, 235),
        Color32::from_rgb(13, 148, 136),
        Color32::from_rgb(124, 58, 237),
        Color32::from_rgb(217, 119, 6),
        Color32::from_rgb(190, 24, 93),
    ];
    let hash: usize = app_name.bytes().fold(0usize, |acc, b| acc.wrapping_add(b as usize));
    let bg = palette[hash % palette.len()];
    ui.painter().rect_filled(rect, Rounding::same(4.0), bg);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        first.to_string(),
        egui::FontId::proportional(10.0),
        Color32::WHITE,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_bar_ratio_clamps_and_handles_zero() {
        assert_eq!(size_bar_ratio(None, 1000), 0.0);
        assert_eq!(size_bar_ratio(Some(500), 0), 0.0);
        assert!((size_bar_ratio(Some(250), 1000) - 0.25).abs() < 1e-6);
        assert!((size_bar_ratio(Some(2000), 1000) - 1.0).abs() < 1e-6);
    }
}
