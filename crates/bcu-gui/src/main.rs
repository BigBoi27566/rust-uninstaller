#![windows_subsystem = "windows"]

mod app;
mod cleanup_modal;
mod theme;

use app::BcuApp;
use eframe::egui;
use std::sync::Arc;

fn load_app_icon() -> Option<Arc<egui::IconData>> {
    let png_bytes = include_bytes!("../assets/icon.png");
    image::load_from_memory(png_bytes).ok().map(|img| {
        let rgba = img.into_rgba8();
        let (width, height) = rgba.dimensions();
        Arc::new(egui::IconData {
            rgba: rgba.into_raw(),
            width,
            height,
        })
    })
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1100.0, 700.0])
        .with_min_inner_size([750.0, 450.0])
        .with_title("RustUninstaller");

    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "RustUninstaller",
        native_options,
        Box::new(|cc| Ok(Box::new(BcuApp::new(cc)))),
    )
}
