use crate::models::{ConfidenceLevel, JunkItem};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const PROTECTED_NAMES: &[&str] = &[
    "windows",
    "system32",
    "syswow64",
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    "roaming",
    "local",
    "locallow",
    "users",
    "documents and settings",
    "common files",
    "microsoft",
    "default",
    "public",
    "all users",
];

pub fn evaluate_confidence(
    path: &Path,
    app_name: &str,
    known_install_dir: Option<&Path>,
) -> ConfidenceLevel {
    let lower_path = path.to_string_lossy().to_lowercase();
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Check if the path or file name is an OS protected root
    for &protected in PROTECTED_NAMES {
        if file_name == protected {
            return ConfidenceLevel::Dangerous;
        }
    }

    if lower_path.ends_with(r":\") || lower_path.ends_with(r":") {
        return ConfidenceLevel::Dangerous;
    }

    if lower_path.contains(r"\windows\system32") || lower_path == r"c:\windows" {
        return ConfidenceLevel::Dangerous;
    }

    // Exact match with known install directory
    if let Some(install_dir) = known_install_dir {
        if path == install_dir {
            return ConfidenceLevel::Safe;
        }
    }

    // Exact name match under AppData or ProgramData
    let lower_app = app_name.trim().to_lowercase();
    if file_name == lower_app {
        return ConfidenceLevel::Safe;
    }

    // Substring match
    if file_name.contains(&lower_app) {
        return ConfidenceLevel::Questionable;
    }

    ConfidenceLevel::Questionable
}

pub fn scan_disk_junk(app_name: &str, known_install_dir: Option<&Path>) -> Vec<JunkItem> {
    let trimmed_app = app_name.trim();
    if trimmed_app.is_empty() {
        return Vec::new();
    }

    let search_roots = get_candidate_search_roots();

    search_roots
        .par_iter()
        .flat_map(|root| {
            let mut found = Vec::new();
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_dir() {
                        let file_name = entry.file_name();
                        let name = file_name.to_string_lossy();

                        if crate::heuristics::matches_app_name(&name, trimmed_app) {
                            let confidence = evaluate_confidence(&path, trimmed_app, known_install_dir);
                            found.push(JunkItem {
                                path: path.clone(),
                                is_registry: false,
                                confidence,
                                reason: format!("Directory matches application name '{}'", trimmed_app),
                            });
                        }
                    }
                }
            }
            found
        })
        .collect()
}

fn get_candidate_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(pf) = env::var("ProgramFiles") {
        roots.push(PathBuf::from(pf));
    }
    if let Ok(pf86) = env::var("ProgramFiles(x86)") {
        roots.push(PathBuf::from(pf86));
    }
    if let Ok(pd) = env::var("ProgramData") {
        roots.push(PathBuf::from(pd));
    }
    if let Ok(appdata) = env::var("APPDATA") {
        roots.push(PathBuf::from(appdata));
    }
    if let Ok(localappdata) = env::var("LOCALAPPDATA") {
        roots.push(PathBuf::from(localappdata));
    }

    roots
}
