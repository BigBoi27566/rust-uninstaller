use crate::models::{ConfidenceLevel, JunkItem};
use rayon::prelude::*;
use std::collections::HashSet;
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

/// Recursively computes total file size in bytes, skipping symlinks/junctions to prevent cycles.
pub fn dir_size_bytes(path: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return 0;
    }
    if meta.is_file() {
        return meta.len();
    }
    if !meta.is_dir() {
        return 0;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .map(|entry| dir_size_bytes(&entry.path()))
        .sum()
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
                            let size_bytes = if confidence == ConfidenceLevel::Dangerous {
                                None
                            } else {
                                Some(dir_size_bytes(&path))
                            };
                            found.push(JunkItem {
                                path: path.clone(),
                                is_registry: false,
                                confidence,
                                reason: format!("Directory matches application name '{}'", trimmed_app),
                                size_bytes,
                            });
                        }
                    }
                }
            }
            found
        })
        .collect()
}

/// Finds `.lnk` shortcuts in `dir` (and 1-level subfolders) whose stem matches `app_name`.
pub fn find_matching_shortcuts_in(dir: &Path, app_name: &str) -> Vec<JunkItem> {
    let mut found = Vec::new();
    let trimmed = app_name.trim();
    if trimmed.is_empty() || !dir.is_dir() {
        return found;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return found;
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            if let Ok(sub_entries) = fs::read_dir(&path) {
                for sub in sub_entries.filter_map(|e| e.ok()) {
                    collect_if_matching_shortcut(&sub.path(), trimmed, &mut found);
                }
            }
        } else {
            collect_if_matching_shortcut(&path, trimmed, &mut found);
        }
    }
    found
}

fn collect_if_matching_shortcut(path: &Path, app_name: &str, out: &mut Vec<JunkItem>) {
    let is_lnk = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
    if !is_lnk {
        return;
    }
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return;
    };
    if crate::heuristics::matches_app_name(stem, app_name) {
        let confidence = evaluate_confidence(Path::new(stem), app_name, None);
        let size_bytes = fs::symlink_metadata(path).map(|m| m.len()).ok();
        out.push(JunkItem {
            path: path.to_path_buf(),
            is_registry: false,
            confidence,
            reason: format!("Shortcut matches application name '{}'", app_name),
            size_bytes,
        });
    }
}

/// Deep disk scan including `LocalLow`, `Publisher\AppName` folders, and Start Menu/Desktop `.lnk` shortcuts.
pub fn scan_disk_junk_deep(
    app_name: &str,
    publisher: Option<&str>,
    known_install_dir: Option<&Path>,
) -> Vec<JunkItem> {
    let trimmed_app = app_name.trim();
    if trimmed_app.is_empty() {
        return Vec::new();
    }

    let mut items = scan_disk_junk(trimmed_app, known_install_dir);
    let mut seen: HashSet<PathBuf> = items.iter().map(|i| i.path.clone()).collect();

    if let Some(pub_name) = publisher.map(str::trim).filter(|p| !p.is_empty()) {
        let pub_lower = pub_name.to_lowercase();
        if !PROTECTED_NAMES.iter().any(|&p| p == pub_lower) {
            for root in get_candidate_search_roots() {
                let pub_dir = root.join(pub_name);
                if let Ok(entries) = fs::read_dir(&pub_dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_dir() && seen.insert(path.clone()) {
                            let file_name = entry.file_name();
                            let name = file_name.to_string_lossy();
                            if crate::heuristics::matches_app_name(&name, trimmed_app) {
                                let confidence = evaluate_confidence(&path, trimmed_app, known_install_dir);
                                let size_bytes = if confidence == ConfidenceLevel::Dangerous {
                                    None
                                } else {
                                    Some(dir_size_bytes(&path))
                                };
                                items.push(JunkItem {
                                    path,
                                    is_registry: false,
                                    confidence,
                                    reason: format!("Directory under publisher '{}' matches '{}'", pub_name, trimmed_app),
                                    size_bytes,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    for shortcut_dir in get_shortcut_search_roots() {
        for item in find_matching_shortcuts_in(&shortcut_dir, trimmed_app) {
            if seen.insert(item.path.clone()) {
                items.push(item);
            }
        }
    }

    dedupe_nested_junk_items(items)
}

/// Removes items whose path is equal to or nested inside another `JunkItem` directory.
pub fn dedupe_nested_junk_items(mut items: Vec<JunkItem>) -> Vec<JunkItem> {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_lowercase()
    };
    items.sort_by_key(|i| norm(&i.path).len());
    let mut kept: Vec<JunkItem> = Vec::with_capacity(items.len());
    let mut kept_paths: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let p = norm(&item.path);
        let is_nested = kept_paths.iter().any(|parent| {
            p == *parent
                || (p.starts_with(parent.as_str())
                    && p.as_bytes().get(parent.len()).is_some_and(|&b| b == b'\\' || b == b'/'))
        });
        if !is_nested {
            kept_paths.push(p);
            kept.push(item);
        }
    }
    kept
}

fn get_shortcut_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(appdata) = env::var("APPDATA") {
        roots.push(PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Ok(pd) = env::var("ProgramData") {
        roots.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        roots.push(PathBuf::from(profile).join("Desktop"));
    }
    roots
}

fn get_candidate_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    let mut push_unique = |p: PathBuf| {
        let key = p.to_string_lossy().trim_end_matches(['\\', '/']).to_lowercase();
        if !key.is_empty() && seen.insert(key) {
            roots.push(p);
        }
    };

    if let Ok(pf) = env::var("ProgramFiles") {
        push_unique(PathBuf::from(pf));
    }
    if let Ok(pf86) = env::var("ProgramFiles(x86)") {
        push_unique(PathBuf::from(pf86));
    }
    if let Ok(pd) = env::var("ProgramData") {
        push_unique(PathBuf::from(pd));
    }
    if let Ok(appdata) = env::var("APPDATA") {
        push_unique(PathBuf::from(appdata));
    }
    if let Ok(localappdata) = env::var("LOCALAPPDATA") {
        push_unique(PathBuf::from(localappdata));
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        push_unique(PathBuf::from(profile).join(r"AppData\LocalLow"));
    }

    roots
}
