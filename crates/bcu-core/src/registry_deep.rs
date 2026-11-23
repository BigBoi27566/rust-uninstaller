use crate::models::{ApplicationEntry, ConfidenceLevel};
use crate::reg_backup::{RegBackup, RegValueBackup, RegValueData};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use winreg::enums::*;
use winreg::RegKey;

/// Category of leftover registry artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryRemnantType {
    OrphanedClsid,
    FileAssociation,
    MuiCacheEntry,
    StartupEntry,
    AppSoftwareKey,
}

/// A specific registry key or value remnant identified as leftover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRemnant {
    pub hive: String,
    pub subkey: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub remnant_type: RegistryRemnantType,
    pub confidence: ConfidenceLevel,
    pub reason: String,
}

const SYSTEM_BLACKLIST: &[&str] = &[
    "microsoft",
    "windows",
    "system",
    "classes",
    "policies",
    "currentcontrolset",
    "control panel",
    "services",
    "drivers",
];

const MUICACHE_PATH: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
const RUN_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUN_ONCE_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";

/// Checks if a string references any protected Windows system keyword.
pub fn is_system_protected(text: &str) -> bool {
    let lower = text.to_lowercase();
    SYSTEM_BLACKLIST.iter().any(|&bl| lower == bl || lower.starts_with(&format!("{}\\", bl)))
}

/// Deep scans Windows Registry for remnants associated with an installed application.
pub fn scan_deep_registry(app: &ApplicationEntry) -> Vec<RegistryRemnant> {
    let mut binary_names = Vec::new();

    // Extract potential binary name from uninstall strings or install location
    if let Some(ref unins) = app.uninstall_string {
        if let Some(bin) = extract_filename(unins) {
            binary_names.push(bin);
        }
    }
    if let Some(ref loc) = app.install_location {
        if let Some(stem) = loc.file_name().and_then(|n| n.to_str()) {
            binary_names.push(stem.to_string());
        }
    }

    let bin_slices: Vec<&str> = binary_names.iter().map(|s| s.as_str()).collect();

    scan_deep_registry_for_target(
        &app.display_name,
        app.publisher.as_deref(),
        app.install_location.as_deref(),
        &bin_slices,
    )
}

/// Scans specific Windows Registry paths for targets matching name, publisher, path, or binaries.
pub fn scan_deep_registry_for_target(
    app_name: &str,
    publisher: Option<&str>,
    install_location: Option<&Path>,
    binary_names: &[&str],
) -> Vec<RegistryRemnant> {
    let mut remnants = Vec::new();
    let trimmed_name = app_name.trim();

    if trimmed_name.is_empty() || is_system_protected(trimmed_name) {
        return remnants;
    }

    let app_lower = trimmed_name.to_lowercase();
    let loc_str = install_location.and_then(|p| p.to_str()).unwrap_or("");
    let loc_lower = loc_str.to_lowercase();

    // 1. Scan MuiCache in HKCU
    scan_muicache(&app_lower, &loc_lower, binary_names, &mut remnants);

    // 2. Scan Startup / Run / RunOnce in HKCU & HKLM
    scan_startup_keys(&app_lower, &loc_lower, binary_names, &mut remnants);

    // 3. Scan Application Software keys in HKCU & HKLM
    scan_software_keys(
        &app_lower,
        trimmed_name,
        publisher,
        &mut remnants,
    );

    remnants
}

fn scan_muicache(
    app_lower: &str,
    loc_lower: &str,
    binary_names: &[&str],
    remnants: &mut Vec<RegistryRemnant>,
) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(MUICACHE_PATH, KEY_READ) {
        for (name, val) in key.enum_values().filter_map(|r| r.ok()) {
            let name_lower = name.to_lowercase();
            let val_str = val.to_string();
            let val_lower = val_str.to_lowercase();

            let matches_loc = !loc_lower.is_empty() && name_lower.contains(loc_lower);
            let matches_app = val_lower.contains(app_lower);
            let matches_bin = binary_names
                .iter()
                .any(|&bin| !bin.is_empty() && name_lower.contains(&bin.to_lowercase()));

            if matches_loc || matches_app || matches_bin {
                remnants.push(RegistryRemnant {
                    hive: "HKEY_CURRENT_USER".to_string(),
                    subkey: MUICACHE_PATH.to_string(),
                    value_name: Some(name),
                    value_data: Some(val_str),
                    remnant_type: RegistryRemnantType::MuiCacheEntry,
                    confidence: ConfidenceLevel::Safe,
                    reason: "Residual execution cache in Windows Shell MuiCache".to_string(),
                });
            }
        }
    }
}

fn scan_startup_keys(
    app_lower: &str,
    loc_lower: &str,
    binary_names: &[&str],
    remnants: &mut Vec<RegistryRemnant>,
) {
    let hives = [
        (HKEY_CURRENT_USER, "HKEY_CURRENT_USER", RUN_PATH, KEY_READ),
        (HKEY_CURRENT_USER, "HKEY_CURRENT_USER", RUN_ONCE_PATH, KEY_READ),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", RUN_PATH, KEY_READ | KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", RUN_PATH, KEY_READ | KEY_WOW64_32KEY),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", RUN_ONCE_PATH, KEY_READ | KEY_WOW64_64KEY),
    ];

    let mut seen = HashSet::new();

    for (hive_code, hive_name, sub_path, sam) in hives {
        let root = RegKey::predef(hive_code);
        if let Ok(key) = root.open_subkey_with_flags(sub_path, sam) {
            for (val_name, val_data) in key.enum_values().filter_map(|r| r.ok()) {
                let name_lower = val_name.to_lowercase();
                let data_str = val_data.to_string();
                let data_lower = data_str.to_lowercase();

                let matches_name = name_lower.contains(app_lower);
                let matches_loc = !loc_lower.is_empty() && data_lower.contains(loc_lower);
                let matches_bin = binary_names
                    .iter()
                    .any(|&bin| !bin.is_empty() && data_lower.contains(&bin.to_lowercase()));

                if matches_name || matches_loc || matches_bin {
                    let dedupe_key = format!("{}:{}:{}", hive_name, sub_path, val_name);
                    if seen.insert(dedupe_key) {
                        // Check if the referenced executable actually exists on disk
                        let target_path = extract_path_from_command(&data_str);
                        let is_orphaned = !target_path.is_empty() && !Path::new(&target_path).exists();

                        let confidence = if is_orphaned {
                            ConfidenceLevel::Safe
                        } else {
                            ConfidenceLevel::Questionable
                        };

                        remnants.push(RegistryRemnant {
                            hive: hive_name.to_string(),
                            subkey: sub_path.to_string(),
                            value_name: Some(val_name),
                            value_data: Some(data_str),
                            remnant_type: RegistryRemnantType::StartupEntry,
                            confidence,
                            reason: if is_orphaned {
                                "Orphaned Windows startup entry pointing to nonexistent file".to_string()
                            } else {
                                "Windows startup autorun entry for target application".to_string()
                            },
                        });
                    }
                }
            }
        }
    }
}

fn scan_software_keys(
    app_lower: &str,
    _app_name: &str,
    publisher: Option<&str>,
    remnants: &mut Vec<RegistryRemnant>,
) {
    let pub_sanitized = publisher
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && !is_system_protected(p));

    let targets = [
        (HKEY_CURRENT_USER, "HKEY_CURRENT_USER", r"Software"),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", r"SOFTWARE"),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node"),
    ];

    for (hive_code, hive_name, base_path) in targets {
        let root = RegKey::predef(hive_code);
        if let Ok(base_key) = root.open_subkey_with_flags(base_path, KEY_READ) {
            // Check direct match Software\<AppName>
            for sub in base_key.enum_keys().filter_map(|r| r.ok()) {
                let sub_lower = sub.to_lowercase();
                if is_system_protected(&sub_lower) {
                    continue;
                }

                if sub_lower == app_lower || sub_lower.contains(app_lower) {
                    let full_subkey = format!(r"{}\{}", base_path, sub);
                    remnants.push(RegistryRemnant {
                        hive: hive_name.to_string(),
                        subkey: full_subkey,
                        value_name: None,
                        value_data: None,
                        remnant_type: RegistryRemnantType::AppSoftwareKey,
                        confidence: ConfidenceLevel::Safe,
                        reason: format!("Dedicated application registry key under {}", base_path),
                    });
                }
            }

            // Check Software\<Publisher>\<AppName>
            if let Some(pub_name) = pub_sanitized {
                let pub_path = format!(r"{}\{}", base_path, pub_name);
                if let Ok(pub_key) = root.open_subkey_with_flags(&pub_path, KEY_READ) {
                    for sub in pub_key.enum_keys().filter_map(|r| r.ok()) {
                        let sub_lower = sub.to_lowercase();
                        if sub_lower == app_lower || sub_lower.contains(app_lower) {
                            let full_subkey = format!(r"{}\{}\{}", base_path, pub_name, sub);
                            remnants.push(RegistryRemnant {
                                hive: hive_name.to_string(),
                                subkey: full_subkey,
                                value_name: None,
                                value_data: None,
                                remnant_type: RegistryRemnantType::AppSoftwareKey,
                                confidence: ConfidenceLevel::Safe,
                                reason: format!("Application registry key under publisher {}", pub_name),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Safely cleans remnants after generating an automatic rollback `.reg` backup file.
/// Returns the PathBuf of the generated `.reg` backup.
pub fn clean_registry_remnants(
    remnants: &[RegistryRemnant],
    backup_dir: Option<&Path>,
    app_id: &str,
) -> std::io::Result<PathBuf> {
    // 1. Filter out Dangerous items
    let safe_remnants: Vec<&RegistryRemnant> = remnants
        .iter()
        .filter(|r| r.confidence != ConfidenceLevel::Dangerous)
        .collect();

    if safe_remnants.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No safe registry remnants found to clean",
        ));
    }

    // 2. Generate Rollback RegBackup
    let mut backup = RegBackup::new();
    for rem in &safe_remnants {
        let hive_code = match rem.hive.as_str() {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            _ => continue,
        };

        let root = RegKey::predef(hive_code);
        let key_path = format!(r"{}\{}", rem.hive, rem.subkey);

        if let Ok(key) = root.open_subkey_with_flags(&rem.subkey, KEY_READ) {
            if let Some(ref val_name) = rem.value_name {
                // Back up single value
                let val_data = match key.get_raw_value(val_name) {
                    Ok(raw) => RegValueData::Binary(raw.bytes),
                    Err(_) => RegValueData::None,
                };
                backup.add_key(&key_path, vec![RegValueBackup {
                    name: val_name.clone(),
                    data: val_data,
                }]);
            } else {
                // Back up entire key and all its values
                let mut values = Vec::new();
                for (vname, _) in key.enum_values().filter_map(|r| r.ok()) {
                    if let Ok(raw) = key.get_raw_value(&vname) {
                        values.push(RegValueBackup {
                            name: vname,
                            data: RegValueData::Binary(raw.bytes),
                        });
                    }
                }
                backup.add_key(&key_path, values);
            }
        }
    }

    // 3. Save backup file to disk
    let backup_path = if let Some(dir) = backup_dir {
        let filename = RegBackup::generate_backup_path(app_id)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        dir.join(filename)
    } else {
        RegBackup::generate_backup_path(app_id)
    };

    backup.save_to_file(&backup_path)?;

    // 4. Perform actual deletions
    for rem in safe_remnants {
        let hive_code = match rem.hive.as_str() {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            _ => continue,
        };

        let root = RegKey::predef(hive_code);
        if let Some(ref val_name) = rem.value_name {
            if let Ok(key) = root.open_subkey_with_flags(&rem.subkey, KEY_WRITE) {
                let _ = key.delete_value(val_name);
            }
        } else {
            // Delete entire subkey
            let _ = root.delete_subkey_all(&rem.subkey);
        }
    }

    Ok(backup_path)
}

fn extract_filename(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    let unquoted = if trimmed.starts_with('"') {
        trimmed[1..].split('"').next()?
    } else {
        trimmed.split_whitespace().next()?
    };

    Path::new(unquoted)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}

fn extract_path_from_command(cmd: &str) -> String {
    let trimmed = cmd.trim();
    if trimmed.starts_with('"') {
        trimmed[1..].split('"').next().unwrap_or("").to_string()
    } else {
        trimmed.split_whitespace().next().unwrap_or("").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_blacklist_protection() {
        assert!(is_system_protected("Microsoft"));
        assert!(is_system_protected("microsoft"));
        assert!(is_system_protected(r"Windows\System32"));
        assert!(!is_system_protected("Git"));
        assert!(!is_system_protected("Mozilla Firefox"));
        assert!(!is_system_protected("VLC Media Player"));
    }

    #[test]
    fn test_extract_filename() {
        assert_eq!(
            extract_filename(r#""C:\Program Files\App\unins000.exe" /SILENT"#),
            Some("unins000".to_string())
        );
        assert_eq!(
            extract_filename(r#"C:\Tools\clean.bat -all"#),
            Some("clean".to_string())
        );
    }

    #[test]
    fn test_extract_path_from_command() {
        assert_eq!(
            extract_path_from_command(r#""C:\Program Files\Test\app.exe" -run"#),
            r#"C:\Program Files\Test\app.exe"#
        );
        assert_eq!(
            extract_path_from_command(r#"C:\Tools\helper.exe --flag"#),
            r#"C:\Tools\helper.exe"#
        );
    }

    #[test]
    fn test_scan_deep_registry_system_app_returns_empty() {
        let remnants = scan_deep_registry_for_target("Microsoft", None, None, &[]);
        assert!(remnants.is_empty(), "Protected system names must return zero remnants");
    }
}
