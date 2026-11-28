use crate::models::{ApplicationEntry, ConfidenceLevel, RegistryHive, RegistryLocation, UninstallerKind};
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

            let matches_loc = !loc_lower.is_empty() && name_lower.contains(loc_lower);
            let matches_app = crate::heuristics::matches_app_name(&val_str, app_lower);
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
                let data_str = val_data.to_string();
                let data_lower = data_str.to_lowercase();

                let matches_name = crate::heuristics::matches_app_name(&val_name, app_lower);
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
    app_name: &str,
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

                let is_exact = sub_lower == app_lower;
                if is_exact || crate::heuristics::matches_app_name(&sub, app_name) {
                    let full_subkey = format!(r"{}\{}", base_path, sub);
                    remnants.push(RegistryRemnant {
                        hive: hive_name.to_string(),
                        subkey: full_subkey,
                        value_name: None,
                        value_data: None,
                        remnant_type: RegistryRemnantType::AppSoftwareKey,
                        confidence: if is_exact {
                            ConfidenceLevel::Safe
                        } else {
                            ConfidenceLevel::Questionable
                        },
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
                        let is_exact = sub_lower == app_lower;
                        if is_exact || crate::heuristics::matches_app_name(&sub, app_name) {
                            let full_subkey = format!(r"{}\{}\{}", base_path, pub_name, sub);
                            remnants.push(RegistryRemnant {
                                hive: hive_name.to_string(),
                                subkey: full_subkey,
                                value_name: None,
                                value_data: None,
                                remnant_type: RegistryRemnantType::AppSoftwareKey,
                                confidence: if is_exact {
                                    ConfidenceLevel::Safe
                                } else {
                                    ConfidenceLevel::Questionable
                                },
                                reason: format!("Application registry key under publisher {}", pub_name),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn parse_hive(hive: &str) -> Option<winreg::HKEY> {
    match hive {
        "HKEY_LOCAL_MACHINE" => Some(HKEY_LOCAL_MACHINE),
        "HKEY_CURRENT_USER" => Some(HKEY_CURRENT_USER),
        "HKEY_CLASSES_ROOT" => Some(HKEY_CLASSES_ROOT),
        _ => None,
    }
}

fn decode_utf16_le(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn raw_to_backup_data(raw: winreg::RegValue) -> RegValueData {
    use winreg::enums::RegType::*;
    match raw.vtype {
        REG_SZ | REG_EXPAND_SZ => {
            let units = decode_utf16_le(&raw.bytes);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            let text = String::from_utf16_lossy(&units[..end]);
            if matches!(raw.vtype, REG_EXPAND_SZ) {
                RegValueData::ExpandString(text)
            } else {
                RegValueData::String(text)
            }
        }
        REG_DWORD if raw.bytes.len() == 4 => RegValueData::Dword(u32::from_le_bytes([
            raw.bytes[0],
            raw.bytes[1],
            raw.bytes[2],
            raw.bytes[3],
        ])),
        REG_QWORD if raw.bytes.len() == 8 => {
            RegValueData::Qword(u64::from_le_bytes(raw.bytes[..8].try_into().unwrap()))
        }
        REG_MULTI_SZ => {
            let units = decode_utf16_le(&raw.bytes);
            let items = units
                .split(|&u| u == 0)
                .take_while(|slice| !slice.is_empty())
                .map(String::from_utf16_lossy)
                .collect();
            RegValueData::MultiString(items)
        }
        REG_NONE => RegValueData::None,
        _ => RegValueData::Binary(raw.bytes),
    }
}

fn backup_key_path(loc: &RegistryLocation) -> String {
    match loc.hive {
        RegistryHive::Hkcu => format!(r"HKEY_CURRENT_USER\{}", loc.subkey_path),
        RegistryHive::Hklm64 => format!(r"HKEY_LOCAL_MACHINE\{}", loc.subkey_path),
        RegistryHive::Hklm32 => {
            if let Some(rest) = loc
                .subkey_path
                .strip_prefix(r"SOFTWARE\")
                .or_else(|| loc.subkey_path.strip_prefix(r"Software\"))
            {
                if !rest.to_lowercase().starts_with(r"wow6432node\") {
                    return format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\{}", rest);
                }
            }
            format!(r"HKEY_LOCAL_MACHINE\{}", loc.subkey_path)
        }
    }
}

fn backup_subkey_recursive(key: &RegKey, reg_key_path: &str, backup: &mut RegBackup) {
    let mut values = Vec::new();
    for (vname, _) in key.enum_values().filter_map(|r| r.ok()) {
        if let Ok(raw) = key.get_raw_value(&vname) {
            values.push(RegValueBackup {
                name: vname,
                data: raw_to_backup_data(raw),
            });
        }
    }
    backup.add_key(reg_key_path, values);

    for child_name in key.enum_keys().filter_map(|r| r.ok()) {
        if let Ok(child_key) = key.open_subkey_with_flags(&child_name, KEY_READ) {
            let child_path = format!(r"{}\{}", reg_key_path, child_name);
            backup_subkey_recursive(&child_key, &child_path, backup);
        }
    }
}

fn resolve_backup_path(backup_dir: Option<&Path>, app_id: &str) -> PathBuf {
    let generated = RegBackup::generate_backup_path(app_id);
    if let Some(dir) = backup_dir {
        dir.join(generated.file_name().unwrap_or_default())
    } else {
        generated
    }
}

/// Safely cleans safe remnants after generating an automatic rollback `.reg` backup file.
/// Returns `(backup_path, deleted_count, errors)`.
pub fn clean_registry_remnants(
    remnants: &[RegistryRemnant],
    backup_dir: Option<&Path>,
    app_id: &str,
) -> std::io::Result<(PathBuf, usize, Vec<String>)> {
    clean_registry_remnants_selective(remnants, false, backup_dir, app_id)
}

/// Cleans `Safe` remnants (and `Questionable` if `allow_questionable` is true) after `.reg` backup.
/// `Dangerous` remnants are always refused. Returns `(backup_path, deleted_count, errors)`.
pub fn clean_registry_remnants_selective(
    remnants: &[RegistryRemnant],
    allow_questionable: bool,
    backup_dir: Option<&Path>,
    app_id: &str,
) -> std::io::Result<(PathBuf, usize, Vec<String>)> {
    let safe_remnants: Vec<&RegistryRemnant> = remnants
        .iter()
        .filter(|r| {
            r.confidence == ConfidenceLevel::Safe
                || (allow_questionable && r.confidence == ConfidenceLevel::Questionable)
        })
        .collect();

    if safe_remnants.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No safe registry remnants found to clean",
        ));
    }

    // Generate Rollback RegBackup preserving original value types
    let mut backup = RegBackup::new();
    for rem in &safe_remnants {
        let Some(hive_code) = parse_hive(&rem.hive) else {
            continue;
        };

        let root = RegKey::predef(hive_code);
        let key_path = format!(r"{}\{}", rem.hive, rem.subkey);

        if let Ok(key) = root.open_subkey_with_flags(&rem.subkey, KEY_READ) {
            if let Some(ref val_name) = rem.value_name {
                let val_data = match key.get_raw_value(val_name) {
                    Ok(raw) => raw_to_backup_data(raw),
                    Err(_) => RegValueData::None,
                };
                backup.add_key(&key_path, vec![RegValueBackup {
                    name: val_name.clone(),
                    data: val_data,
                }]);
            } else {
                backup_subkey_recursive(&key, &key_path, &mut backup);
            }
        }
    }

    let backup_path = resolve_backup_path(backup_dir, app_id);

    backup.save_to_file(&backup_path)?;

    let mut deleted_count = 0usize;
    let mut errors = Vec::new();
    for rem in safe_remnants {
        let Some(hive_code) = parse_hive(&rem.hive) else {
            continue;
        };

        let root = RegKey::predef(hive_code);
        let target = if let Some(ref val_name) = rem.value_name {
            format!(r"{}\{} -> {}", rem.hive, rem.subkey, val_name)
        } else {
            format!(r"{}\{}", rem.hive, rem.subkey)
        };

        let res = if let Some(ref val_name) = rem.value_name {
            root.open_subkey_with_flags(&rem.subkey, KEY_WRITE)
                .and_then(|key| key.delete_value(val_name))
        } else {
            root.delete_subkey_all(&rem.subkey)
        };

        match res {
            Ok(()) => deleted_count += 1,
            Err(e) => errors.push(format!("{}: {}", target, e)),
        }
    }

    Ok((backup_path, deleted_count, errors))
}

/// Backs up and deletes an application's `Uninstall` registry key for Force Uninstall.
/// Refuses `StoreApp` entries and entries without `registry_location`.
pub fn force_remove_uninstall_entry(
    app: &ApplicationEntry,
    backup_dir: Option<&Path>,
) -> std::io::Result<PathBuf> {
    if app.uninstaller_kind == UninstallerKind::StoreApp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Force Uninstall is disabled for Store/UWP applications",
        ));
    }

    let Some(ref loc) = app.registry_location else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing registry location for Force Uninstall",
        ));
    };

    let (hive_code, wow_flag) = match loc.hive {
        RegistryHive::Hklm64 => (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
        RegistryHive::Hklm32 => (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        RegistryHive::Hkcu => (HKEY_CURRENT_USER, 0),
    };

    let root = RegKey::predef(hive_code);
    let key = root.open_subkey_with_flags(&loc.subkey_path, KEY_READ | wow_flag)?;

    let mut backup = RegBackup::new();
    backup_subkey_recursive(&key, &backup_key_path(loc), &mut backup);

    let backup_path = resolve_backup_path(backup_dir, &app.id);
    backup.save_to_file(&backup_path)?;

    let (parent_path, leaf) = loc
        .subkey_path
        .rsplit_once('\\')
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid registry subkey path"))?;

    let parent_key = root.open_subkey_with_flags(parent_path, KEY_WRITE | wow_flag)?;
    parent_key.delete_subkey_all(leaf)?;

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

    #[test]
    fn test_raw_to_backup_data_preserves_types() {
        let sz_bytes: Vec<u8> = "C:\\App\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(
            raw_to_backup_data(winreg::RegValue {
                bytes: sz_bytes,
                vtype: RegType::REG_SZ,
            }),
            RegValueData::String("C:\\App".to_string())
        );

        assert_eq!(
            raw_to_backup_data(winreg::RegValue {
                bytes: 42u32.to_le_bytes().to_vec(),
                vtype: RegType::REG_DWORD,
            }),
            RegValueData::Dword(42)
        );
    }

    #[test]
    fn test_selective_cleanup_refuses_dangerous_and_unapproved_questionable() {
        let remnants = vec![
            RegistryRemnant {
                hive: "HKEY_CURRENT_USER".into(),
                subkey: r"Software\NonExistentTestApp".into(),
                value_name: None,
                value_data: None,
                remnant_type: RegistryRemnantType::AppSoftwareKey,
                confidence: ConfidenceLevel::Questionable,
                reason: "test".into(),
            },
            RegistryRemnant {
                hive: "HKEY_LOCAL_MACHINE".into(),
                subkey: r"SOFTWARE\Microsoft".into(),
                value_name: None,
                value_data: None,
                remnant_type: RegistryRemnantType::AppSoftwareKey,
                confidence: ConfidenceLevel::Dangerous,
                reason: "test".into(),
            },
        ];

        let err = clean_registry_remnants_selective(&remnants, false, None, "test_app").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_force_remove_refuses_store_app_and_missing_location() {
        let store_app = ApplicationEntry {
            id: "pkg1".into(),
            display_name: "Store App".into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: crate::models::UninstallerKind::StoreApp,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        };
        assert!(force_remove_uninstall_entry(&store_app, None).is_err());

        let mut win32_no_loc = store_app;
        win32_no_loc.uninstaller_kind = crate::models::UninstallerKind::Nsis;
        assert!(force_remove_uninstall_entry(&win32_no_loc, None).is_err());
    }

    #[test]
    fn test_backup_key_path_inserts_wow6432node_for_hklm32() {
        let loc = crate::models::RegistryLocation {
            hive: RegistryHive::Hklm32,
            subkey_path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TestApp".into(),
        };
        assert_eq!(
            backup_key_path(&loc),
            r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\TestApp"
        );
    }

    #[test]
    fn test_backup_subkey_tree_includes_nested_subkeys() {
        let test_subkey = r"Software\BCU_Rust_Test_BackupTree";
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(test_subkey);

        {
            let (parent, _) = hkcu.create_subkey(test_subkey).unwrap();
            parent.set_value("RootVal", &"root").unwrap();
            let (child, _) = parent.create_subkey("Child").unwrap();
            child.set_value("ChildVal", &"nested").unwrap();
        }

        let mut backup = RegBackup::new();
        let opened = hkcu.open_subkey_with_flags(test_subkey, KEY_READ).unwrap();
        backup_subkey_recursive(&opened, &format!(r"HKEY_CURRENT_USER\{}", test_subkey), &mut backup);
        let _ = hkcu.delete_subkey_all(test_subkey);

        let reg_text = backup.to_reg_string();
        assert!(reg_text.contains(r"[HKEY_CURRENT_USER\Software\BCU_Rust_Test_BackupTree]"));
        assert!(reg_text.contains(r"[HKEY_CURRENT_USER\Software\BCU_Rust_Test_BackupTree\Child]"));
        assert!(reg_text.contains("ChildVal"));
    }
}
