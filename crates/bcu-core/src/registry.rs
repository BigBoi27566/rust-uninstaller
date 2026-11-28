use crate::models::{ApplicationEntry, RegistryHive, RegistryLocation, UninstallerKind};
use std::collections::HashSet;
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;

const UNINSTALL_KEY_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

pub fn scan_registry_uninstallers() -> Vec<ApplicationEntry> {
    let mut results = Vec::new();
    let mut seen_ids = HashSet::new();

    // HKLM 64-bit
    scan_hive(
        HKEY_LOCAL_MACHINE,
        UNINSTALL_KEY_PATH,
        KEY_READ | KEY_WOW64_64KEY,
        &mut results,
        &mut seen_ids,
    );

    // HKLM 32-bit (WoW6432Node)
    scan_hive(
        HKEY_LOCAL_MACHINE,
        UNINSTALL_KEY_PATH,
        KEY_READ | KEY_WOW64_32KEY,
        &mut results,
        &mut seen_ids,
    );

    // HKCU
    scan_hive(
        HKEY_CURRENT_USER,
        UNINSTALL_KEY_PATH,
        KEY_READ,
        &mut results,
        &mut seen_ids,
    );

    results
}

fn scan_hive(
    root_hive: winreg::HKEY,
    sub_path: &str,
    sam: u32,
    results: &mut Vec<ApplicationEntry>,
    seen_ids: &mut HashSet<String>,
) {
    let root = RegKey::predef(root_hive);
    let uninstall_key = match root.open_subkey_with_flags(sub_path, sam) {
        Ok(k) => k,
        Err(_) => return,
    };

    for subkey_name in uninstall_key.enum_keys().filter_map(|r| r.ok()) {
        let app_key = match uninstall_key.open_subkey_with_flags(&subkey_name, sam) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let display_name: String = match app_key.get_value("DisplayName") {
            Ok(name) => name,
            Err(_) => continue,
        };

        let trimmed_name = display_name.trim();
        if trimmed_name.is_empty() {
            continue;
        }

        // Deduplication based on key name + hive
        let unique_id = format!("{}_{}", subkey_name, sam);
        if seen_ids.contains(&unique_id) {
            continue;
        }
        seen_ids.insert(unique_id);

        let display_version: Option<String> = app_key.get_value("DisplayVersion").ok();
        let publisher: Option<String> = app_key.get_value("Publisher").ok();
        let install_location: Option<PathBuf> = app_key
            .get_value::<String, _>("InstallLocation")
            .ok()
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let uninstall_string: Option<String> = app_key.get_value("UninstallString").ok();
        let quiet_uninstall_string: Option<String> =
            app_key.get_value("QuietUninstallString").ok();
        let install_date: Option<String> = app_key.get_value("InstallDate").ok();
        let display_icon: Option<String> = app_key
            .get_value::<String, _>("DisplayIcon")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let estimated_size_bytes: Option<u64> = app_key
            .get_value::<u32, _>("EstimatedSize")
            .ok()
            .map(|kb| (kb as u64) * 1024);

        let is_system_component = app_key
            .get_value::<u32, _>("SystemComponent")
            .map(|v| v == 1)
            .unwrap_or(false);

        let is_protected = app_key
            .get_value::<u32, _>("NoRemove")
            .map(|v| v == 1)
            .unwrap_or(false);

        let is_windows_installer = app_key
            .get_value::<u32, _>("WindowsInstaller")
            .map(|v| v == 1)
            .unwrap_or(false);

        let uninstaller_kind = if let Some(ref cmd) = uninstall_string {
            crate::heuristics::detect_uninstaller_kind(cmd, Some(is_windows_installer))
        } else if is_windows_installer {
            UninstallerKind::Msi
        } else {
            UninstallerKind::Unknown
        };

        let quiet_uninstall_string = quiet_uninstall_string.or_else(|| {
            uninstall_string
                .as_ref()
                .and_then(|cmd| crate::heuristics::synthesize_quiet_command(cmd, &uninstaller_kind))
        });

        let hive = if root_hive == HKEY_CURRENT_USER {
            RegistryHive::Hkcu
        } else if (sam & KEY_WOW64_32KEY) != 0 {
            RegistryHive::Hklm32
        } else {
            RegistryHive::Hklm64
        };

        results.push(ApplicationEntry {
            id: subkey_name.clone(),
            display_name: trimmed_name.to_string(),
            display_version,
            publisher,
            install_location,
            uninstall_string,
            quiet_uninstall_string,
            install_date,
            estimated_size_bytes,
            uninstaller_kind,
            is_system_component,
            is_protected,
            registry_location: Some(RegistryLocation {
                hive,
                subkey_path: format!(r"{}\{}", sub_path, subkey_name),
            }),
            display_icon,
        });
    }
}
