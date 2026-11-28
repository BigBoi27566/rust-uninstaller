use crate::models::{ApplicationEntry, UninstallerKind};
use std::path::PathBuf;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;

const PACKAGES_KEY_PATH: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

pub fn scan_store_apps() -> Vec<ApplicationEntry> {
    let mut apps = Vec::new();
    let root = RegKey::predef(HKEY_CURRENT_USER);

    let packages_key = match root.open_subkey_with_flags(PACKAGES_KEY_PATH, KEY_READ) {
        Ok(k) => k,
        Err(_) => return apps,
    };

    for package_full_name in packages_key.enum_keys().filter_map(|r| r.ok()) {
        let pkg_key = match packages_key.open_subkey_with_flags(&package_full_name, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Extract raw display name or fallback to package ID
        let raw_display_name: Option<String> = pkg_key.get_value("DisplayName").ok();
        let package_id: Option<String> = pkg_key.get_value("PackageID").ok();
        let package_root: Option<PathBuf> = pkg_key
            .get_value::<String, _>("PackageRootFolder")
            .ok()
            .map(PathBuf::from);

        let publisher: Option<String> = pkg_key.get_value("Publisher").ok();

        // Format clean display name
        let clean_name = raw_display_name
            .filter(|s| !s.is_empty() && !s.starts_with('@') && !s.starts_with("ms-resource:"))
            .or_else(|| {
                package_id.as_ref().map(|id| {
                    id.split('_')
                        .next()
                        .unwrap_or(id)
                        .to_string()
                })
            })
            .unwrap_or_else(|| {
                package_full_name
                    .split('_')
                    .next()
                    .unwrap_or(&package_full_name)
                    .to_string()
            });

        // Filter system-level internal packages
        if clean_name.is_empty() {
            continue;
        }

        let quiet_cmd = format!(
            r#"PowerShell.exe -NonInteractive -NoProfile -Command "Remove-AppxPackage -Package '{}'""#,
            package_full_name
        );

        apps.push(ApplicationEntry {
            id: package_full_name.clone(),
            display_name: clean_name,
            display_version: None,
            publisher,
            install_location: package_root,
            uninstall_string: Some(quiet_cmd.clone()),
            quiet_uninstall_string: Some(quiet_cmd),
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: UninstallerKind::StoreApp,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        });
    }

    apps
}
