use bcu_core::export::{export_to_csv, export_to_json};
use bcu_core::models::{ApplicationEntry, UninstallerKind};

#[test]
fn test_export_csv_escapes_commas_and_quotes() {
    let app = ApplicationEntry {
        id: "id_1".into(),
        display_name: r#"App, with "Special" Characters"#.into(),
        display_version: Some("1.0,beta".into()),
        publisher: Some("Vendor, Inc.".into()),
        install_location: None,
        uninstall_string: Some(r#""C:\Program Files\App\unins000.exe""#.into()),
        quiet_uninstall_string: None,
        install_date: None,
        estimated_size_bytes: Some(1024 * 1024),
        uninstaller_kind: UninstallerKind::InnoSetup,
        is_system_component: false,
        is_protected: false,
        registry_location: None,
    };

    let csv = export_to_csv(&[app]);
    assert!(csv.starts_with("ID,DisplayName,Version,Publisher,Kind,QuietAvailable,InstallLocation,UninstallString\n"));
    assert!(csv.contains(r#""App, with ""Special"" Characters""#));
    assert!(csv.contains(r#""Vendor, Inc.""#));
}

#[test]
fn test_export_json_valid_array() {
    let app = ApplicationEntry {
        id: "id_2".into(),
        display_name: "Simple App".into(),
        display_version: Some("2.0".into()),
        publisher: None,
        install_location: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        install_date: None,
        estimated_size_bytes: None,
        uninstaller_kind: UninstallerKind::Unknown,
        is_system_component: false,
        is_protected: false,
        registry_location: None,
    };

    let json = export_to_json(&[app]);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Must be valid JSON");
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}
