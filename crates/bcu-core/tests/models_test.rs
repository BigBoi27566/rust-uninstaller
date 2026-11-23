use bcu_core::models::{ApplicationEntry, UninstallerKind, ConfidenceLevel};

#[test]
fn test_application_entry_serialization() {
    let entry = ApplicationEntry {
        id: "TestApp123".to_string(),
        display_name: "Test Application".to_string(),
        display_version: Some("1.0.0".to_string()),
        publisher: Some("Test Publisher".to_string()),
        install_location: Some("C:\\Program Files\\TestApp".into()),
        uninstall_string: Some("\"C:\\Program Files\\TestApp\\unins000.exe\"".to_string()),
        quiet_uninstall_string: None,
        install_date: Some("2026-11-23".to_string()),
        estimated_size_bytes: Some(1024 * 1024 * 50),
        uninstaller_kind: UninstallerKind::InnoSetup,
        is_system_component: false,
        is_protected: false,
    };

    let json = serde_json::to_string(&entry).expect("Must serialize to JSON");
    assert!(json.contains("Test Application"));
    assert!(json.contains("InnoSetup"));

    let deserialized: ApplicationEntry = serde_json::from_str(&json).expect("Must deserialize from JSON");
    assert_eq!(deserialized.id, "TestApp123");
    assert_eq!(deserialized.display_name, "Test Application");
    assert_eq!(deserialized.uninstaller_kind, UninstallerKind::InnoSetup);
}

#[test]
fn test_confidence_level() {
    let safe = ConfidenceLevel::Safe;
    let json = serde_json::to_string(&safe).unwrap();
    assert_eq!(json, "\"Safe\"");
}
