use bcu_core::registry::scan_registry_uninstallers;

#[test]
fn test_scan_registry_finds_applications() {
    let apps = scan_registry_uninstallers();
    // On any standard Windows machine, there are dozens or hundreds of registry uninstall keys.
    assert!(!apps.is_empty(), "Registry scan should find at least one installed application on Windows");
    println!("Found {} applications in Registry", apps.len());

    // Verify properties of at least one app
    for app in &apps {
        assert!(!app.id.is_empty(), "App ID must not be empty");
        assert!(!app.display_name.is_empty(), "Display name must not be empty");
    }
}
