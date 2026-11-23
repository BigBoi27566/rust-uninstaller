use bcu_core::models::UninstallerKind;
use bcu_core::store::scan_store_apps;

#[test]
fn test_scan_store_apps_returns_list() {
    let store_apps = scan_store_apps();
    // On any standard Windows 10/11 system, there are preinstalled UWP/Store apps
    // (e.g. Calculator, Photos, Store, Edge).
    println!("Found {} Windows Store Apps", store_apps.len());
    for app in &store_apps {
        assert_eq!(app.uninstaller_kind, UninstallerKind::StoreApp);
        assert!(!app.id.is_empty());
        assert!(!app.display_name.is_empty());
    }
}
