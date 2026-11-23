// Tests the CLI logic directly
use bcu_core::registry::scan_registry_uninstallers;

#[test]
fn test_cli_list_logic() {
    let apps = scan_registry_uninstallers();
    assert!(!apps.is_empty());
}
