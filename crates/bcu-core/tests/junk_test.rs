use bcu_core::junk::{evaluate_confidence, scan_disk_junk};
use bcu_core::models::ConfidenceLevel;
use std::path::Path;

#[test]
fn test_system_paths_are_strictly_dangerous() {
    let windows_dir = Path::new(r"C:\Windows");
    let system32_dir = Path::new(r"C:\Windows\System32");
    let program_files = Path::new(r"C:\Program Files");
    let app_data = Path::new(r"C:\Users\Admin\AppData\Roaming");

    assert_eq!(
        evaluate_confidence(windows_dir, "Windows", None),
        ConfidenceLevel::Dangerous
    );
    assert_eq!(
        evaluate_confidence(system32_dir, "System32", None),
        ConfidenceLevel::Dangerous
    );
    assert_eq!(
        evaluate_confidence(program_files, "Program Files", None),
        ConfidenceLevel::Dangerous
    );
    assert_eq!(
        evaluate_confidence(app_data, "Roaming", None),
        ConfidenceLevel::Dangerous
    );
}

#[test]
fn test_app_specific_paths_are_safe_or_questionable() {
    let exact_install_dir = Path::new(r"C:\Program Files\MyCoolApp");
    assert_eq!(
        evaluate_confidence(exact_install_dir, "MyCoolApp", Some(exact_install_dir)),
        ConfidenceLevel::Safe
    );

    let app_data_sub = Path::new(r"C:\Users\Admin\AppData\Local\MyCoolApp");
    assert_eq!(
        evaluate_confidence(app_data_sub, "MyCoolApp", Some(exact_install_dir)),
        ConfidenceLevel::Safe
    );

    let loose_match = Path::new(r"C:\Program Files\MyCoolApp Tools");
    assert_eq!(
        evaluate_confidence(loose_match, "MyCoolApp", Some(exact_install_dir)),
        ConfidenceLevel::Questionable
    );
}

#[test]
fn test_scan_disk_junk_runs_without_panic() {
    // Search for a non-existent or dummy software
    let junk = scan_disk_junk("NonExistentSoftware_12345XYZ", None);
    assert!(junk.is_empty(), "Should not find junk for non-existent software");
}
