use bcu_core::junk::{
    dedupe_nested_junk_items, dir_size_bytes, evaluate_confidence, find_matching_shortcuts_in,
    scan_disk_junk,
};
use bcu_core::models::{ConfidenceLevel, JunkItem};
use std::fs;
use std::path::{Path, PathBuf};

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

#[test]
fn test_dir_size_bytes_calculates_files_and_skips_missing() {
    let temp_dir = std::env::temp_dir().join("bcu_test_dir_size");
    let _ = fs::remove_dir_all(&temp_dir);
    let sub_dir = temp_dir.join("sub");
    fs::create_dir_all(&sub_dir).unwrap();
    fs::write(temp_dir.join("a.bin"), vec![0u8; 100]).unwrap();
    fs::write(sub_dir.join("b.bin"), vec![0u8; 250]).unwrap();

    assert_eq!(dir_size_bytes(&temp_dir), 350);
    assert_eq!(dir_size_bytes(&temp_dir.join("missing")), 0);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_shortcut_matching_in_dir() {
    let temp_dir = std::env::temp_dir().join("bcu_test_shortcuts");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    fs::write(temp_dir.join("MyApp.lnk"), b"lnk").unwrap();
    fs::write(temp_dir.join("OtherApp.lnk"), b"lnk").unwrap();

    let found = find_matching_shortcuts_in(&temp_dir, "MyApp");
    assert_eq!(found.len(), 1);
    assert!(found[0].path.ends_with("MyApp.lnk"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_dedupe_nested_junk_items_excludes_descendants() {
    let parent = JunkItem {
        path: PathBuf::from(r"C:\Program Files\Dropbox"),
        is_registry: false,
        confidence: ConfidenceLevel::Safe,
        reason: "parent".into(),
        size_bytes: Some(1000),
    };
    let child = JunkItem {
        path: PathBuf::from(r"C:\Program Files\Dropbox\Dropbox"),
        is_registry: false,
        confidence: ConfidenceLevel::Safe,
        reason: "child".into(),
        size_bytes: Some(500),
    };
    let deduped = dedupe_nested_junk_items(vec![parent, child]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].path, PathBuf::from(r"C:\Program Files\Dropbox"));
}
