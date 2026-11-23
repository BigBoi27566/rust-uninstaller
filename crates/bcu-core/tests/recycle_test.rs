use bcu_core::models::{ConfidenceLevel, JunkItem};
use bcu_core::recycle::{clean_junk_items, move_to_recycle_bin};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_dangerous_junk_is_strictly_rejected() {
    let dangerous_item = JunkItem {
        path: PathBuf::from(r"C:\Windows\System32"),
        is_registry: false,
        confidence: ConfidenceLevel::Dangerous,
        reason: "System root".into(),
    };

    let (cleaned_count, errors) = clean_junk_items(&[dangerous_item], true);
    assert_eq!(cleaned_count, 0, "Dangerous items must NEVER be cleaned");
    assert!(!errors.is_empty(), "Should report rejection of dangerous item");
}

#[test]
fn test_move_temp_file_to_recycle_bin() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("bcu_test_recycle_dummy.txt");
    fs::write(&test_file, "temporary content for recycle bin test").expect("Must create test file");
    assert!(test_file.exists());

    let res = move_to_recycle_bin(&test_file);
    assert!(res.is_ok(), "Must successfully send file to Recycle Bin: {:?}", res);
    assert!(!test_file.exists(), "File should no longer exist at original path");
}
