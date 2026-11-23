use bcu_ffi::{bcu_scan_installed_applications, bcu_free_string};
use std::ffi::CStr;

#[test]
fn test_ffi_scan_and_free() {
    let raw_ptr = bcu_scan_installed_applications();
    assert!(!raw_ptr.is_null(), "Pointer returned from FFI scan must not be null");

    unsafe {
        let c_str = CStr::from_ptr(raw_ptr);
        let json_str = c_str.to_str().expect("Must be valid UTF-8 string");
        assert!(json_str.starts_with('['), "JSON must start with array '['");
        assert!(json_str.ends_with(']'), "JSON must end with array ']'");

        // Parse to verify valid JSON
        let parsed: serde_json::Value = serde_json::from_str(json_str).expect("Must parse into valid JSON");
        assert!(parsed.is_array());
        let array = parsed.as_array().unwrap();
        assert!(!array.is_empty(), "Must contain scanned applications");

        // Free the memory
        bcu_free_string(raw_ptr);
    }
}
