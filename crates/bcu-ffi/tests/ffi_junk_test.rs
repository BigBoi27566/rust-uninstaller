use bcu_ffi::{bcu_free_string, bcu_scan_application_junk};
use std::ffi::{CStr, CString};

#[test]
fn test_ffi_scan_junk_roundtrip() {
    let app_name = CString::new("NonExistent_App_123XYZ").unwrap();
    let raw_ptr = unsafe { bcu_scan_application_junk(app_name.as_ptr(), std::ptr::null()) };
    assert!(!raw_ptr.is_null());

    unsafe {
        let c_str = CStr::from_ptr(raw_ptr);
        let json_str = c_str.to_str().expect("Valid UTF-8");
        assert_eq!(json_str, "[]");

        bcu_free_string(raw_ptr);
    }
}
