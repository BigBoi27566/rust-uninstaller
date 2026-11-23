use bcu_core::junk::scan_disk_junk;
use bcu_core::registry::scan_registry_uninstallers;
use bcu_core::store::scan_store_apps;
use std::ffi::{c_char, CStr, CString};
use std::path::Path;

/// Scans installed applications from Windows Registry and returns a pointer
/// to a null-terminated UTF-8 JSON string.
/// The caller MUST free this pointer by calling `bcu_free_string`.
#[no_mangle]
pub extern "C" fn bcu_scan_installed_applications() -> *mut c_char {
    let apps = scan_registry_uninstallers();
    let json = serde_json::to_string(&apps).unwrap_or_else(|_| "[]".to_string());
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Scans Windows Store Apps (UWP/AppX) and returns a pointer to a null-terminated UTF-8 JSON string.
/// The caller MUST free this pointer by calling `bcu_free_string`.
#[no_mangle]
pub extern "C" fn bcu_scan_store_applications() -> *mut c_char {
    let apps = scan_store_apps();
    let json = serde_json::to_string(&apps).unwrap_or_else(|_| "[]".to_string());
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Scans for leftover junk items on disk matching an application name and optional install directory.
/// Returns a pointer to a null-terminated UTF-8 JSON string.
/// The caller MUST free this pointer by calling `bcu_free_string`.
///
/// # Safety
/// `app_name` must be a valid null-terminated C string. `install_dir` can be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn bcu_scan_application_junk(
    app_name: *const c_char,
    install_dir: *const c_char,
) -> *mut c_char {
    if app_name.is_null() {
        return CString::new("[]").unwrap().into_raw();
    }

    let name = match CStr::from_ptr(app_name).to_str() {
        Ok(s) => s,
        Err(_) => return CString::new("[]").unwrap().into_raw(),
    };

    let dir = if !install_dir.is_null() {
        CStr::from_ptr(install_dir).to_str().ok().map(Path::new)
    } else {
        None
    };

    let junk = scan_disk_junk(name, dir);
    let json = serde_json::to_string(&junk).unwrap_or_else(|_| "[]".to_string());
    match CString::new(json) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a C string previously allocated by Rust.
///
/// # Safety
/// The pointer must have been obtained from a `bcu_scan_*` function
/// and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn bcu_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}
