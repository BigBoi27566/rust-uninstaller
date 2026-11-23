use crate::models::{ConfidenceLevel, JunkItem};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::{
    SHFileOperationW, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT, FO_DELETE,
    SHFILEOPSTRUCTW,
};

/// Safely moves a file or directory to the Windows Recycle Bin.
/// Returns Ok(()) on success, or Err with the error code/message.
pub fn move_to_recycle_bin(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()));
    }

    // Windows SHFileOperationW requires a double-null terminated wide string: "path\0\0"
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide_path.push(0);
    wide_path.push(0);

    let mut file_op = SHFILEOPSTRUCTW {
        hwnd: Default::default(),
        wFunc: FO_DELETE,
        pFrom: PCWSTR(wide_path.as_ptr()),
        pTo: PCWSTR::null(),
        fFlags: (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI).0 as u16,
        fAnyOperationsAborted: Default::default(),
        hNameMappings: std::ptr::null_mut(),
        lpszProgressTitle: PCWSTR::null(),
    };

    let result = unsafe { SHFileOperationW(&mut file_op) };
    if result == 0 {
        if file_op.fAnyOperationsAborted.as_bool() {
            Err("Operation was aborted by user or system".into())
        } else {
            Ok(())
        }
    } else {
        Err(format!("SHFileOperation failed with code: {}", result))
    }
}

/// Cleans a list of junk items by moving them to the Recycle Bin.
/// Never cleans items marked `Dangerous`.
/// Returns (number of successfully cleaned items, list of errors).
pub fn clean_junk_items(
    items: &[JunkItem],
    allow_questionable: bool,
) -> (usize, Vec<String>) {
    let mut cleaned_count = 0;
    let mut errors = Vec::new();

    for item in items {
        if item.is_registry {
            // Registry key cleaning requires registry deletion logic, skip here
            continue;
        }

        match item.confidence {
            ConfidenceLevel::Dangerous => {
                errors.push(format!(
                    "REFUSED: Path is marked DANGEROUS and cannot be recycled: {}",
                    item.path.display()
                ));
            }
            ConfidenceLevel::Questionable if !allow_questionable => {
                errors.push(format!(
                    "SKIPPED: Path is QUESTIONABLE (enable allow_questionable to recycle): {}",
                    item.path.display()
                ));
            }
            ConfidenceLevel::Safe | ConfidenceLevel::Questionable => {
                match move_to_recycle_bin(&item.path) {
                    Ok(_) => cleaned_count += 1,
                    Err(e) => errors.push(format!("Failed to recycle {}: {}", item.path.display(), e)),
                }
            }
        }
    }

    (cleaned_count, errors)
}
