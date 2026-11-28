use crate::heuristics::{parse_command_line, parse_display_icon_spec};
use crate::models::{ApplicationEntry, UninstallerKind};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS,
};
use windows::Win32::UI::Shell::ExtractIconExW;
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

/// Extracts a 16x16 RGBA icon (`1024` bytes) for an application from `DisplayIcon` or its uninstaller exe.
pub fn extract_app_icon_rgba(app: &ApplicationEntry) -> Option<Vec<u8>> {
    if app.uninstaller_kind == UninstallerKind::StoreApp {
        return None;
    }

    if let Some(ref spec) = app.display_icon {
        let expanded = expand_env_vars(spec);
        if let Some((path, index)) = parse_display_icon_spec(&expanded) {
            if let Some(rgba) = extract_icon_from_path(&path, index) {
                return Some(rgba);
            }
        }
    }

    if let Some(ref cmd) = app.uninstall_string {
        let expanded = expand_env_vars(cmd);
        if let Some((exe, _)) = parse_command_line(&expanded) {
            let lower = exe.to_lowercase();
            if !lower.ends_with("msiexec.exe") && !lower.ends_with("cmd.exe") {
                if let Some(rgba) = extract_icon_from_path(Path::new(&exe), 0) {
                    return Some(rgba);
                }
            }
        }
    }

    None
}

/// Extracts a 16x16 RGBA bitmap from a Windows `.exe`, `.dll`, or `.ico` file.
pub fn extract_icon_from_path(path: &Path, icon_index: i32) -> Option<Vec<u8>> {
    if !path.is_file() {
        return None;
    }

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut small_icon = HICON::default();
    let count = unsafe {
        ExtractIconExW(
            PCWSTR(wide.as_ptr()),
            icon_index,
            None,
            Some(&mut small_icon),
            1,
        )
    };
    if count == 0 || small_icon.is_invalid() {
        return None;
    }

    let rgba = hicon_to_rgba16(small_icon);
    unsafe {
        let _ = DestroyIcon(small_icon);
    }
    rgba
}

fn hicon_to_rgba16(hicon: HICON) -> Option<Vec<u8>> {
    const SIZE: usize = 16;
    let mut info = ICONINFO::default();
    if unsafe { GetIconInfo(hicon, &mut info) }.is_err() {
        return None;
    }

    let result = (|| {
        if info.hbmColor.is_invalid() {
            return None;
        }
        let hdc = unsafe { CreateCompatibleDC(None) };
        if hdc.is_invalid() {
            return None;
        }

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: SIZE as i32,
                biHeight: -(SIZE as i32), // top-down DIB
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut pixels = vec![0u8; SIZE * SIZE * 4];
        let rows = unsafe {
            GetDIBits(
                hdc,
                info.hbmColor,
                0,
                SIZE as u32,
                Some(pixels.as_mut_ptr().cast()),
                &mut bmi,
                DIB_RGB_COLORS,
            )
        };
        unsafe {
            let _ = DeleteDC(hdc);
        }
        if rows == 0 {
            return None;
        }

        for chunk in pixels.chunks_exact_mut(4) {
            chunk.swap(0, 2); // BGRA -> RGBA
        }

        // Old 24-bit icons leave alpha=0 everywhere; promote non-black pixels to opaque
        if pixels.chunks_exact(4).all(|p| p[3] == 0) {
            let has_color = pixels.chunks_exact(4).any(|p| p[0] | p[1] | p[2] != 0);
            if !has_color {
                return None;
            }
            for p in pixels.chunks_exact_mut(4) {
                if p[0] | p[1] | p[2] != 0 {
                    p[3] = 255;
                }
            }
        }

        Some(pixels)
    })();

    unsafe {
        if !info.hbmColor.is_invalid() {
            let _ = DeleteObject(info.hbmColor);
        }
        if !info.hbmMask.is_invalid() {
            let _ = DeleteObject(info.hbmMask);
        }
    }

    result
}

fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let var_name = &after[..end];
            if !var_name.is_empty() {
                if let Ok(val) = std::env::var(var_name) {
                    out.push_str(&val);
                    rest = &after[end + 1..];
                    continue;
                }
            }
            out.push('%');
            out.push_str(var_name);
            out.push('%');
            rest = &after[end + 1..];
        } else {
            out.push('%');
            rest = after;
            break;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_icon_returns_none_for_missing_file() {
        assert!(extract_icon_from_path(Path::new(r"C:\NonExistent_BCU_Icon_123.exe"), 0).is_none());
    }

    #[test]
    fn test_expand_env_vars_resolves_known_var() {
        std::env::set_var("BCU_TEST_ICON_DIR", r"C:\Apps");
        assert_eq!(
            expand_env_vars(r"%BCU_TEST_ICON_DIR%\Tool\app.exe,0"),
            r"C:\Apps\Tool\app.exe,0"
        );
        std::env::remove_var("BCU_TEST_ICON_DIR");
    }
}
