use windows::Win32::Foundation::{BOOL, HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassNameW, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowVisible, SendMessageW, BM_CLICK,
};

/// Result of an automation probe or action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomationStatus {
    /// Successfully clicked a standard affirmative button.
    Clicked {
        button_text: String,
        hwnd: isize,
    },
    /// Detected a potentially destructive prompt (e.g. data loss question); yielded control to user.
    YieldToUser {
        reason: String,
        window_title: String,
    },
    /// No actionable buttons or dialogs found in target process windows.
    NoActionFound,
    /// Target process has no visible top-level windows.
    ProcessWindowNotFound,
}

const AFFIRMATIVE_BUTTONS: &[&str] = &[
    "next",
    "next >",
    "next >>",
    "i agree",
    "agree",
    "install",
    "uninstall",
    "finish",
    "close",
    "done",
    "continue",
    "tiếp tục",
    "tiếp tục >",
    "đồng ý",
    "gỡ cài đặt",
    "hoàn tất",
    "đóng",
];

const DESTRUCTIVE_PHRASES: &[&str] = &[
    "delete personal",
    "delete database",
    "remove personal",
    "keep personal",
    "keep settings",
    "delete settings",
    "delete configuration",
    "remove configuration",
    "save data",
    "format drive",
    "restart now",
    "reboot now",
    "xóa dữ liệu",
    "xóa cấu hình",
    "giữ lại cài đặt",
    "khởi động lại ngay",
];

/// Checks if a text string matches standard affirmative button labels.
pub fn is_affirmative_button(raw_text: &str) -> bool {
    let cleaned = clean_label(raw_text);
    if cleaned.is_empty() {
        return false;
    }

    AFFIRMATIVE_BUTTONS
        .iter()
        .any(|&verb| cleaned == verb || cleaned.starts_with(&format!("{} ", verb)))
}

/// Checks if dialog text contains phrases indicating potential user data loss or reboot requests.
pub fn is_destructive_prompt(raw_text: &str) -> bool {
    let lower = raw_text.to_lowercase();
    DESTRUCTIVE_PHRASES.iter().any(|&phrase| lower.contains(phrase))
}

/// Cleans label string by stripping accelerators (&) and extraneous punctuation.
pub fn clean_label(text: &str) -> String {
    text.chars()
        .filter(|&c| c != '&' && c != '_' && c != '\r' && c != '\n')
        .collect::<String>()
        .trim()
        .to_lowercase()
}

/// Enumerate all visible top-level windows belonging to a given PID.
pub fn find_visible_windows_for_pid(target_pid: u32) -> Vec<HWND> {
    struct EnumContext {
        pid: u32,
        windows: Vec<HWND>,
    }

    let mut ctx = EnumContext {
        pid: target_pid,
        windows: Vec::new(),
    };

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut EnumContext);
        let mut proc_id = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut proc_id));

        if proc_id == ctx.pid && IsWindowVisible(hwnd).as_bool() {
            ctx.windows.push(hwnd);
        }
        BOOL(1)
    }

    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(&mut ctx as *mut _ as isize));
    }

    ctx.windows
}

/// Extracts title/text from a window handle safely.
pub unsafe fn get_window_text(hwnd: HWND) -> String {
    let len = GetWindowTextLengthW(hwnd);
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; (len + 1) as usize];
    let copied = GetWindowTextW(hwnd, &mut buf);
    if copied > 0 {
        String::from_utf16_lossy(&buf[..copied as usize])
    } else {
        String::new()
    }
}

/// Extracts class name from a window handle safely.
pub unsafe fn get_window_class(hwnd: HWND) -> String {
    let mut buf = [0u16; 256];
    let len = GetClassNameW(hwnd, &mut buf);
    if len > 0 {
        String::from_utf16_lossy(&buf[..len as usize])
    } else {
        String::new()
    }
}

/// Probes a window and child controls, auto-clicking affirmative buttons if safe.
pub fn automate_uninstaller_window(hwnd: HWND) -> AutomationStatus {
    let title = unsafe { get_window_text(hwnd) };

    // 1. Check if window title contains destructive phrase
    if is_destructive_prompt(&title) {
        return AutomationStatus::YieldToUser {
            reason: "Window title indicates user confirmation needed".to_string(),
            window_title: title,
        };
    }

    struct ChildContext {
        buttons: Vec<(HWND, String)>,
        dialog_text: Vec<String>,
    }

    let mut ctx = ChildContext {
        buttons: Vec::new(),
        dialog_text: Vec::new(),
    };

    unsafe extern "system" fn enum_child(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut ChildContext);
        let class = get_window_class(hwnd);
        let text = get_window_text(hwnd);

        if class.eq_ignore_ascii_case("button") {
            ctx.buttons.push((hwnd, text));
        } else if class.eq_ignore_ascii_case("static") {
            ctx.dialog_text.push(text);
        }
        BOOL(1)
    }

    unsafe {
        let _ = EnumChildWindows(hwnd, Some(enum_child), LPARAM(&mut ctx as *mut _ as isize));
    }

    // 2. Check all static text labels for destructive phrases
    for label in &ctx.dialog_text {
        if is_destructive_prompt(label) {
            return AutomationStatus::YieldToUser {
                reason: format!("Destructive prompt detected: \"{}\"", label),
                window_title: title,
            };
        }
    }

    // 3. Scan for affirmative action buttons
    for (btn_hwnd, btn_text) in ctx.buttons {
        if is_affirmative_button(&btn_text) {
            // Dispatch click via BM_CLICK message
            unsafe {
                SendMessageW(btn_hwnd, BM_CLICK, WPARAM(0), LPARAM(0));
            }
            return AutomationStatus::Clicked {
                button_text: btn_text,
                hwnd: btn_hwnd.0 as isize,
            };
        }
    }

    AutomationStatus::NoActionFound
}

/// Executes a single automated clicker probe against all visible windows of target PID.
pub fn run_automation_cycle(pid: u32) -> AutomationStatus {
    let windows = find_visible_windows_for_pid(pid);
    if windows.is_empty() {
        return AutomationStatus::ProcessWindowNotFound;
    }

    for hwnd in windows {
        let status = automate_uninstaller_window(hwnd);
        if status != AutomationStatus::NoActionFound {
            return status;
        }
    }

    AutomationStatus::NoActionFound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affirmative_buttons_matching() {
        assert!(is_affirmative_button("&Next >"));
        assert!(is_affirmative_button("Next"));
        assert!(is_affirmative_button("&I Agree"));
        assert!(is_affirmative_button("Uninstall"));
        assert!(is_affirmative_button("&Finish"));
        assert!(is_affirmative_button("&Tiếp tục >"));
        assert!(is_affirmative_button("Đồng ý"));
        assert!(is_affirmative_button("Gỡ cài đặt"));
        assert!(!is_affirmative_button("Cancel"));
        assert!(!is_affirmative_button("Hủy bỏ"));
        assert!(!is_affirmative_button("Back"));
    }

    #[test]
    fn test_destructive_prompt_detection() {
        assert!(is_destructive_prompt("Do you want to delete personal files?"));
        assert!(is_destructive_prompt("Keep settings on this computer?"));
        assert!(is_destructive_prompt("Warning: Will remove configuration database!"));
        assert!(is_destructive_prompt("Bạn có muốn xóa dữ liệu cá nhân không?"));
        assert!(is_destructive_prompt("Restart now to complete uninstallation"));
        assert!(!is_destructive_prompt("Are you sure you want to uninstall App?"));
        assert!(!is_destructive_prompt("Click Next to continue."));
    }

    #[test]
    fn test_clean_label() {
        assert_eq!(clean_label("&Next >"), "next >");
        assert_eq!(clean_label("  &I Agree  "), "i agree");
        assert_eq!(clean_label("&Uninstall\r\n"), "uninstall");
    }
}
