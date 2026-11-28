use crate::models::UninstallerKind;

pub fn detect_uninstaller_kind(
    uninstall_command: &str,
    is_windows_installer: Option<bool>,
) -> UninstallerKind {
    if is_windows_installer.unwrap_or(false) {
        return UninstallerKind::Msi;
    }

    let lower = uninstall_command.to_lowercase();

    if lower.contains("msiexec") || lower.contains("/x{") || lower.contains("/i{") {
        return UninstallerKind::Msi;
    }

    // Inno Setup commonly uses unins000.exe or unins001.exe
    if lower.contains("unins000.exe")
        || lower.contains("unins001.exe")
        || lower.contains("unins002.exe")
    {
        return UninstallerKind::InnoSetup;
    }

    // NSIS commonly uses uninstall.exe or uninst.exe
    if lower.contains("uninstall.exe") || lower.contains("uninst.exe") {
        return UninstallerKind::Nsis;
    }

    if lower.contains("_isuninst") || lower.contains("installshield") {
        return UninstallerKind::InstallShield;
    }

    if lower.contains("advancedinstaller") {
        return UninstallerKind::AdvancedInstaller;
    }

    UninstallerKind::Unknown
}

pub fn synthesize_quiet_command(
    uninstall_command: &str,
    kind: &UninstallerKind,
) -> Option<String> {
    let trimmed = uninstall_command.trim();
    if trimmed.is_empty() {
        return None;
    }

    match kind {
        UninstallerKind::InnoSetup => {
            Some(format!(r#"{} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"#, trimmed))
        }
        UninstallerKind::Nsis => {
            Some(format!(r#"{} /S"#, trimmed))
        }
        UninstallerKind::Msi => {
            // If it's MsiExec.exe /I{GUID}, change /I to /X and add /qn /norestart
            let lower = trimmed.to_lowercase();
            if let Some(pos) = lower.find('{') {
                if let Some(end) = lower[pos..].find('}') {
                    let guid = &trimmed[pos..=pos + end];
                    return Some(format!(r#"MsiExec.exe /X{} /qn /norestart"#, guid));
                }
            }
            Some(format!(r#"{} /qn /norestart"#, trimmed))
        }
        UninstallerKind::AdvancedInstaller => {
            Some(format!(r#"{} /quiet /norestart"#, trimmed))
        }
        _ => None,
    }
}

/// Parses a raw Windows uninstall command line string into (executable_path, args).
/// Handles quotes around paths with spaces (e.g. `"C:\Program Files\App\unins.exe" /S`).
pub fn parse_command_line(cmd: &str) -> Option<(String, Vec<String>)> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (exe, rest) = if trimmed.starts_with('"') {
        if let Some(end_quote) = trimmed[1..].find('"') {
            let exe = &trimmed[1..=end_quote];
            let rest = &trimmed[end_quote + 2..];
            (exe.trim().to_string(), rest.trim())
        } else {
            (trimmed[1..].trim().to_string(), "")
        }
    } else if let Some(space_idx) = trimmed.find(|c: char| c.is_whitespace()) {
        let exe = &trimmed[..space_idx];
        let rest = &trimmed[space_idx..];
        (exe.trim().to_string(), rest.trim())
    } else {
        (trimmed.to_string(), "")
    };

    if exe.is_empty() {
        return None;
    }

    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quote = false;

    for ch in rest.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
            }
            c if c.is_whitespace() && !in_quote => {
                if !current_arg.is_empty() {
                    args.push(current_arg.clone());
                    current_arg.clear();
                }
            }
            c => {
                current_arg.push(c);
            }
        }
    }
    if !current_arg.is_empty() {
        args.push(current_arg);
    }

    Some((exe, args))
}

/// Matches `app_name` against `candidate` using exact match or word-boundary match (>= 3 chars)
/// so short names like "Git" do not match unrelated names like "Logitech".
pub fn matches_app_name(candidate: &str, app_name: &str) -> bool {
    let cand = candidate.trim().to_lowercase();
    let target = app_name.trim().to_lowercase();
    if target.is_empty() || cand.is_empty() {
        return false;
    }
    if cand == target {
        return true;
    }
    if target.chars().count() < 3 {
        return false;
    }

    cand.match_indices(&target).any(|(start, _)| {
        let left_ok = cand[..start]
            .chars()
            .next_back()
            .map_or(true, |c| !c.is_alphanumeric());
        let end = start + target.len();
        let right_ok = cand[end..]
            .chars()
            .next()
            .map_or(true, |c| !c.is_alphanumeric());
        left_ok && right_ok
    })
}

