use crate::models::ApplicationEntry;

/// Exports a slice of application entries into RFC 4180 compliant CSV string.
pub fn export_to_csv(apps: &[ApplicationEntry]) -> String {
    let mut out = String::new();
    out.push_str("ID,DisplayName,Version,Publisher,Kind,QuietAvailable,InstallLocation,UninstallString\n");

    for app in apps {
        let has_quiet = if app.quiet_uninstall_string.is_some() { "YES" } else { "NO" };
        let install_loc = app
            .install_location
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let row = format!(
            "{},{},{},{},{:?},{},{},{}\n",
            escape_csv(&app.id),
            escape_csv(&app.display_name),
            escape_csv(app.display_version.as_deref().unwrap_or("")),
            escape_csv(app.publisher.as_deref().unwrap_or("")),
            app.uninstaller_kind,
            has_quiet,
            escape_csv(&install_loc),
            escape_csv(app.uninstall_string.as_deref().unwrap_or(""))
        );
        out.push_str(&row);
    }

    out
}

/// Exports a slice of application entries into a formatted JSON string.
pub fn export_to_json(apps: &[ApplicationEntry]) -> String {
    serde_json::to_string_pretty(apps).unwrap_or_else(|_| "[]".to_string())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}
