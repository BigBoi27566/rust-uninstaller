use bcu_core::models::{ApplicationEntry, UninstallerKind};

// Unit test testing the filtering algorithm that the GUI app uses
fn filter_applications<'a>(apps: &'a [ApplicationEntry], query: &str) -> Vec<&'a ApplicationEntry> {
    if query.trim().is_empty() {
        return apps.iter().collect();
    }
    let lower = query.trim().to_lowercase();
    apps.iter()
        .filter(|app| {
            app.display_name.to_lowercase().contains(&lower)
                || app.publisher.as_deref().unwrap_or("").to_lowercase().contains(&lower)
        })
        .collect()
}

#[test]
fn test_filter_applications_by_name_and_publisher() {
    let apps = vec![
        ApplicationEntry {
            id: "1".into(),
            display_name: "Visual Studio Code".into(),
            display_version: Some("1.85".into()),
            publisher: Some("Microsoft Corporation".into()),
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: UninstallerKind::InnoSetup,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        },
        ApplicationEntry {
            id: "2".into(),
            display_name: "Git".into(),
            display_version: Some("2.43".into()),
            publisher: Some("The Git Community".into()),
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: None,
            uninstaller_kind: UninstallerKind::InnoSetup,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        },
    ];

    let matches = filter_applications(&apps, "studio");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].display_name, "Visual Studio Code");

    let matches_publisher = filter_applications(&apps, "Microsoft");
    assert_eq!(matches_publisher.len(), 1);
    assert_eq!(matches_publisher[0].id, "1");

    let all = filter_applications(&apps, "");
    assert_eq!(all.len(), 2);
}

#[test]
fn test_sort_applications_by_name_and_size() {
    let mut apps = vec![
        ApplicationEntry {
            id: "1".into(),
            display_name: "Zeta App".into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: Some(10 * 1024 * 1024), // 10 MB
            uninstaller_kind: UninstallerKind::Unknown,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        },
        ApplicationEntry {
            id: "2".into(),
            display_name: "Alpha App".into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: Some(500 * 1024 * 1024), // 500 MB
            uninstaller_kind: UninstallerKind::Unknown,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        },
        ApplicationEntry {
            id: "3".into(),
            display_name: "Beta App".into(),
            display_version: None,
            publisher: None,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_bytes: None, // 0 / unknown
            uninstaller_kind: UninstallerKind::Unknown,
            is_system_component: false,
            is_protected: false,
            registry_location: None,
        },
    ];

    // Name Ascending
    apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    assert_eq!(apps[0].display_name, "Alpha App");
    assert_eq!(apps[1].display_name, "Beta App");
    assert_eq!(apps[2].display_name, "Zeta App");

    // Name Descending
    apps.sort_by(|a, b| b.display_name.to_lowercase().cmp(&a.display_name.to_lowercase()));
    assert_eq!(apps[0].display_name, "Zeta App");
    assert_eq!(apps[1].display_name, "Beta App");
    assert_eq!(apps[2].display_name, "Alpha App");

    // Size Descending (largest first)
    apps.sort_by(|a, b| {
        let sa = a.estimated_size_bytes.unwrap_or(0);
        let sb = b.estimated_size_bytes.unwrap_or(0);
        sb.cmp(&sa)
    });
    assert_eq!(apps[0].display_name, "Alpha App"); // 500 MB
    assert_eq!(apps[1].display_name, "Zeta App");  // 10 MB
    assert_eq!(apps[2].display_name, "Beta App");  // 0 / None

    // Size Ascending (smallest first)
    apps.sort_by(|a, b| {
        let sa = a.estimated_size_bytes.unwrap_or(0);
        let sb = b.estimated_size_bytes.unwrap_or(0);
        sa.cmp(&sb)
    });
    assert_eq!(apps[0].display_name, "Beta App");  // 0 / None
    assert_eq!(apps[1].display_name, "Zeta App");  // 10 MB
    assert_eq!(apps[2].display_name, "Alpha App"); // 500 MB
}
