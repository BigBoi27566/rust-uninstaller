use bcu_core::models::{ApplicationEntry, UninstallerKind};
use bcu_core::queue::{TaskStatus, UninstallQueue};

#[test]
fn test_queue_ordering_and_msi_collision_prevention() {
    let mut queue = UninstallQueue::new();

    let msi_app_1 = ApplicationEntry {
        id: "msi1".into(),
        display_name: "MSI App 1".into(),
        display_version: None,
        publisher: None,
        install_location: None,
        uninstall_string: Some("msiexec /X{1}".into()),
        quiet_uninstall_string: Some("msiexec /X{1} /qn".into()),
        install_date: None,
        estimated_size_bytes: None,
        uninstaller_kind: UninstallerKind::Msi,
        is_system_component: false,
        is_protected: false,
    };

    let msi_app_2 = ApplicationEntry {
        id: "msi2".into(),
        display_name: "MSI App 2".into(),
        display_version: None,
        publisher: None,
        install_location: None,
        uninstall_string: Some("msiexec /X{2}".into()),
        quiet_uninstall_string: Some("msiexec /X{2} /qn".into()),
        install_date: None,
        estimated_size_bytes: None,
        uninstaller_kind: UninstallerKind::Msi,
        is_system_component: false,
        is_protected: false,
    };

    let inno_app = ApplicationEntry {
        id: "inno1".into(),
        display_name: "Inno App".into(),
        display_version: None,
        publisher: None,
        install_location: None,
        uninstall_string: Some("unins000.exe".into()),
        quiet_uninstall_string: Some("unins000.exe /VERYSILENT".into()),
        install_date: None,
        estimated_size_bytes: None,
        uninstaller_kind: UninstallerKind::InnoSetup,
        is_system_component: false,
        is_protected: false,
    };

    queue.add(msi_app_1);
    queue.add(msi_app_2);
    queue.add(inno_app);

    assert_eq!(queue.len(), 3);

    // Pick first executable task
    let id1 = queue.next_runnable_task().map(|t| t.app.id.clone()).expect("First task runnable");
    assert_eq!(id1, "msi1");
    queue.set_status(&id1, TaskStatus::Running);

    // Because msi1 is Running, msi2 cannot run in parallel (MSI collision rule)
    // But inno_app CAN run because it does not conflict with msiexec!
    let id2 = queue.next_runnable_task().map(|t| t.app.id.clone()).expect("Inno runnable");
    assert_eq!(id2, "inno1");
    queue.set_status(&id2, TaskStatus::Running);

    // Now no tasks can run until an MSI completes
    assert!(queue.next_runnable_task().is_none(), "msi2 must wait for msi1");

    // Complete msi1
    queue.set_status("msi1", TaskStatus::Completed);

    // Now msi2 becomes runnable!
    let id3 = queue.next_runnable_task().map(|t| t.app.id.clone()).expect("msi2 should now run");
    assert_eq!(id3, "msi2");
}
