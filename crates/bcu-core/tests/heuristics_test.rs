use bcu_core::heuristics::{
    detect_uninstaller_kind, matches_app_name, parse_command_line, synthesize_quiet_command,
};
use bcu_core::models::UninstallerKind;

#[test]
fn test_detect_inno_setup() {
    let cmd = r#""C:\Program Files\MyTool\unins000.exe""#;
    let kind = detect_uninstaller_kind(cmd, None);
    assert_eq!(kind, UninstallerKind::InnoSetup);

    let quiet = synthesize_quiet_command(cmd, &kind).expect("Should synthesize quiet command");
    assert!(quiet.contains("/VERYSILENT"));
    assert!(quiet.contains("/SUPPRESSMSGBOXES"));
}

#[test]
fn test_detect_nsis() {
    let cmd = r#""C:\Program Files\VLC\uninstall.exe""#;
    let kind = detect_uninstaller_kind(cmd, None);
    assert_eq!(kind, UninstallerKind::Nsis);

    let quiet = synthesize_quiet_command(cmd, &kind).expect("Should synthesize quiet command");
    assert!(quiet.contains("/S"));
}

#[test]
fn test_detect_msi() {
    let cmd = "MsiExec.exe /I{12345678-ABCD-1234-ABCD-1234567890AB}";
    let kind = detect_uninstaller_kind(cmd, None);
    assert_eq!(kind, UninstallerKind::Msi);

    let quiet = synthesize_quiet_command(cmd, &kind).expect("Should synthesize quiet command");
    assert!(quiet.contains("/qn"));
    assert!(quiet.contains("/X{12345678-ABCD-1234-ABCD-1234567890AB}"));
}

#[test]
fn test_parse_command_line() {
    // Quoted path with spaces and flags
    let (exe, args) = parse_command_line(r#""C:\Program Files\Bandicam\uninstall.exe" /S"#).unwrap();
    assert_eq!(exe, r#"C:\Program Files\Bandicam\uninstall.exe"#);
    assert_eq!(args, vec!["/S"]);

    // Quoted path without flags
    let (exe2, args2) = parse_command_line(r#""C:\Program Files\Bandicam\uninstall.exe""#).unwrap();
    assert_eq!(exe2, r#"C:\Program Files\Bandicam\uninstall.exe"#);
    assert!(args2.is_empty());

    // Unquoted path with spaces and flags
    let (exe3, args3) = parse_command_line("MsiExec.exe /X{12345} /qn /norestart").unwrap();
    assert_eq!(exe3, "MsiExec.exe");
    assert_eq!(args3, vec!["/X{12345}", "/qn", "/norestart"]);

    // Empty
    assert!(parse_command_line("   ").is_none());
}

#[test]
fn test_matches_app_name_word_boundaries() {
    assert!(matches_app_name("Git", "Git"));
    assert!(matches_app_name("Git for Windows", "Git"));
    assert!(matches_app_name("MyCoolApp Tools", "MyCoolApp"));
    assert!(!matches_app_name("Logitech", "Git"));
    assert!(!matches_app_name("GitHub", "Git"));
    assert!(matches_app_name("Go", "Go"));
    assert!(!matches_app_name("Google Chrome", "Go"));
}
