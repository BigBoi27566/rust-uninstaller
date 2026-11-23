#[test]
fn test_icon_assets_exist_and_valid() {
    let png_bytes = include_bytes!("../assets/icon.png");
    assert!(png_bytes.len() > 100);
    assert_eq!(&png_bytes[0..8], b"\x89PNG\r\n\x1a\n");

    let ico_bytes = include_bytes!("../assets/icon.ico");
    assert!(ico_bytes.len() > 100);
    assert_eq!(&ico_bytes[0..4], &[0x00, 0x00, 0x01, 0x00]); // ICO magic
}
