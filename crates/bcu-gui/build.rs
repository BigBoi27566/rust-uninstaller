fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "RustUninstaller");
        res.set("FileDescription", "RustUninstaller - Fast & Lightweight Uninstaller");
        res.set("OriginalFilename", "rust-uninstaller.exe");
        res.set("LegalCopyright", "Copyright (c) 2026 RustUninstaller Contributors (Apache-2.0)");
        res.set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#);
        let _ = res.compile();
    }
}
