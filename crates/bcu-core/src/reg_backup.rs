use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// Represents data types stored in Windows Registry values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValueData {
    String(String),
    ExpandString(String),
    Dword(u32),
    Qword(u64),
    MultiString(Vec<String>),
    Binary(Vec<u8>),
    None,
}

/// Represents a single registry value to be backed up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValueBackup {
    pub name: String,
    pub data: RegValueData,
}

/// Represents a full registry key and its backed-up values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegKeyBackup {
    pub key_path: String,
    pub values: Vec<RegValueBackup>,
}

/// Rollback generator for Windows Registry (.reg format).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegBackup {
    pub keys: Vec<RegKeyBackup>,
}

impl RegBackup {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn add_key(&mut self, key_path: impl Into<String>, values: Vec<RegValueBackup>) {
        self.keys.push(RegKeyBackup {
            key_path: key_path.into(),
            values,
        });
    }

    /// Generates valid `.reg` text compatible with Windows Registry Editor Version 5.00.
    pub fn to_reg_string(&self) -> String {
        let mut out = String::from("Windows Registry Editor Version 5.00\r\n\r\n");

        for key in &self.keys {
            out.push('[');
            out.push_str(&key.key_path);
            out.push_str("]\r\n");

            for val in &key.values {
                let name_formatted = if val.name.is_empty() || val.name == "@" {
                    "@".to_string()
                } else {
                    format!("\"{}\"", Self::escape_string(&val.name))
                };

                match &val.data {
                    RegValueData::String(s) => {
                        out.push_str(&format!("{}=\"{}\"\r\n", name_formatted, Self::escape_string(s)));
                    }
                    RegValueData::Dword(dw) => {
                        out.push_str(&format!("{}=dword:{:08x}\r\n", name_formatted, dw));
                    }
                    RegValueData::Qword(qw) => {
                        let bytes = qw.to_le_bytes();
                        let hex_str: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        out.push_str(&format!("{}=hex(b):{}\r\n", name_formatted, hex_str.join(",")));
                    }
                    RegValueData::Binary(bytes) => {
                        let hex_str: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        out.push_str(&format!("{}=hex:{}\r\n", name_formatted, hex_str.join(",")));
                    }
                    RegValueData::ExpandString(s) => {
                        let mut utf16_bytes = Vec::new();
                        for u in s.encode_utf16() {
                            utf16_bytes.extend_from_slice(&u.to_le_bytes());
                        }
                        utf16_bytes.push(0);
                        utf16_bytes.push(0);
                        let hex_str: Vec<String> = utf16_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        out.push_str(&format!("{}=hex(2):{}\r\n", name_formatted, hex_str.join(",")));
                    }
                    RegValueData::MultiString(strings) => {
                        let mut utf16_bytes = Vec::new();
                        for s in strings {
                            for u in s.encode_utf16() {
                                utf16_bytes.extend_from_slice(&u.to_le_bytes());
                            }
                            utf16_bytes.push(0);
                            utf16_bytes.push(0);
                        }
                        utf16_bytes.push(0);
                        utf16_bytes.push(0);
                        let hex_str: Vec<String> = utf16_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        out.push_str(&format!("{}=hex(7):{}\r\n", name_formatted, hex_str.join(",")));
                    }
                    RegValueData::None => {
                        // Value without data or key-only
                    }
                }
            }
            out.push_str("\r\n");
        }

        out
    }

    /// Escapes backslashes and double quotes for .reg string literals.
    pub fn escape_string(input: &str) -> String {
        let mut res = String::with_capacity(input.len() * 2);
        for c in input.chars() {
            match c {
                '\\' => res.push_str("\\\\"),
                '"' => res.push_str("\\\""),
                '\r' => res.push_str("\\r"),
                '\n' => res.push_str("\\n"),
                _ => res.push(c),
            }
        }
        res
    }

    /// Saves the .reg file with UTF-8 BOM so Windows regedit.exe correctly renders all characters.
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let reg_content = self.to_reg_string();
        let mut bytes = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        bytes.extend_from_slice(reg_content.as_bytes());

        fs::write(path, bytes)
    }

    /// Resolves default backup directory: `%LOCALAPPDATA%\BCU_Rust\Backups` (or fallback to `%TEMP%`).
    pub fn default_backup_dir() -> PathBuf {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(local_app_data).join("BCU_Rust").join("Backups")
        } else if let Ok(temp) = std::env::var("TEMP") {
            PathBuf::from(temp).join("BCU_Rust").join("Backups")
        } else {
            PathBuf::from("C:\\BCU_Rust_Backups")
        }
    }

    /// Generates a standardized rollback file path: `registry_<epoch_secs>_<app_id>.reg`.
    pub fn generate_backup_path(app_id: &str) -> PathBuf {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sanitized_id: String = app_id
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect();
        let filename = format!("registry_{}_{}.reg", secs, sanitized_id);
        Self::default_backup_dir().join(filename)
    }

    /// Resolves the user's Windows Desktop directory (including OneDrive/custom redirections).
    pub fn desktop_dir() -> PathBuf {
        unsafe {
            if let Ok(pwstr) = windows::Win32::UI::Shell::SHGetKnownFolderPath(
                &windows::Win32::UI::Shell::FOLDERID_Desktop,
                windows::Win32::UI::Shell::KNOWN_FOLDER_FLAG(0),
                None,
            ) {
                let s = pwstr.to_string().unwrap_or_default();
                windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.as_ptr().cast()));
                if !s.is_empty() {
                    return PathBuf::from(s);
                }
            }
        }
        std::env::var("USERPROFILE")
            .map(|p| PathBuf::from(p).join("Desktop"))
            .unwrap_or_else(|_| Self::default_backup_dir())
    }

    /// Writes a desktop `backup(YYYY-MM-DD_HH-MM-SS).zip` containing optional `.reg` rollback and `cleanup_log.txt`.
    pub fn create_desktop_backup_zip(
        reg_backup_path: Option<&Path>,
        summary_text: &str,
    ) -> std::io::Result<PathBuf> {
        let mut owned_reg: Option<(String, Vec<u8>)> = None;
        if let Some(reg_path) = reg_backup_path {
            if let Ok(bytes) = fs::read(reg_path) {
                let name = reg_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("rollback.reg")
                    .to_string();
                owned_reg = Some((name, bytes));
            }
        }

        let mut entries: Vec<(&str, &[u8])> = Vec::new();
        if let Some((ref name, ref bytes)) = owned_reg {
            entries.push((name.as_str(), bytes.as_slice()));
        }
        entries.push(("cleanup_log.txt", summary_text.as_bytes()));

        Self::write_backup_zip_to_dir(&Self::desktop_dir(), &local_timestamp(), &entries)
    }

    /// Writes an uncompressed (STORED) ZIP archive named `backup(<timestamp>).zip` inside `dir`.
    pub fn write_backup_zip_to_dir(
        dir: &Path,
        timestamp: &str,
        entries: &[(&str, &[u8])],
    ) -> std::io::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let mut zip_path = dir.join(format!("backup({}).zip", timestamp));
        let mut suffix = 1usize;
        while zip_path.exists() {
            zip_path = dir.join(format!("backup({})_{}.zip", timestamp, suffix));
            suffix += 1;
        }

        let mut out = Vec::new();
        let mut central_dir = Vec::new();

        for &(name, data) in entries {
            let name_bytes = name.as_bytes();
            let crc = crc32(data);
            let size = data.len() as u32;
            let local_offset = out.len() as u32;

            // Local file header (30 bytes + filename)
            out.extend_from_slice(&0x04034B50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 filename flag
            out.extend_from_slice(&0u16.to_le_bytes()); // method: STORED
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(data);

            // Central directory header (46 bytes + filename)
            central_dir.extend_from_slice(&0x02014B50u32.to_le_bytes());
            central_dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central_dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central_dir.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // STORED
            central_dir.extend_from_slice(&0u16.to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes());
            central_dir.extend_from_slice(&crc.to_le_bytes());
            central_dir.extend_from_slice(&size.to_le_bytes());
            central_dir.extend_from_slice(&size.to_le_bytes());
            central_dir.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes());
            central_dir.extend_from_slice(&0u32.to_le_bytes());
            central_dir.extend_from_slice(&local_offset.to_le_bytes());
            central_dir.extend_from_slice(name_bytes);
        }

        let cd_offset = out.len() as u32;
        let cd_size = central_dir.len() as u32;
        let count = entries.len() as u16;
        out.extend_from_slice(&central_dir);

        // End of central directory record (22 bytes)
        out.extend_from_slice(&0x06054B50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());

        fs::write(&zip_path, out)?;
        Ok(zip_path)
    }
}

fn local_timestamp() -> String {
    let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02}_{:02}-{:02}-{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_reg_backup_header() {
        let backup = RegBackup::new();
        let text = backup.to_reg_string();
        assert_eq!(text, "Windows Registry Editor Version 5.00\r\n\r\n");
    }

    #[test]
    fn test_escape_string() {
        let raw = r#"C:\Program Files\App "Special"\test.exe"#;
        let escaped = RegBackup::escape_string(raw);
        assert_eq!(escaped, r#"C:\\Program Files\\App \"Special\"\\test.exe"#);
    }

    #[test]
    fn test_reg_backup_formatting() {
        let mut backup = RegBackup::new();
        backup.add_key(
            r#"HKEY_CURRENT_USER\Software\TestApp"#,
            vec![
                RegValueBackup {
                    name: "@".to_string(),
                    data: RegValueData::String("Default App Value".to_string()),
                },
                RegValueBackup {
                    name: "InstallPath".to_string(),
                    data: RegValueData::String(r#"C:\Games\TestApp"#.to_string()),
                },
                RegValueBackup {
                    name: "VersionCode".to_string(),
                    data: RegValueData::Dword(1024),
                },
                RegValueBackup {
                    name: "FlagBits".to_string(),
                    data: RegValueData::Binary(vec![0xAA, 0xBB, 0xCC]),
                },
            ],
        );

        let content = backup.to_reg_string();
        assert!(content.starts_with("Windows Registry Editor Version 5.00\r\n\r\n"));
        assert!(content.contains("[HKEY_CURRENT_USER\\Software\\TestApp]\r\n"));
        assert!(content.contains("@=\"Default App Value\"\r\n"));
        assert!(content.contains(r#""InstallPath"="C:\\Games\\TestApp""#));
        assert!(content.contains(r#""VersionCode"=dword:00000400"#));
        assert!(content.contains(r#""FlagBits"=hex:aa,bb,cc"#));
    }

    #[test]
    fn test_save_and_verify_file_bom() {
        let mut backup = RegBackup::new();
        backup.add_key(
            r#"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TestClsid"#,
            vec![RegValueBackup {
                name: "DisplayName".to_string(),
                data: RegValueData::String("Phần mềm Kiểm thử Tiếng Việt".to_string()),
            }],
        );

        let temp_dir = std::env::temp_dir().join("bcu_test_backup");
        let file_path = temp_dir.join("test_rollback.reg");

        let res = backup.save_to_file(&file_path);
        assert!(res.is_ok());

        let bytes = fs::read(&file_path).unwrap();
        // Verify UTF-8 BOM
        assert_eq!(&bytes[0..3], &[0xEF, 0xBB, 0xBF]);

        let string_content = String::from_utf8(bytes[3..].to_vec()).unwrap();
        assert!(string_content.contains("Phần mềm Kiểm thử Tiếng Việt"));

        let _ = fs::remove_file(file_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_write_backup_zip_creates_valid_archive() {
        let temp_dir = std::env::temp_dir().join("bcu_test_zip_backup");
        let extract_dir = temp_dir.join("extracted");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let zip_path = RegBackup::write_backup_zip_to_dir(
            &temp_dir,
            "2026-11-28_16-10-05",
            &[
                ("rollback.reg", b"Windows Registry Editor Version 5.00\r\n" as &[u8]),
                ("cleanup_log.txt", b"Recycled: C:\\Test\\App\r\n" as &[u8]),
            ],
        )
        .expect("must write zip");

        assert_eq!(
            zip_path.file_name().unwrap().to_str().unwrap(),
            "backup(2026-11-28_16-10-05).zip"
        );
        let raw = fs::read(&zip_path).unwrap();
        assert_eq!(&raw[0..4], b"PK\x03\x04");

        // Verify Windows Expand-Archive extracts both files intact
        let status = std::process::Command::new("PowerShell.exe")
            .args([
                "-NonInteractive",
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    zip_path.display(),
                    extract_dir.display()
                ),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read(extract_dir.join("rollback.reg")).unwrap(),
            b"Windows Registry Editor Version 5.00\r\n"
        );
        assert_eq!(
            fs::read(extract_dir.join("cleanup_log.txt")).unwrap(),
            b"Recycled: C:\\Test\\App\r\n"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
