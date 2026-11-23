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
}
