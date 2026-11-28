use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UninstallerKind {
    Msi,
    InnoSetup,
    Nsis,
    InstallShield,
    AdvancedInstaller,
    StoreApp,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Safe,
    Questionable,
    Dangerous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryHive {
    Hklm64,
    Hklm32,
    Hkcu,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryLocation {
    pub hive: RegistryHive,
    pub subkey_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationEntry {
    pub id: String,
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub install_date: Option<String>,
    pub estimated_size_bytes: Option<u64>,
    pub uninstaller_kind: UninstallerKind,
    pub is_system_component: bool,
    pub is_protected: bool,
    #[serde(default)]
    pub registry_location: Option<RegistryLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JunkItem {
    pub path: PathBuf,
    pub is_registry: bool,
    pub confidence: ConfidenceLevel,
    pub reason: String,
    #[serde(default)]
    pub size_bytes: Option<u64>,
}
