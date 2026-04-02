use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePaths {
    pub data_dir: PathBuf,
    pub git_approved_root: PathBuf,
    pub git_quarantine_root: PathBuf,
    pub git_upstream_root: PathBuf,
    pub firecracker_run_dir: PathBuf,
}

impl RuntimePaths {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            git_approved_root: data_dir.join("git/approved"),
            git_quarantine_root: data_dir.join("git/quarantine"),
            git_upstream_root: data_dir.join("git/upstream"),
            firecracker_run_dir: data_dir.join("firecracker"),
            data_dir,
        }
    }

    pub fn from_env() -> Self {
        let data_dir = std::env::var_os("ZITPIT_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".zitpit"));
        Self::new(data_dir)
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.git_approved_root)?;
        std::fs::create_dir_all(&self.git_quarantine_root)?;
        std::fs::create_dir_all(&self.git_upstream_root)?;
        std::fs::create_dir_all(&self.firecracker_run_dir)?;
        Ok(())
    }

    pub fn state_dir(&self) -> &Path {
        &self.data_dir
    }
}
