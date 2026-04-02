pub use clap::Parser;
use zitpit_config::RuntimePaths;

#[derive(Debug, Clone, Parser)]
pub struct CommonFlags {
    #[arg(long, env = "ZITPIT_DATA_DIR", default_value = ".zitpit")]
    pub data_dir: std::path::PathBuf,
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: Option<String>,
}

impl CommonFlags {
    pub fn runtime_paths(&self) -> RuntimePaths {
        RuntimePaths::new(self.data_dir.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::CommonFlags;
    use clap::Parser;

    #[test]
    fn parses_defaults() {
        let flags = CommonFlags::parse_from(["zitpit", "--data-dir", "/tmp/zitpit"]);
        assert_eq!(flags.data_dir, std::path::PathBuf::from("/tmp/zitpit"));
    }
}
