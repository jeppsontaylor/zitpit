use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::{fs, process::Command};
use uuid::Uuid;

use crate::{
    lab::LabPlanner,
    types::{ArtifactCoordinate, ArtifactKey, LabRun, LabRunStatus},
};
use zitpit_config::RuntimePaths;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirecrackerConfig {
    pub machine_config: MachineConfig,
    pub boot_source: BootSource,
    pub drives: Vec<Drive>,
    pub network_interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineConfig {
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
    pub smt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
    pub allow_mmds: bool,
}

#[derive(Debug, Clone)]
pub struct FirecrackerOrchestrator {
    pub firecracker_bin: PathBuf,
    pub kernel_image: PathBuf,
    pub rootfs_image: PathBuf,
    pub base_run_dir: PathBuf,
}

impl Default for FirecrackerOrchestrator {
    fn default() -> Self {
        let paths = RuntimePaths::from_env();
        Self {
            firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
            kernel_image: PathBuf::from("/var/lib/zitpit/vmlinux"),
            rootfs_image: PathBuf::from("/var/lib/zitpit/rootfs.ext4"),
            base_run_dir: paths.firecracker_run_dir,
        }
    }
}

impl FirecrackerOrchestrator {
    pub fn with_paths(paths: RuntimePaths) -> Self {
        Self {
            base_run_dir: paths.firecracker_run_dir,
            ..Self::default()
        }
    }

    pub fn is_available(&self) -> bool {
        self.firecracker_bin.exists() && self.kernel_image.exists() && self.rootfs_image.exists()
    }

    pub fn plan_run(&self, artifact: ArtifactCoordinate) -> LabRun {
        let run_id = Uuid::new_v4();
        let tap_device = format!("zitpit{}", &run_id.simple().to_string()[..8]);
        let detonation_plan = LabPlanner::plan(artifact.clone());
        LabRun {
            run_id,
            artifact_key: ArtifactKey::from(&artifact),
            status: if self.is_available() {
                LabRunStatus::Planned
            } else {
                LabRunStatus::Skipped
            },
            planned_at: Utc::now(),
            started_at: None,
            finished_at: None,
            personas: detonation_plan.personas,
            scenarios: detonation_plan.scenarios,
            firecracker_config_path: None,
            firecracker_api_socket: Some(
                self.base_run_dir
                    .join(run_id.to_string())
                    .join("firecracker.socket")
                    .display()
                    .to_string(),
            ),
            tap_device: Some(tap_device),
            command_preview: vec![
                self.firecracker_bin.display().to_string(),
                "--api-sock".to_string(),
                self.base_run_dir
                    .join(run_id.to_string())
                    .join("firecracker.socket")
                    .display()
                    .to_string(),
            ],
            notes: vec![
                format!("kernel image: {}", self.kernel_image.display()),
                format!("rootfs image: {}", self.rootfs_image.display()),
                "planning only; execution requires Firecracker host assets".to_string(),
            ],
        }
    }

    pub async fn prepare_run_dir(
        &self,
        artifact: &ArtifactCoordinate,
    ) -> Result<FirecrackerRunArtifacts, std::io::Error> {
        let run_id = Uuid::new_v4();
        let run_dir = self.base_run_dir.join(run_id.to_string());
        fs::create_dir_all(&run_dir).await?;

        let tap_device = format!("zitpit{}", &run_id.simple().to_string()[..8]);
        let api_socket = run_dir.join("firecracker.socket");
        let config_path = run_dir.join("firecracker.json");
        let sinkhole_dir = run_dir.join("sinkhole");
        fs::create_dir_all(&sinkhole_dir).await?;

        let config = self.build_config(artifact, &tap_device);
        let config_json =
            serde_json::to_string_pretty(&config).expect("serialize firecracker config");
        fs::write(&config_path, config_json.as_bytes()).await?;

        Ok(FirecrackerRunArtifacts {
            run_id,
            run_dir,
            config_path,
            api_socket,
            tap_device,
            sinkhole_dir,
            config,
        })
    }

    pub async fn launch_if_available(
        &self,
        artifact: ArtifactCoordinate,
    ) -> Result<LabRun, std::io::Error> {
        let artifacts = self.prepare_run_dir(&artifact).await?;
        let mut run = self.plan_run(artifact.clone());
        run.run_id = artifacts.run_id;
        run.status = if self.is_available() {
            LabRunStatus::Running
        } else {
            LabRunStatus::Skipped
        };
        run.firecracker_config_path = Some(artifacts.config_path.display().to_string());
        run.firecracker_api_socket = Some(artifacts.api_socket.display().to_string());
        run.tap_device = Some(artifacts.tap_device.clone());
        run.command_preview = vec![
            self.firecracker_bin.display().to_string(),
            "--api-sock".to_string(),
            artifacts.api_socket.display().to_string(),
            "--config-file".to_string(),
            artifacts.config_path.display().to_string(),
        ];
        run.notes.push(format!(
            "sinkhole workspace: {}",
            artifacts.sinkhole_dir.display()
        ));
        run.notes
            .push("guest egress must be sinkholed before execution".to_string());

        if self.is_available() {
            let child = Command::new(&self.firecracker_bin)
                .arg("--api-sock")
                .arg(&artifacts.api_socket)
                .arg("--config-file")
                .arg(&artifacts.config_path)
                .spawn()?;
            run.started_at = Some(Utc::now());
            run.notes
                .push(format!("spawned firecracker pid {:?}", child.id()));
        }

        Ok(run)
    }

    pub fn build_config(
        &self,
        artifact: &ArtifactCoordinate,
        tap_device: &str,
    ) -> FirecrackerConfig {
        let boot_args = format!(
            "console=ttyS0 reboot=k panic=1 init=/sbin/init zitpit.source={} zitpit.selector={} zitpit.ecosystem={:?}",
            artifact.source, artifact.requested_selector, artifact.ecosystem
        );
        FirecrackerConfig {
            machine_config: MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 512,
                smt: false,
            },
            boot_source: BootSource {
                kernel_image_path: self.kernel_image.display().to_string(),
                boot_args,
            },
            drives: vec![Drive {
                drive_id: "rootfs".to_string(),
                path_on_host: self.rootfs_image.display().to_string(),
                is_root_device: true,
                is_read_only: true,
            }],
            network_interfaces: vec![NetworkInterface {
                iface_id: "eth0".to_string(),
                host_dev_name: tap_device.to_string(),
                allow_mmds: false,
            }],
        }
    }

    pub fn config_exists(&self) -> bool {
        Path::new(&self.kernel_image).exists() && Path::new(&self.rootfs_image).exists()
    }
}

#[derive(Debug, Clone)]
pub struct FirecrackerRunArtifacts {
    pub run_id: Uuid,
    pub run_dir: PathBuf,
    pub config_path: PathBuf,
    pub api_socket: PathBuf,
    pub tap_device: String,
    pub sinkhole_dir: PathBuf,
    pub config: FirecrackerConfig,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::FirecrackerOrchestrator;
    use crate::{ArtifactCoordinate, Ecosystem, SelectorKind};
    use zitpit_config::RuntimePaths;

    #[test]
    fn build_config_contains_tap_and_sinkhole_context() {
        let orchestrator = FirecrackerOrchestrator {
            firecracker_bin: PathBuf::from("/tmp/firecracker"),
            kernel_image: PathBuf::from("/tmp/kernel"),
            rootfs_image: PathBuf::from("/tmp/rootfs"),
            base_run_dir: PathBuf::from("/tmp/runs"),
        };
        let config = orchestrator.build_config(
            &ArtifactCoordinate {
                ecosystem: Ecosystem::Archive,
                source: "https://github.com/acme/tool/releases/download/v2.0.0/tool.tar.gz"
                    .to_string(),
                requested_selector: "v2.0.0".to_string(),
                selector_kind: SelectorKind::Tag,
            },
            "zitpitzero",
        );
        assert_eq!(config.network_interfaces[0].host_dev_name, "zitpitzero");
        assert!(config.boot_source.boot_args.contains("zitpit.source"));
    }

    #[tokio::test]
    async fn prepare_run_dir_writes_config_json() {
        let tmp = tempdir().expect("tempdir");
        let mut orchestrator =
            FirecrackerOrchestrator::with_paths(RuntimePaths::new(tmp.path().join("state")));
        orchestrator.firecracker_bin = PathBuf::from("/tmp/firecracker");
        orchestrator.kernel_image = PathBuf::from("/tmp/kernel");
        orchestrator.rootfs_image = PathBuf::from("/tmp/rootfs");
        let artifacts = orchestrator
            .prepare_run_dir(&ArtifactCoordinate {
                ecosystem: Ecosystem::Archive,
                source: "https://github.com/acme/tool/releases/download/v2.0.0/tool.tar.gz"
                    .to_string(),
                requested_selector: "v2.0.0".to_string(),
                selector_kind: SelectorKind::Tag,
            })
            .await
            .expect("prepare run dir");
        assert!(artifacts.config_path.exists());
    }
}
