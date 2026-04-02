use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zitpit_core::{
    ArtifactCoordinate, DetectionSeverity, DetonationPersona, DetonationScenario,
    PackageLifecyclePhase, TripwireKind, Verdict,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BattleSuite {
    Fast,
    GitCore,
    Actions,
    Artifact,
    Browser,
    Queue,
    Controls,
    PublicCore,
    Vm,
    Go,
    Cargo,
    Shell,
    Workspace,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttackFamily {
    GitIntegrity,
    GithubActions,
    MaintainerCompromise,
    PackageInstallMalware,
    RuntimeTrojan,
    BrowserSessionAbuse,
    Control,
    GoModules,
    CargoBuildScripts,
    ShellInstallers,
    WorkspaceConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicTier {
    PublicCore,
    PrivateAdvanced,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfidencePolicy {
    HardBan,
    ComboRequired,
    ControlDiffRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerMode {
    FixtureOnly,
    RuntimeProbe,
    BrowserReal,
    QueueFull,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFamily {
    JavaScript,
    Python,
    Rust,
    Go,
    Shell,
    GithubActions,
    Browser,
    Control,
    Workspace,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSourceType {
    GitRepo,
    TarballArchive,
    NpmPackage,
    PypiPackage,
    CargoCrate,
    GoModule,
    BrowserBundle,
    GithubAction,
    ShellInstaller,
    WorkspaceBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionRequirements {
    pub browser_required: bool,
    pub vm_required: bool,
    pub queue_required: bool,
    #[serde(default)]
    pub runner_mode: Option<RunnerMode>,
    #[serde(default)]
    pub probe_command: Option<Vec<String>>,
    #[serde(default)]
    pub browser_script: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimingExpectations {
    pub max_queue_latency_ms: u64,
    pub max_detonation_startup_ms: u64,
    pub max_verdict_completion_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleScenario {
    pub name: String,
    pub detonation: DetonationScenario,
    pub phase: PackageLifecyclePhase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedVerdict {
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedTripwireSet {
    pub required: Vec<TripwireKind>,
    #[serde(default)]
    pub allowed_false_positives: Vec<TripwireKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlExpectations {
    pub require_clean_verdict: bool,
    #[serde(default)]
    pub max_shared_tripwires: usize,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceMinimums {
    pub require_captured_request: bool,
    pub require_quarantine_job: bool,
    pub require_lab_run: bool,
    pub require_evidence_bundle: bool,
    pub require_feed_visibility: bool,
    #[serde(default)]
    pub require_browser_trace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleStep {
    pub step_id: String,
    pub detail: String,
    pub phase: PackageLifecyclePhase,
    #[serde(default)]
    pub process_lineage: Vec<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub network_target: Option<String>,
    #[serde(default)]
    pub network_protocol: Option<String>,
    #[serde(default)]
    pub canary_id: Option<String>,
    #[serde(default)]
    pub tripwire: Option<TripwireKind>,
    #[serde(default)]
    pub severity: Option<DetectionSeverity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattlePack {
    pub pack_id: String,
    pub title: String,
    pub attack_family: AttackFamily,
    pub public_tier: PublicTier,
    pub runtime_family: RuntimeFamily,
    pub artifact_type: ArtifactSourceType,
    pub artifact: ArtifactCoordinate,
    #[serde(default)]
    pub incident_refs: Vec<String>,
    #[serde(default)]
    pub technique_refs: Vec<String>,
    #[serde(default)]
    pub control_pair_id: Option<String>,
    pub confidence_policy: ConfidencePolicy,
    #[serde(default)]
    pub allowed_baseline_signals: Vec<TripwireKind>,
    #[serde(default)]
    pub persona_overrides: Vec<DetonationPersona>,
    pub required_personas: Vec<DetonationPersona>,
    pub required_scenarios: Vec<BattleScenario>,
    pub suite_tags: Vec<BattleSuite>,
    pub execution: ExecutionRequirements,
    pub expected_verdict: ExpectedVerdict,
    pub expected_tripwires: ExpectedTripwireSet,
    pub control_expectations: ControlExpectations,
    pub evidence_minimums: EvidenceMinimums,
    pub timing: TimingExpectations,
    pub files: Vec<String>,
    #[serde(default)]
    pub steps: Vec<BattleStep>,
}

impl BattlePack {
    pub fn validate(&self, base_dir: &Path) -> Result<()> {
        if self.pack_id.trim().is_empty() {
            bail!("pack_id must not be empty");
        }
        if self.required_personas.is_empty() {
            bail!("{} must declare at least one persona", self.pack_id);
        }
        if self.required_scenarios.is_empty() {
            bail!("{} must declare at least one scenario", self.pack_id);
        }
        if self.suite_tags.is_empty() {
            bail!("{} must declare at least one suite tag", self.pack_id);
        }
        if self.execution.browser_required && self.execution.browser_script.is_none() {
            bail!(
                "{} requires a browser_script when browser_required is true",
                self.pack_id
            );
        }
        if self.expected_verdict.verdict == Verdict::Malicious
            && !matches!(self.confidence_policy, ConfidencePolicy::HardBan)
            && self.control_pair_id.is_none()
        {
            bail!(
                "{} malicious non-hard-ban pack must declare a control_pair_id",
                self.pack_id
            );
        }
        if matches!(self.attack_family, AttackFamily::Control)
            && self.expected_verdict.verdict != Verdict::Clean
        {
            bail!("{} control pack must expect a clean verdict", self.pack_id);
        }
        if self.public_tier == PublicTier::PublicCore
            && !matches!(self.attack_family, AttackFamily::Control)
            && (self.incident_refs.is_empty() || self.technique_refs.is_empty())
        {
            bail!(
                "{} public-core malicious/significant pack must declare incident_refs and technique_refs",
                self.pack_id
            );
        }
        if !matches!(self.attack_family, AttackFamily::Control)
            && self.public_tier == PublicTier::PublicCore
            && self.expected_verdict.verdict == Verdict::Malicious
            && self.control_pair_id.is_none()
        {
            bail!(
                "{} public-core malicious pack must declare a control pair",
                self.pack_id
            );
        }
        for file in &self.files {
            let path = base_dir.join(file);
            if !path.exists() {
                bail!(
                    "{} references missing file {}",
                    self.pack_id,
                    path.display()
                );
            }
        }
        if let Some(browser_script) = &self.execution.browser_script {
            let path = base_dir.join(browser_script);
            if !path.exists() {
                bail!(
                    "{} references missing browser script {}",
                    self.pack_id,
                    path.display()
                );
            }
        }

        for required in &self.expected_tripwires.required {
            let covered = self
                .steps
                .iter()
                .any(|step| step.tripwire.as_ref() == Some(required));
            if !covered {
                bail!(
                    "{} expects tripwire {:?} but no step emits it",
                    self.pack_id,
                    required
                );
            }
        }

        for step in &self.steps {
            if let Some(tripwire) = step.tripwire {
                let allowed = self.expected_tripwires.required.contains(&tripwire)
                    || self
                        .expected_tripwires
                        .allowed_false_positives
                        .contains(&tripwire);
                if !allowed {
                    bail!(
                        "{} step {} emits {:?} without declaring it in expectations",
                        self.pack_id,
                        step.step_id,
                        tripwire
                    );
                }
            }
        }

        Ok(())
    }

    pub fn belongs_to_suite(&self, suite: BattleSuite) -> bool {
        match suite {
            BattleSuite::Controls => matches!(self.attack_family, AttackFamily::Control),
            BattleSuite::PublicCore => self.public_tier == PublicTier::PublicCore,
            BattleSuite::GitCore => matches!(self.attack_family, AttackFamily::GitIntegrity),
            BattleSuite::Actions => matches!(self.attack_family, AttackFamily::GithubActions),
            BattleSuite::Go => matches!(self.attack_family, AttackFamily::GoModules),
            BattleSuite::Cargo => matches!(self.attack_family, AttackFamily::CargoBuildScripts),
            BattleSuite::Shell => matches!(self.attack_family, AttackFamily::ShellInstallers),
            BattleSuite::Workspace => {
                matches!(self.attack_family, AttackFamily::WorkspaceConfig)
            }
            _ => self.suite_tags.contains(&suite),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleAssertionOutcome {
    pub verdict_matches: bool,
    pub missing_tripwires: Vec<TripwireKind>,
    pub unexpected_tripwires: Vec<TripwireKind>,
    pub control_pair_valid: bool,
    pub control_notes: Vec<String>,
    pub evidence_complete: bool,
    pub evidence_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleTimingBreakdown {
    pub queue_latency_ms: u128,
    pub detonation_startup_ms: u128,
    pub verdict_completion_ms: u128,
    pub total_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleCorrelation {
    pub captured_request_id: String,
    pub quarantine_job_id: String,
    pub lab_run_id: String,
    pub evidence_bundle_id: String,
    pub feed_visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlComparison {
    pub control_pack_id: Option<String>,
    pub control_verdict: Option<Verdict>,
    pub shared_tripwires: Vec<TripwireKind>,
    pub comparison_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCompleteness {
    pub captured_request: bool,
    pub quarantine_job: bool,
    pub lab_run: bool,
    pub evidence_bundle: bool,
    pub feed_visible: bool,
    pub browser_trace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleRunResult {
    pub pack_id: String,
    pub attack_family: AttackFamily,
    pub public_tier: PublicTier,
    pub ecosystem: String,
    pub verdict: Verdict,
    pub tripwires_seen: Vec<TripwireKind>,
    pub timing: BattleTimingBreakdown,
    pub stdout_summary: String,
    pub stderr_summary: String,
    pub browser_trace_reference: Option<String>,
    pub control_comparison: ControlComparison,
    pub evidence_completeness: EvidenceCompleteness,
    pub assertion: BattleAssertionOutcome,
    pub correlation: BattleCorrelation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageRecord {
    pub attack_family: AttackFamily,
    pub public_tier: PublicTier,
    pub ecosystem: String,
    pub pack_id: String,
    pub verdict: Verdict,
    pub control_pair_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageSummary {
    pub malicious_detection_rate: String,
    pub control_pass_rate: String,
    pub unsupported_gaps: Vec<String>,
    pub matrix: Vec<CoverageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BattleSuiteReport {
    pub suite: BattleSuite,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<BattleRunResult>,
    pub coverage: CoverageSummary,
}

pub fn default_pack_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("zitpit-battle-packs")
        .join("packs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zitpit_core::{Ecosystem, SelectorKind};

    #[test]
    fn validation_requires_expected_tripwires_to_be_backed_by_steps() {
        let pack = BattlePack {
            pack_id: "bad-pack".to_string(),
            title: "Bad".to_string(),
            attack_family: AttackFamily::GitIntegrity,
            public_tier: PublicTier::PublicCore,
            runtime_family: RuntimeFamily::Shell,
            artifact_type: ArtifactSourceType::ShellInstaller,
            artifact: ArtifactCoordinate {
                ecosystem: Ecosystem::Archive,
                source: "https://example.invalid/evil.sh".to_string(),
                requested_selector: "latest".to_string(),
                selector_kind: SelectorKind::Url,
            },
            incident_refs: vec!["public/example".to_string()],
            technique_refs: vec!["tripwire-check".to_string()],
            control_pair_id: Some("control-benign-git-release".to_string()),
            confidence_policy: ConfidencePolicy::HardBan,
            allowed_baseline_signals: vec![],
            persona_overrides: vec![],
            required_personas: vec![DetonationPersona::DeveloperWorkstation],
            required_scenarios: vec![BattleScenario {
                name: "install".to_string(),
                detonation: DetonationScenario::InstallBuild,
                phase: PackageLifecyclePhase::Install,
            }],
            suite_tags: vec![BattleSuite::Fast],
            execution: ExecutionRequirements {
                browser_required: false,
                vm_required: false,
                queue_required: true,
                runner_mode: Some(RunnerMode::FixtureOnly),
                probe_command: None,
                browser_script: None,
            },
            expected_verdict: ExpectedVerdict {
                verdict: Verdict::Malicious,
            },
            expected_tripwires: ExpectedTripwireSet {
                required: vec![TripwireKind::PortScan],
                allowed_false_positives: vec![],
            },
            control_expectations: ControlExpectations {
                require_clean_verdict: true,
                max_shared_tripwires: 0,
                notes: vec![],
            },
            evidence_minimums: EvidenceMinimums {
                require_captured_request: true,
                require_quarantine_job: true,
                require_lab_run: true,
                require_evidence_bundle: true,
                require_feed_visibility: true,
                require_browser_trace: false,
            },
            timing: TimingExpectations {
                max_queue_latency_ms: 2000,
                max_detonation_startup_ms: 2000,
                max_verdict_completion_ms: 2000,
            },
            files: vec![],
            steps: vec![],
        };

        let error = pack.validate(Path::new(".")).expect_err("validation");
        assert!(error.to_string().contains("expects tripwire"));
    }
}
