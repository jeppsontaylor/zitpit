use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Git,
    Npm,
    Pypi,
    Cargo,
    Go,
    Oci,
    Archive,
    GenericWeb,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectorKind {
    ExactVersion,
    ExactCommit,
    Tag,
    Branch,
    SemverRange,
    Floating,
    Url,
}

impl SelectorKind {
    pub fn is_exact(self) -> bool {
        matches!(self, Self::ExactVersion | Self::ExactCommit)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficLane {
    Browse,
    CodeIntake,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CodeIntent {
    GitRemote,
    Registry,
    OciPull,
    ReleaseArchive,
    SourceArchive,
    InstallScript,
    UnknownCodeHost,
    Browsing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Approved,
    Pending,
    Blocked,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAction {
    Allow,
    Fallback,
    Pending,
    Blocked,
    Tunnel,
    Bypass,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientVisibleOutcome {
    Success,
    TemporaryFailure,
    Blocked,
    UpstreamError,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TripwireKind {
    HoneySecretAccess,
    MetadataProbe,
    Downloader,
    ShellSpawn,
    SecretScrape,
    Persistence,
    ContainerSocketTouch,
    ArchiveStaging,
    ExfilAttempt,
    NetworkConnection,
    PortScan,
    BrowserTokenScrape,
    EnvMassEnumeration,
    InternalGitCredentialAccess,
    PackageCredentialAccess,
    KubeTokenEnumeration,
    SshAgentTouch,
    GitHookWrite,
    ProcessInjectionAttempt,
    SandboxFingerprinting,
    SystemReconBurst,
    GitRefDrift,
    ReleaseArtifactMismatch,
    SubmoduleRewrite,
    RepoIdentityDrift,
    HotCacheHit,
    WorkspaceConfigLoad,
    AgentHookWrite,
    WorkspaceSecretScrape,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetonationPersona {
    DeveloperWorkstation,
    CiRunner,
    ContainerBuildNode,
    CloudOperator,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetonationScenario {
    InstallBuild,
    ImportLoad,
    CliSmoke,
    WarmCache,
    ColdCache,
    DelayedRerun,
    BaitedVsSterile,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageLifecyclePhase {
    Fetch,
    Install,
    Build,
    Import,
    Cli,
    Browser,
    DelayedRerun,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectorHint {
    pub requested: String,
    pub kind: SelectorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestObservation {
    pub request_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub method: String,
    pub user_agent: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub selector_hint: Option<SelectorHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Classification {
    pub lane: TrafficLane,
    pub ecosystem: Option<Ecosystem>,
    pub intent: CodeIntent,
    pub reason: String,
    pub confidence: u8,
    pub requires_quarantine: bool,
    pub host_family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactCoordinate {
    pub ecosystem: Ecosystem,
    pub source: String,
    pub requested_selector: String,
    pub selector_kind: SelectorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FallbackTarget {
    pub selector: String,
    pub resolved_target: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRecord {
    pub ecosystem: Ecosystem,
    pub source: String,
    pub requested_selector: String,
    pub selector_kind: SelectorKind,
    pub resolved_target: String,
    pub raw_digest_sha256: String,
    pub normalized_digest_sha256: String,
    pub status: ApprovalStatus,
    pub first_seen_at: DateTime<Utc>,
    pub hold_until: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub fallback: Option<FallbackTarget>,
    pub detector_refs: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

impl ManifestRecord {
    pub fn coordinate(&self) -> ArtifactCoordinate {
        ArtifactCoordinate {
            ecosystem: self.ecosystem,
            source: self.source.clone(),
            requested_selector: self.requested_selector.clone(),
            selector_kind: self.selector_kind,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyDecision {
    pub action: ProxyAction,
    pub reason: String,
    pub classification: Classification,
    pub manifest_status: Option<ApprovalStatus>,
    pub fallback: Option<FallbackTarget>,
    pub hold_until: Option<DateTime<Utc>>,
    pub matched_record: Option<ManifestRecord>,
    pub audit_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRequest {
    pub observation: RequestObservation,
    pub coordinate: Option<ArtifactCoordinate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    pub hold_duration_hours: i64,
    pub enabled_ecosystems: Vec<Ecosystem>,
    pub allow_browse_lane: bool,
    pub log_all_https: bool,
    pub proxy_port: u16,
    pub admin_port: u16,
    pub capture_http_port: u16,
    pub transparent_capture: bool,
    pub bypass_hosts: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            hold_duration_hours: 14 * 24,
            enabled_ecosystems: vec![
                Ecosystem::Git,
                Ecosystem::Npm,
                Ecosystem::Pypi,
                Ecosystem::Cargo,
                Ecosystem::Go,
                Ecosystem::Oci,
                Ecosystem::Archive,
            ],
            allow_browse_lane: true,
            log_all_https: true,
            proxy_port: 3004,
            admin_port: 3000,
            capture_http_port: 3005,
            transparent_capture: true,
            bypass_hosts: vec![
                "control.zitpit.internal".to_string(),
                "updates.zitpit.internal".to_string(),
                "breakglass.zitpit.internal".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceEvent {
    pub timestamp: DateTime<Utc>,
    pub kind: TripwireKind,
    pub subject: String,
    pub detail: String,
    pub severity: DetectionSeverity,
    #[serde(default)]
    pub phase: Option<PackageLifecyclePhase>,
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
    pub sinkhole_transcript_sha256: Option<String>,
    #[serde(default)]
    pub scenario_step: Option<String>,
    #[serde(default)]
    pub canary_id: Option<String>,
    #[serde(default)]
    pub attack_family_tag: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyTraceKind {
    Received,
    Classified,
    CacheHit,
    HotCacheHit,
    FetchStarted,
    FetchCompleted,
    HashStarted,
    HashCompleted,
    ManifestChecked,
    QuarantineCreated,
    LabScheduled,
    RoutedToGitAdapter,
    RoutedUpstream,
    Blocked,
    Pending,
    ResponseSent,
    Completed,
    UpstreamError,
    TunnelAccepted,
    TunnelClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyTraceEvent {
    pub at: DateTime<Utc>,
    pub kind: ProxyTraceKind,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyTrace {
    pub received_at: DateTime<Utc>,
    pub decision_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub peer_addr: Option<String>,
    pub local_addr: Option<String>,
    pub events: Vec<ProxyTraceEvent>,
}

impl ProxyTrace {
    pub fn new(
        peer_addr: Option<String>,
        local_addr: Option<String>,
        received_at: DateTime<Utc>,
    ) -> Self {
        Self {
            received_at,
            decision_at: None,
            completed_at: None,
            peer_addr,
            local_addr,
            events: vec![ProxyTraceEvent {
                at: received_at,
                kind: ProxyTraceKind::Received,
                detail: "request accepted by proxy".to_string(),
            }],
        }
    }

    pub fn with_event(mut self, kind: ProxyTraceKind, detail: impl Into<String>) -> Self {
        self.events.push(ProxyTraceEvent {
            at: Utc::now(),
            kind,
            detail: detail.into(),
        });
        self
    }

    pub fn with_decision(mut self, detail: impl Into<String>) -> Self {
        let at = Utc::now();
        self.decision_at = Some(at);
        self.events.push(ProxyTraceEvent {
            at,
            kind: ProxyTraceKind::Classified,
            detail: detail.into(),
        });
        self
    }

    pub fn with_completion(mut self, detail: impl Into<String>) -> Self {
        let at = Utc::now();
        self.completed_at = Some(at);
        self.events.push(ProxyTraceEvent {
            at,
            kind: ProxyTraceKind::Completed,
            detail: detail.into(),
        });
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub artifact: ArtifactCoordinate,
    pub persona: DetonationPersona,
    pub scenario: DetonationScenario,
    pub started_at: DateTime<Utc>,
    pub verdict: Verdict,
    pub tripwires: Vec<TripwireKind>,
    pub events: Vec<EvidenceEvent>,
    pub replay_recipe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetonationPlan {
    pub artifact: ArtifactCoordinate,
    pub personas: Vec<DetonationPersona>,
    pub scenarios: Vec<DetonationScenario>,
    pub decoys: Vec<String>,
    pub sinkholes: Vec<String>,
    pub objectives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HourlyFeedRecord {
    pub artifact: ArtifactCoordinate,
    pub status: ApprovalStatus,
    pub first_seen_at: DateTime<Utc>,
    pub confidence: DetectionSeverity,
    pub trigger_category: Option<TripwireKind>,
    pub recommended_action: String,
    pub approved_fallback: Option<FallbackTarget>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheDomain {
    Approved,
    Quarantine,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Pending,
    ReadyForAnalysis,
    Analyzing,
    Approved,
    Blocked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LabRunStatus {
    Planned,
    Running,
    Passed,
    Failed,
    Blocked,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactKey {
    pub ecosystem: Ecosystem,
    pub source: String,
    pub requested_selector: String,
    pub selector_kind: SelectorKind,
}

impl From<ArtifactCoordinate> for ArtifactKey {
    fn from(value: ArtifactCoordinate) -> Self {
        Self {
            ecosystem: value.ecosystem,
            source: value.source,
            requested_selector: value.requested_selector,
            selector_kind: value.selector_kind,
        }
    }
}

impl From<&ArtifactCoordinate> for ArtifactKey {
    fn from(value: &ArtifactCoordinate) -> Self {
        Self {
            ecosystem: value.ecosystem,
            source: value.source.clone(),
            requested_selector: value.requested_selector.clone(),
            selector_kind: value.selector_kind,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedArtifact {
    pub immutable_target: String,
    pub raw_digest_sha256: String,
    pub normalized_digest_sha256: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub artifact_key: ArtifactKey,
    pub domain: CacheDomain,
    pub storage_path: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: Option<u64>,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineJob {
    pub job_id: Uuid,
    pub artifact_key: ArtifactKey,
    pub status: QuarantineStatus,
    pub created_at: DateTime<Utc>,
    pub hold_until: DateTime<Utc>,
    pub last_error: Option<String>,
    pub cache_entry: Option<CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub evidence_id: Uuid,
    pub artifact_key: ArtifactKey,
    pub run_id: Option<Uuid>,
    pub summary: EvidenceRecord,
    pub sinkhole_transcript: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabRun {
    pub run_id: Uuid,
    pub artifact_key: ArtifactKey,
    pub status: LabRunStatus,
    pub planned_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub personas: Vec<DetonationPersona>,
    pub scenarios: Vec<DetonationScenario>,
    pub firecracker_config_path: Option<String>,
    pub firecracker_api_socket: Option<String>,
    pub tap_device: Option<String>,
    pub command_preview: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedRequest {
    pub request_id: Uuid,
    pub observation: RequestObservation,
    pub classification: Classification,
    pub proxy_action: ProxyAction,
    pub status_code: Option<u16>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub stored_body: bool,
    pub client_outcome: Option<ClientVisibleOutcome>,
    pub decision_reason: String,
    pub artifact_key: Option<ArtifactKey>,
    pub trace: ProxyTrace,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSession {
    pub node_id: String,
    pub user_label: String,
    pub hostname: String,
    pub policy_version: String,
    pub ca_version: String,
    pub transparent_capture: bool,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub config: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeBootstrapBundle {
    pub node_id: String,
    pub policy: PolicySnapshot,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub nftables_ruleset: String,
    pub install_script: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyTunnelDecision {
    pub authority: String,
    pub action: ProxyAction,
    pub classification: Classification,
    pub reason: String,
    pub should_intercept: bool,
}

pub fn sample_policy() -> PolicyConfig {
    PolicyConfig::default()
}
