use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use uuid::Uuid;
use zitpit_battle_types::{
    AttackFamily, BattleAssertionOutcome, BattleCorrelation, BattlePack, BattleRunResult,
    BattleSuite, BattleSuiteReport, BattleTimingBreakdown, ConfidencePolicy, ControlComparison,
    CoverageRecord, CoverageSummary, EvidenceCompleteness, NodeDecisionExpectation,
    default_pack_root,
};
use zitpit_config::RuntimePaths;
use zitpit_core::{
    ApprovalStatus, ArtifactKey, CacheDomain, CacheEntry, CapturedRequest, Classification,
    ClientVisibleOutcome, CodeIntent, DetectionSeverity, DetonationPersona,
    FirecrackerOrchestrator, HourlyFeedRecord, LabRunStatus, MemoryStore, ProxyAction, ProxyTrace,
    ProxyTraceKind, QuarantineJob, QuarantineStatus, RequestObservation, SelectorHint, StoreHandle,
    TrafficLane, TripwireEvaluator, Verdict, manifest::digest_for,
};

#[derive(Debug, Clone)]
pub struct LoadedBattlePack {
    pub root_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub pack: BattlePack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMode {
    SkipIfUnavailable,
    Require,
}

#[derive(Debug, Clone)]
pub struct BattleRunner {
    pack_root: PathBuf,
}

impl Default for BattleRunner {
    fn default() -> Self {
        Self::new(default_pack_root())
    }
}

impl BattleRunner {
    pub fn new(pack_root: PathBuf) -> Self {
        Self { pack_root }
    }

    pub fn discover_packs(&self) -> Result<Vec<LoadedBattlePack>> {
        let mut manifests = Vec::new();
        collect_pack_manifests(&self.pack_root, &mut manifests)?;
        manifests.sort();
        let mut packs = Vec::new();
        for manifest_path in manifests {
            let bytes = fs::read(&manifest_path)
                .with_context(|| format!("read pack {}", manifest_path.display()))?;
            let pack: BattlePack = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse pack {}", manifest_path.display()))?;
            let root_dir = manifest_path
                .parent()
                .context("pack manifest parent")?
                .to_path_buf();
            packs.push(LoadedBattlePack {
                root_dir,
                manifest_path,
                pack,
            });
        }
        Ok(packs)
    }

    pub fn lint(&self) -> Result<Vec<LoadedBattlePack>> {
        let packs = self.discover_packs()?;
        for pack in &packs {
            pack.pack
                .validate(&pack.root_dir)
                .with_context(|| format!("lint {}", pack.manifest_path.display()))?;
        }
        Ok(packs)
    }

    pub async fn run_suite(
        &self,
        suite: BattleSuite,
        browser_mode: BrowserMode,
    ) -> Result<BattleSuiteReport> {
        let all_packs = self.lint()?;
        let lookup_packs = all_packs.clone();
        let mut results = Vec::new();
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;
        let selected = all_packs
            .into_iter()
            .filter(|pack| pack.pack.belongs_to_suite(suite))
            .collect::<Vec<_>>();

        for pack in &selected {
            if pack.pack.execution.browser_required && !browser_available() {
                match browser_mode {
                    BrowserMode::SkipIfUnavailable => {
                        skipped += 1;
                        continue;
                    }
                    BrowserMode::Require => {
                        bail!(
                            "browser suite requires Playwright + Chromium, but they were not found"
                        );
                    }
                }
            }

            let result = self.run_pack(pack, &lookup_packs).await?;
            if result.assertion.verdict_matches
                && result.assertion.node_decision_matches
                && result.assertion.missing_tripwires.is_empty()
                && result.assertion.unexpected_tripwires.is_empty()
                && result.assertion.control_pair_valid
                && result.assertion.evidence_complete
            {
                passed += 1;
            } else {
                failed += 1;
            }
            results.push(result);
        }

        Ok(BattleSuiteReport {
            suite,
            total: passed + failed + skipped,
            passed,
            failed,
            skipped,
            coverage: build_coverage_summary(&results),
            results,
        })
    }

    pub async fn run_pack(
        &self,
        pack: &LoadedBattlePack,
        all_packs: &[LoadedBattlePack],
    ) -> Result<BattleRunResult> {
        let total_start = Instant::now();
        let tempdir = tempfile::Builder::new()
            .prefix("zitpit-battle")
            .tempdir()
            .context("create battle tempdir")?;
        let runtime_paths = RuntimePaths::new(tempdir.path().join("state"));
        runtime_paths.ensure_dirs()?;

        let store = StoreHandle::from_memory(MemoryStore::seeded().await);
        let orchestrator = FirecrackerOrchestrator::with_paths(runtime_paths);

        let request_id = Uuid::new_v4();
        let node_decision = pack
            .pack
            .expected_node_decision
            .unwrap_or(NodeDecisionExpectation::Allowed);
        let trace = ProxyTrace::new(
            Some("127.0.0.1:55000".to_string()),
            Some("127.0.0.1:3004".to_string()),
            Utc::now(),
        )
        .with_decision("battle pack submitted into quarantine queue")
        .with_event(
            ProxyTraceKind::QuarantineCreated,
            "battle queue created quarantine job",
        )
        .with_event(
            ProxyTraceKind::LabScheduled,
            "battle queue scheduled lab run",
        );
        let observation = RequestObservation {
            request_id,
            observed_at: Utc::now(),
            scheme: "https".to_string(),
            authority: pack
                .pack
                .artifact
                .source
                .split("://")
                .nth(1)
                .unwrap_or(pack.pack.artifact.source.as_str())
                .split('/')
                .next()
                .unwrap_or_default()
                .to_string(),
            path: url_path(&pack.pack.artifact.source),
            method: "BATTLE".to_string(),
            user_agent: Some(format!("zitpit-battle/{}", pack.pack.pack_id)),
            headers: BTreeMap::new(),
            selector_hint: Some(SelectorHint {
                requested: pack.pack.artifact.requested_selector.clone(),
                kind: pack.pack.artifact.selector_kind,
            }),
        };
        let classification = Classification {
            lane: TrafficLane::CodeIntake,
            ecosystem: Some(pack.pack.artifact.ecosystem),
            intent: CodeIntent::UnknownCodeHost,
            reason: "battle pack queued for quarantine".to_string(),
            confidence: 100,
            requires_quarantine: true,
            host_family: Some(observation.authority.clone()),
        };
        let artifact_key = ArtifactKey::from(&pack.pack.artifact);
        store
            .0
            .record_captured_request(CapturedRequest {
                request_id,
                observation,
                classification,
                proxy_action: match node_decision {
                    NodeDecisionExpectation::Allowed => ProxyAction::Pending,
                    NodeDecisionExpectation::BlockedPreExec => ProxyAction::Blocked,
                    NodeDecisionExpectation::DeniedBeforeSend => ProxyAction::Blocked,
                    NodeDecisionExpectation::BrokerRequired => ProxyAction::Blocked,
                    NodeDecisionExpectation::UnsupportedDenied => ProxyAction::Blocked,
                },
                status_code: Some(match node_decision {
                    NodeDecisionExpectation::Allowed => 202,
                    NodeDecisionExpectation::BlockedPreExec => 403,
                    NodeDecisionExpectation::DeniedBeforeSend => 403,
                    NodeDecisionExpectation::BrokerRequired => 403,
                    NodeDecisionExpectation::UnsupportedDenied => 501,
                }),
                bytes_in: None,
                bytes_out: None,
                stored_body: true,
                client_outcome: Some(match node_decision {
                    NodeDecisionExpectation::Allowed => ClientVisibleOutcome::TemporaryFailure,
                    NodeDecisionExpectation::BlockedPreExec
                    | NodeDecisionExpectation::DeniedBeforeSend
                    | NodeDecisionExpectation::BrokerRequired
                    | NodeDecisionExpectation::UnsupportedDenied => ClientVisibleOutcome::Blocked,
                }),
                decision_reason: match node_decision {
                    NodeDecisionExpectation::Allowed => {
                        "battle pack held for quarantine and lab evaluation".to_string()
                    }
                    NodeDecisionExpectation::BlockedPreExec => {
                        "battle pack blocked at the node before execution".to_string()
                    }
                    NodeDecisionExpectation::DeniedBeforeSend => {
                        "battle pack was denied before bytes left the governed egress path"
                            .to_string()
                    }
                    NodeDecisionExpectation::BrokerRequired => {
                        "battle pack requires a brokered action path".to_string()
                    }
                    NodeDecisionExpectation::UnsupportedDenied => {
                        "battle pack used an unsupported path and was denied".to_string()
                    }
                },
                artifact_key: Some(artifact_key.clone()),
                egress_decision: None,
                trace,
            })
            .await?;

        let (job, queue_latency_ms, lab_run, detonation_startup_ms) =
            if node_decision == NodeDecisionExpectation::Allowed {
                let queue_start = Instant::now();
                let cache_entry = CacheEntry {
                    artifact_key: artifact_key.clone(),
                    domain: CacheDomain::Quarantine,
                    storage_path: pack.root_dir.display().to_string(),
                    created_at: Utc::now(),
                    size_bytes: Some(total_file_bytes(&pack.root_dir, &pack.pack.files)?),
                    digest_sha256: pack_digest(pack)?,
                };
                store.0.put_cache_entry(cache_entry.clone()).await?;
                let job = QuarantineJob {
                    job_id: Uuid::new_v4(),
                    artifact_key: artifact_key.clone(),
                    status: QuarantineStatus::Analyzing,
                    created_at: Utc::now(),
                    hold_until: Utc::now() + chrono::TimeDelta::minutes(5),
                    last_error: None,
                    cache_entry: Some(cache_entry),
                };
                let job = store.0.upsert_quarantine_job(job).await?;
                let queue_latency_ms = queue_start.elapsed().as_millis();

                let detonation_start = Instant::now();
                let lab_run = orchestrator.plan_run(pack.pack.artifact.clone());
                let lab_run = store.0.upsert_lab_run(lab_run).await?;
                let detonation_startup_ms = detonation_start.elapsed().as_millis();
                (
                    Some(job),
                    queue_latency_ms,
                    Some(lab_run),
                    detonation_startup_ms,
                )
            } else {
                (None, 0, None, 0)
            };

        let (stdout_summary, stderr_summary, browser_trace_reference) =
            run_pack_probe(pack, tempdir.path(), browser_available())?;

        let verdict_start = Instant::now();
        let persona = pack
            .pack
            .required_personas
            .first()
            .copied()
            .unwrap_or(DetonationPersona::DeveloperWorkstation);
        let scenario = pack
            .pack
            .required_scenarios
            .first()
            .map(|scenario| scenario.detonation)
            .unwrap_or(zitpit_core::DetonationScenario::InstallBuild);
        let events = pack
            .pack
            .steps
            .iter()
            .filter_map(|step| {
                Some(zitpit_core::EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: step.tripwire?,
                    subject: step
                        .file_path
                        .clone()
                        .or_else(|| step.network_target.clone())
                        .unwrap_or_else(|| step.step_id.clone()),
                    detail: step.detail.clone(),
                    severity: step.severity.unwrap_or(DetectionSeverity::Medium),
                    phase: Some(step.phase),
                    process_lineage: step.process_lineage.clone(),
                    command: step.command.clone(),
                    file_path: step.file_path.clone(),
                    network_target: step.network_target.clone(),
                    network_protocol: step.network_protocol.clone(),
                    sinkhole_transcript_sha256: step
                        .network_target
                        .as_ref()
                        .map(|target| digest_for(target)),
                    scenario_step: Some(step.step_id.clone()),
                    canary_id: step.canary_id.clone(),
                    attack_family_tag: Some(format!("{:?}", pack.pack.attack_family)),
                })
            })
            .collect::<Vec<_>>();
        let evidence =
            TripwireEvaluator::evaluate(pack.pack.artifact.clone(), persona, scenario, events);
        let evidence_id = Uuid::new_v4();
        store
            .0
            .record_evidence_bundle(zitpit_core::EvidenceBundle {
                evidence_id,
                artifact_key: artifact_key.clone(),
                run_id: lab_run.as_ref().map(|run| run.run_id),
                sinkhole_transcript: pack
                    .pack
                    .steps
                    .iter()
                    .filter_map(|step| {
                        step.network_target
                            .as_ref()
                            .map(|target| format!("{} -> {}", step.step_id, target))
                    })
                    .collect(),
                summary: evidence.clone(),
            })
            .await?;
        let verdict_completion_ms = verdict_start.elapsed().as_millis();

        if let Some(job) = &job {
            let final_quarantine_status = match evidence.verdict {
                Verdict::Clean => QuarantineStatus::Approved,
                Verdict::Suspicious | Verdict::Malicious => QuarantineStatus::Blocked,
            };
            store
                .0
                .upsert_quarantine_job(QuarantineJob {
                    status: final_quarantine_status,
                    ..job.clone()
                })
                .await?;
        }
        if let Some(lab_run) = &lab_run {
            store
                .0
                .upsert_lab_run(zitpit_core::LabRun {
                    status: match evidence.verdict {
                        Verdict::Clean => LabRunStatus::Passed,
                        Verdict::Suspicious | Verdict::Malicious => LabRunStatus::Blocked,
                    },
                    finished_at: Some(Utc::now()),
                    notes: {
                        let mut notes = lab_run.notes.clone();
                        notes.push(format!("battle pack {}", pack.pack.pack_id));
                        notes
                    },
                    ..lab_run.clone()
                })
                .await?;
        }
        store
            .0
            .put_feed_record(HourlyFeedRecord {
                artifact: pack.pack.artifact.clone(),
                status: match evidence.verdict {
                    Verdict::Clean => ApprovalStatus::Approved,
                    Verdict::Suspicious | Verdict::Malicious => ApprovalStatus::Blocked,
                },
                first_seen_at: Utc::now(),
                confidence: highest_severity(&pack.pack),
                trigger_category: evidence.tripwires.first().copied(),
                recommended_action: match evidence.verdict {
                    Verdict::Clean => "approve control pack".to_string(),
                    Verdict::Suspicious => "inspect suspicious battle pack".to_string(),
                    Verdict::Malicious => "block malicious battle pack".to_string(),
                },
                approved_fallback: None,
            })
            .await?;

        let feed_visible = store
            .0
            .list_feed_records()
            .await?
            .iter()
            .any(|feed| feed.artifact.source == pack.pack.artifact.source);
        let control_comparison = self
            .evaluate_control_pair(pack, all_packs, &evidence.tripwires)
            .await?;
        let evidence_completeness = EvidenceCompleteness {
            captured_request: true,
            quarantine_job: job.is_some(),
            lab_run: lab_run.is_some(),
            evidence_bundle: true,
            feed_visible,
            browser_trace: !pack.pack.evidence_minimums.require_browser_trace
                || browser_trace_reference.is_some(),
        };
        let assertion = assert_pack_expectations(
            &pack.pack,
            evidence.verdict,
            node_decision,
            &evidence.tripwires,
            &control_comparison,
            &evidence_completeness,
        );
        let total_ms = total_start.elapsed().as_millis();

        Ok(BattleRunResult {
            pack_id: pack.pack.pack_id.clone(),
            attack_family: pack.pack.attack_family,
            public_tier: pack.pack.public_tier,
            ecosystem: format!("{:?}", pack.pack.artifact.ecosystem),
            verdict: evidence.verdict,
            node_decision,
            tripwires_seen: evidence.tripwires,
            timing: BattleTimingBreakdown {
                queue_latency_ms,
                detonation_startup_ms,
                verdict_completion_ms,
                total_ms,
            },
            stdout_summary,
            stderr_summary,
            browser_trace_reference,
            control_comparison,
            evidence_completeness,
            assertion,
            correlation: BattleCorrelation {
                captured_request_id: request_id.to_string(),
                quarantine_job_id: job
                    .as_ref()
                    .map(|job| job.job_id.to_string())
                    .unwrap_or_default(),
                lab_run_id: lab_run
                    .as_ref()
                    .map(|run| run.run_id.to_string())
                    .unwrap_or_default(),
                evidence_bundle_id: evidence_id.to_string(),
                feed_visible,
            },
        })
    }

    async fn evaluate_control_pair(
        &self,
        pack: &LoadedBattlePack,
        all_packs: &[LoadedBattlePack],
        tripwires_seen: &[zitpit_core::TripwireKind],
    ) -> Result<ControlComparison> {
        let Some(control_pair_id) = &pack.pack.control_pair_id else {
            return Ok(ControlComparison {
                control_pack_id: None,
                control_verdict: None,
                shared_tripwires: vec![],
                comparison_notes: vec!["no control pair declared".to_string()],
            });
        };

        let control_pack = all_packs
            .iter()
            .find(|candidate| &candidate.pack.pack_id == control_pair_id)
            .with_context(|| format!("missing control pair {control_pair_id}"))?;
        let control_result = self.run_control_pack(control_pack).await?;
        let shared_tripwires = control_result
            .tripwires_seen
            .iter()
            .copied()
            .filter(|tripwire| tripwires_seen.contains(tripwire))
            .collect::<Vec<_>>();
        let mut comparison_notes = Vec::new();
        if control_result.verdict != Verdict::Clean {
            comparison_notes.push(format!(
                "control {} produced {:?}",
                control_pack.pack.pack_id, control_result.verdict
            ));
        }
        if shared_tripwires.len() > pack.pack.control_expectations.max_shared_tripwires {
            comparison_notes.push(format!(
                "control shared {} tripwires, max {}",
                shared_tripwires.len(),
                pack.pack.control_expectations.max_shared_tripwires
            ));
        }
        Ok(ControlComparison {
            control_pack_id: Some(control_pack.pack.pack_id.clone()),
            control_verdict: Some(control_result.verdict),
            shared_tripwires,
            comparison_notes,
        })
    }

    async fn run_control_pack(&self, control_pack: &LoadedBattlePack) -> Result<BattleRunResult> {
        let tempdir = tempfile::Builder::new()
            .prefix("zitpit-control")
            .tempdir()
            .context("create control tempdir")?;
        let runtime_paths = RuntimePaths::new(tempdir.path().join("state"));
        runtime_paths.ensure_dirs()?;
        let store = StoreHandle::from_memory(MemoryStore::seeded().await);
        let orchestrator = FirecrackerOrchestrator::with_paths(runtime_paths);
        let _ = orchestrator;

        let evidence = TripwireEvaluator::evaluate(
            control_pack.pack.artifact.clone(),
            control_pack.pack.required_personas[0],
            control_pack.pack.required_scenarios[0].detonation,
            control_pack
                .pack
                .steps
                .iter()
                .filter_map(|step| {
                    Some(zitpit_core::EvidenceEvent {
                        timestamp: Utc::now(),
                        kind: step.tripwire?,
                        subject: step
                            .file_path
                            .clone()
                            .or_else(|| step.network_target.clone())
                            .unwrap_or_else(|| step.step_id.clone()),
                        detail: step.detail.clone(),
                        severity: step.severity.unwrap_or(DetectionSeverity::Low),
                        phase: Some(step.phase),
                        process_lineage: step.process_lineage.clone(),
                        command: step.command.clone(),
                        file_path: step.file_path.clone(),
                        network_target: step.network_target.clone(),
                        network_protocol: step.network_protocol.clone(),
                        sinkhole_transcript_sha256: step
                            .network_target
                            .as_ref()
                            .map(|target| digest_for(target)),
                        scenario_step: Some(step.step_id.clone()),
                        canary_id: step.canary_id.clone(),
                        attack_family_tag: Some(format!("{:?}", control_pack.pack.attack_family)),
                    })
                })
                .collect(),
        );

        let artifact_key = ArtifactKey::from(&control_pack.pack.artifact);
        let evidence_id = Uuid::new_v4();
        store
            .0
            .record_evidence_bundle(zitpit_core::EvidenceBundle {
                evidence_id,
                artifact_key: artifact_key.clone(),
                run_id: None,
                summary: evidence.clone(),
                sinkhole_transcript: vec![],
            })
            .await?;

        Ok(BattleRunResult {
            pack_id: control_pack.pack.pack_id.clone(),
            attack_family: control_pack.pack.attack_family,
            public_tier: control_pack.pack.public_tier,
            ecosystem: format!("{:?}", control_pack.pack.artifact.ecosystem),
            verdict: evidence.verdict,
            node_decision: NodeDecisionExpectation::Allowed,
            tripwires_seen: evidence.tripwires,
            timing: BattleTimingBreakdown {
                queue_latency_ms: 0,
                detonation_startup_ms: 0,
                verdict_completion_ms: 0,
                total_ms: 0,
            },
            stdout_summary: String::new(),
            stderr_summary: String::new(),
            browser_trace_reference: None,
            control_comparison: ControlComparison {
                control_pack_id: None,
                control_verdict: None,
                shared_tripwires: vec![],
                comparison_notes: vec![],
            },
            evidence_completeness: EvidenceCompleteness {
                captured_request: true,
                quarantine_job: true,
                lab_run: true,
                evidence_bundle: true,
                feed_visible: true,
                browser_trace: !control_pack.pack.evidence_minimums.require_browser_trace,
            },
            assertion: BattleAssertionOutcome {
                verdict_matches: evidence.verdict == control_pack.pack.expected_verdict.verdict,
                node_decision_matches: true,
                missing_tripwires: vec![],
                unexpected_tripwires: vec![],
                control_pair_valid: true,
                control_notes: vec![],
                evidence_complete: true,
                evidence_notes: vec![],
            },
            correlation: BattleCorrelation {
                captured_request_id: Uuid::new_v4().to_string(),
                quarantine_job_id: Uuid::new_v4().to_string(),
                lab_run_id: Uuid::new_v4().to_string(),
                evidence_bundle_id: evidence_id.to_string(),
                feed_visible: true,
            },
        })
    }
}

fn highest_severity(pack: &BattlePack) -> DetectionSeverity {
    pack.steps
        .iter()
        .filter_map(|step| step.severity)
        .max()
        .unwrap_or(DetectionSeverity::Low)
}

fn assert_pack_expectations(
    pack: &BattlePack,
    verdict: Verdict,
    node_decision: NodeDecisionExpectation,
    tripwires: &[zitpit_core::TripwireKind],
    control_comparison: &ControlComparison,
    evidence_completeness: &EvidenceCompleteness,
) -> BattleAssertionOutcome {
    let mut tripwires_seen = tripwires.to_vec();
    tripwires_seen.sort();
    tripwires_seen.dedup();

    let missing_tripwires = pack
        .expected_tripwires
        .required
        .iter()
        .copied()
        .filter(|tripwire| !tripwires_seen.contains(tripwire))
        .collect::<Vec<_>>();

    let unexpected_tripwires = tripwires_seen
        .iter()
        .copied()
        .filter(|tripwire| {
            !pack.expected_tripwires.required.contains(tripwire)
                && !pack
                    .expected_tripwires
                    .allowed_false_positives
                    .contains(tripwire)
        })
        .collect::<Vec<_>>();

    let mut control_notes = control_comparison.comparison_notes.clone();
    let control_pair_valid = if pack.control_pair_id.is_none() {
        true
    } else {
        let clean_ok = !pack.control_expectations.require_clean_verdict
            || control_comparison.control_verdict == Some(Verdict::Clean);
        let shared_ok = control_comparison.shared_tripwires.len()
            <= pack.control_expectations.max_shared_tripwires;
        if !clean_ok {
            control_notes.push("control verdict was not clean".to_string());
        }
        if !shared_ok {
            control_notes.push("control shared too many tripwires".to_string());
        }
        clean_ok && shared_ok
    };

    let mut evidence_notes = Vec::new();
    let evidence_complete =
        evidence_completeness.captured_request || !pack.evidence_minimums.require_captured_request;
    let evidence_complete = evidence_complete
        && (evidence_completeness.quarantine_job || !pack.evidence_minimums.require_quarantine_job);
    let evidence_complete = evidence_complete
        && (evidence_completeness.lab_run || !pack.evidence_minimums.require_lab_run);
    let evidence_complete = evidence_complete
        && (evidence_completeness.evidence_bundle
            || !pack.evidence_minimums.require_evidence_bundle);
    let evidence_complete = evidence_complete
        && (evidence_completeness.feed_visible || !pack.evidence_minimums.require_feed_visibility);
    let evidence_complete = evidence_complete
        && (evidence_completeness.browser_trace || !pack.evidence_minimums.require_browser_trace);
    if pack.evidence_minimums.require_captured_request && !evidence_completeness.captured_request {
        evidence_notes.push("captured request missing".to_string());
    }
    if pack.evidence_minimums.require_quarantine_job && !evidence_completeness.quarantine_job {
        evidence_notes.push("quarantine job missing".to_string());
    }
    if pack.evidence_minimums.require_lab_run && !evidence_completeness.lab_run {
        evidence_notes.push("lab run missing".to_string());
    }
    if pack.evidence_minimums.require_evidence_bundle && !evidence_completeness.evidence_bundle {
        evidence_notes.push("evidence bundle missing".to_string());
    }
    if pack.evidence_minimums.require_feed_visibility && !evidence_completeness.feed_visible {
        evidence_notes.push("feed visibility missing".to_string());
    }
    if pack.evidence_minimums.require_browser_trace && !evidence_completeness.browser_trace {
        evidence_notes.push("browser trace missing".to_string());
    }

    if verdict == Verdict::Malicious
        && matches!(pack.confidence_policy, ConfidencePolicy::ComboRequired)
    {
        let weak_only = tripwires_seen
            .iter()
            .all(|tripwire| is_soft_signal(*tripwire));
        if weak_only && pack.control_pair_id.is_none() {
            control_notes.push("combo-required malicious verdict had no control pair".to_string());
        }
    }

    BattleAssertionOutcome {
        verdict_matches: verdict == pack.expected_verdict.verdict,
        node_decision_matches: pack
            .expected_node_decision
            .map(|expected| expected == node_decision)
            .unwrap_or(true),
        missing_tripwires,
        unexpected_tripwires,
        control_pair_valid,
        control_notes,
        evidence_complete,
        evidence_notes,
    }
}

fn is_soft_signal(tripwire: zitpit_core::TripwireKind) -> bool {
    matches!(
        tripwire,
        zitpit_core::TripwireKind::EnvMassEnumeration
            | zitpit_core::TripwireKind::SandboxFingerprinting
            | zitpit_core::TripwireKind::SystemReconBurst
            | zitpit_core::TripwireKind::ArchiveStaging
            | zitpit_core::TripwireKind::NetworkConnection
    )
}

fn build_coverage_summary(results: &[BattleRunResult]) -> CoverageSummary {
    let malicious_total = results
        .iter()
        .filter(|result| result.verdict == Verdict::Malicious)
        .count();
    let malicious_matched = results
        .iter()
        .filter(|result| result.verdict == Verdict::Malicious && result.assertion.verdict_matches)
        .count();
    let control_total = results
        .iter()
        .filter(|result| matches!(result.attack_family, AttackFamily::Control))
        .count();
    let control_passed = results
        .iter()
        .filter(|result| {
            matches!(result.attack_family, AttackFamily::Control)
                && result.verdict == Verdict::Clean
        })
        .count();
    let unsupported_gaps = results
        .iter()
        .filter(|result| {
            !result.assertion.evidence_complete || !result.assertion.control_pair_valid
        })
        .map(|result| {
            format!(
                "{} has incomplete evidence or noisy control overlap",
                result.pack_id
            )
        })
        .collect::<Vec<_>>();
    let matrix = results
        .iter()
        .map(|result| CoverageRecord {
            attack_family: result.attack_family,
            public_tier: result.public_tier,
            ecosystem: result.ecosystem.clone(),
            pack_id: result.pack_id.clone(),
            verdict: result.verdict,
            control_pair_id: result.control_comparison.control_pack_id.clone(),
        })
        .collect::<Vec<_>>();

    CoverageSummary {
        malicious_detection_rate: format!("{malicious_matched}/{malicious_total}"),
        control_pass_rate: format!("{control_passed}/{control_total}"),
        unsupported_gaps,
        matrix,
    }
}

fn browser_available() -> bool {
    command_works("npx", &["playwright", "--version"])
}

fn command_works(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_pack_probe(
    pack: &LoadedBattlePack,
    temp_root: &Path,
    browser_available: bool,
) -> Result<(String, String, Option<String>)> {
    if pack.pack.execution.browser_required {
        if browser_available {
            let script = pack
                .pack
                .execution
                .browser_script
                .as_ref()
                .context("browser script")?;
            let trace_path = temp_root.join(format!("{}-browser-trace.txt", pack.pack.pack_id));
            fs::write(
                &trace_path,
                format!(
                    "playwright simulated run for {} using {}\n",
                    pack.pack.pack_id, script
                ),
            )?;
            return Ok((
                format!("browser pack {} prepared", pack.pack.pack_id),
                String::new(),
                Some(trace_path.display().to_string()),
            ));
        }

        return Ok((
            String::new(),
            "browser runtime unavailable; pack evaluated from declared battle steps".to_string(),
            None,
        ));
    }

    if let Some(command) = &pack.pack.execution.probe_command {
        if let Some((bin, args)) = command.split_first() {
            let output = Command::new(bin)
                .args(args)
                .current_dir(&pack.root_dir)
                .output()
                .with_context(|| format!("run probe command for {}", pack.pack.pack_id))?;
            return Ok((
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
                None,
            ));
        }
    }

    Ok((
        format!("pack {} queued without runtime probe", pack.pack.pack_id),
        String::new(),
        None,
    ))
}

fn collect_pack_manifests(root: &Path, manifests: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_pack_manifests(&path, manifests)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("pack.json") {
            manifests.push(path);
        }
    }
    Ok(())
}

fn pack_digest(pack: &LoadedBattlePack) -> Result<String> {
    let mut material = String::new();
    for file in &pack.pack.files {
        let bytes = fs::read(pack.root_dir.join(file))?;
        material.push_str(file);
        material.push(':');
        material.push_str(&digest_for(&String::from_utf8_lossy(&bytes)));
        material.push('\n');
    }
    Ok(digest_for(&material))
}

fn total_file_bytes(root: &Path, files: &[String]) -> Result<u64> {
    let mut total = 0u64;
    for file in files {
        total += fs::metadata(root.join(file))
            .with_context(|| format!("metadata for {}", root.join(file).display()))?
            .len();
    }
    Ok(total)
}

fn url_path(source: &str) -> String {
    source
        .split("://")
        .nth(1)
        .and_then(|rest| rest.find('/').map(|idx| rest[idx..].to_string()))
        .unwrap_or_else(|| "/".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zitpit_battle_types::{AttackFamily, BattleSuite};
    use zitpit_core::{TripwireKind, Verdict};

    #[test]
    fn discovers_pack_corpus() {
        let runner = BattleRunner::default();
        let packs = runner.lint().expect("lint packs");
        assert!(packs.len() >= 8);
        assert!(
            packs
                .iter()
                .any(|pack| pack.pack.pack_id == "js-postinstall-downloader")
        );
        assert!(
            packs
                .iter()
                .any(|pack| pack.pack.pack_id == "control-benign-npm-install")
        );
    }

    #[tokio::test]
    async fn artifact_suite_runs_malicious_and_benign_controls() {
        let runner = BattleRunner::default();
        let report = runner
            .run_suite(BattleSuite::Artifact, BrowserMode::SkipIfUnavailable)
            .await
            .expect("artifact suite");
        assert!(report.total >= 10);
        assert_eq!(report.failed, 0);
        assert!(
            report
                .results
                .iter()
                .any(|result| result.verdict == Verdict::Malicious)
        );
        assert!(
            report
                .results
                .iter()
                .any(|result| result.verdict == Verdict::Clean)
        );
    }

    #[tokio::test]
    async fn queue_suite_records_correlation_ids_and_tripwires() {
        let runner = BattleRunner::default();
        let pack = runner
            .lint()
            .expect("lint")
            .into_iter()
            .find(|pack| pack.pack.pack_id == "shell-port-scan")
            .expect("shell-port-scan");
        let all = runner.lint().expect("lint again");
        let result = runner.run_pack(&pack, &all).await.expect("run pack");
        assert_eq!(result.verdict, Verdict::Malicious);
        assert!(result.tripwires_seen.contains(&TripwireKind::ReconDenied));
        assert!(!result.correlation.captured_request_id.is_empty());

        assert!(result.correlation.feed_visible);
    }

    #[tokio::test]
    async fn public_core_suite_has_coverage_matrix_and_controls() {
        let runner = BattleRunner::default();
        let report = runner
            .run_suite(BattleSuite::PublicCore, BrowserMode::SkipIfUnavailable)
            .await
            .expect("public core suite");
        assert_eq!(report.failed, 0);
        assert!(
            report
                .coverage
                .matrix
                .iter()
                .any(|record| record.attack_family == AttackFamily::GitIntegrity)
        );
        assert!(
            report
                .coverage
                .matrix
                .iter()
                .any(|record| record.attack_family == AttackFamily::Control)
        );
        assert!(!report.coverage.control_pass_rate.is_empty());
    }

    #[tokio::test]
    async fn actions_and_git_core_suites_select_expected_packs() {
        let runner = BattleRunner::default();
        let actions = runner
            .run_suite(BattleSuite::Actions, BrowserMode::SkipIfUnavailable)
            .await
            .expect("actions suite");
        assert!(
            actions
                .results
                .iter()
                .all(|result| result.attack_family == AttackFamily::GithubActions)
        );

        let git_core = runner
            .run_suite(BattleSuite::GitCore, BrowserMode::SkipIfUnavailable)
            .await
            .expect("git core suite");
        assert!(
            git_core
                .results
                .iter()
                .all(|result| result.attack_family == AttackFamily::GitIntegrity)
        );
    }

    #[tokio::test]
    async fn non_git_suites_select_expected_packs() {
        let runner = BattleRunner::default();

        let go = runner
            .run_suite(BattleSuite::Go, BrowserMode::SkipIfUnavailable)
            .await
            .expect("go suite");
        assert!(!go.results.is_empty());
        assert!(
            go.results
                .iter()
                .all(|result| result.attack_family == AttackFamily::GoModules)
        );

        let cargo = runner
            .run_suite(BattleSuite::Cargo, BrowserMode::SkipIfUnavailable)
            .await
            .expect("cargo suite");
        assert!(!cargo.results.is_empty());
        assert!(
            cargo
                .results
                .iter()
                .all(|result| result.attack_family == AttackFamily::CargoBuildScripts)
        );

        let shell = runner
            .run_suite(BattleSuite::Shell, BrowserMode::SkipIfUnavailable)
            .await
            .expect("shell suite");
        assert!(!shell.results.is_empty());
        assert!(
            shell
                .results
                .iter()
                .all(|result| result.attack_family == AttackFamily::ShellInstallers)
        );

        let workspace = runner
            .run_suite(BattleSuite::Workspace, BrowserMode::SkipIfUnavailable)
            .await
            .expect("workspace suite");
        assert!(!workspace.results.is_empty());
        assert!(
            workspace
                .results
                .iter()
                .all(|result| result.attack_family == AttackFamily::WorkspaceConfig)
        );
    }

    #[tokio::test]
    async fn control_pair_validation_is_enforced_for_public_core_pack() {
        let runner = BattleRunner::default();
        let all = runner.lint().expect("lint");
        let pack = all
            .iter()
            .find(|pack| pack.pack.pack_id == "git-hidden-example-payload")
            .expect("hidden payload pack");
        let result = runner.run_pack(pack, &all).await.expect("run pack");
        assert!(result.assertion.control_pair_valid);
        assert_eq!(
            result.control_comparison.control_pack_id.as_deref(),
            Some("control-benign-git-release")
        );
    }
}
