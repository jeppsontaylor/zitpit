use std::{
    collections::BTreeMap,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use chrono::{TimeDelta, Utc};
use tokio::fs;
use uuid::Uuid;

use crate::{
    DecisionEngine, ManifestCatalog, StoreHandle,
    types::{
        ApprovalStatus, ArtifactCoordinate, ArtifactKey, ArtifactPolicyEvent, CacheDomain,
        CacheEntry, CapabilityVerdict, CapturedRequest, Classification, DecisionRequest,
        ExpiryState, PolicyConfig, PolicyEventContext, ProvenanceResult, ProvenanceStatus,
        ProxyAction, ProxyDecision, QuarantineJob, QuarantineStatus, RequestObservation,
        RevocationState,
    },
};
use zitpit_config::RuntimePaths;

#[derive(Clone)]
pub struct ArtifactBroker {
    store: StoreHandle,
    decision_engine: DecisionEngine,
    approved_root: PathBuf,
    quarantine_root: PathBuf,
}

impl ArtifactBroker {
    pub fn new(store: StoreHandle, policy: PolicyConfig) -> Self {
        Self::with_paths(store, policy, RuntimePaths::from_env())
    }

    pub fn with_paths(store: StoreHandle, policy: PolicyConfig, paths: RuntimePaths) -> Self {
        Self {
            store,
            decision_engine: DecisionEngine::new(policy),
            approved_root: paths.git_approved_root,
            quarantine_root: paths.git_quarantine_root,
        }
    }

    pub async fn decide(
        &self,
        observation: RequestObservation,
        coordinate: Option<ArtifactCoordinate>,
    ) -> Result<ProxyDecision, crate::store::StoreError> {
        let observed_at = observation.observed_at;
        let request_id = observation.request_id;
        let records = self.store.0.list_manifest_records().await?;
        let decision = self.decision_engine.decide(
            &DecisionRequest {
                observation: observation.clone(),
                coordinate: coordinate.clone(),
            },
            &ManifestCatalog::new(records),
        );

        let artifact_key = coordinate.as_ref().map(ArtifactKey::from);
        self.store
            .0
            .record_captured_request(CapturedRequest {
                request_id,
                observation,
                classification: decision.classification.clone(),
                proxy_action: decision.action,
                status_code: None,
                bytes_in: None,
                bytes_out: None,
                stored_body: decision.classification.lane == crate::TrafficLane::CodeIntake,
                client_outcome: None,
                decision_reason: decision.reason.clone(),
                artifact_key,
                egress_decision: None,
                trace: crate::types::ProxyTrace::new(None, None, observed_at)
                    .with_decision(decision.reason.clone()),
            })
            .await?;
        self.store
            .0
            .prune_captured_requests(self.decision_engine.policy.captured_request_retention)
            .await?;

        if matches!(decision.action, ProxyAction::Pending | ProxyAction::Blocked) {
            if let Some(coord) = coordinate.clone() {
                self.ensure_quarantine_job(coord, &decision.classification)
                    .await?;
            }
        }

        if let Some(selector) = coordinate.clone().or_else(|| {
            decision
                .matched_record
                .as_ref()
                .map(|record| record.coordinate())
        }) {
            self.record_policy_event(
                &selector,
                &decision,
                Some(observed_at),
                PolicyEventContext {
                    request_id: Some(request_id),
                    session_id: None,
                    lane: Some(decision.classification.lane),
                    code_intent: Some(decision.classification.intent),
                    host_scope: None,
                    source_coordinates: Some(selector.source.clone()),
                    execution_surface_flags: vec!["broker_decision".to_string()],
                },
                None,
            )
            .await?;
        }

        Ok(decision)
    }

    pub async fn ensure_quarantine_job(
        &self,
        coordinate: ArtifactCoordinate,
        _classification: &Classification,
    ) -> Result<QuarantineJob, crate::store::StoreError> {
        let key = ArtifactKey::from(&coordinate);
        if let Some(existing) = self.store.0.get_quarantine_job(&key).await? {
            return Ok(existing);
        }

        fs::create_dir_all(self.quarantine_root.join(safe_artifact_dir(&key))).await?;

        let cache_entry = CacheEntry {
            artifact_key: key.clone(),
            domain: CacheDomain::Quarantine,
            storage_path: self
                .quarantine_root
                .join(safe_artifact_dir(&key))
                .display()
                .to_string(),
            created_at: Utc::now(),
            size_bytes: None,
            digest_sha256: crate::manifest::digest_for(&format!(
                "{}:{}",
                key.source, key.requested_selector
            )),
            content_digest_sha256: None,
        };
        self.store.0.put_cache_entry(cache_entry.clone()).await?;

        let hold_hours = self.decision_engine.policy.hold_duration_hours;
        let job = QuarantineJob {
            job_id: Uuid::new_v4(),
            artifact_key: key.clone(),
            status: QuarantineStatus::Pending,
            created_at: Utc::now(),
            hold_until: Utc::now() + TimeDelta::hours(hold_hours),
            last_error: None,
            cache_entry: Some(cache_entry),
        };
        self.store.0.upsert_quarantine_job(job.clone()).await?;
        self.store
            .0
            .record_artifact_policy_event(ArtifactPolicyEvent {
                event_id: Uuid::new_v4(),
                artifact_key: key.clone(),
                selector: coordinate.clone(),
                resolved_immutable_identity: None,
                provenance_result: ProvenanceResult {
                    status: ProvenanceStatus::Pending,
                    detail: "artifact queued for quarantine".to_string(),
                },
                verdict: CapabilityVerdict::FetchOnly,
                evidence_pointer: None,
                content_digest_sha256: None,
                normalized_content_digest_sha256: None,
                context: PolicyEventContext {
                    request_id: None,
                    session_id: None,
                    lane: Some(crate::TrafficLane::CodeIntake),
                    code_intent: Some(_classification.intent),
                    host_scope: None,
                    source_coordinates: Some(coordinate.source.clone()),
                    execution_surface_flags: vec!["quarantine_job_created".to_string()],
                },
                expiry_state: ExpiryState {
                    expires_at: Some(job.hold_until),
                    is_expired: false,
                },
                revocation_state: RevocationState::default(),
                created_at: Utc::now(),
            })
            .await?;
        Ok(job)
    }

    pub async fn promote_artifact(
        &self,
        coordinate: ArtifactCoordinate,
        resolved_target: String,
        metadata: BTreeMap<String, String>,
    ) -> Result<(), crate::store::StoreError> {
        let key = ArtifactKey::from(&coordinate);
        let existing_manifest = self
            .store
            .0
            .list_manifest_records()
            .await?
            .into_iter()
            .find(|record| {
                record.ecosystem == coordinate.ecosystem
                    && record.source == coordinate.source
                    && record.requested_selector == coordinate.requested_selector
                    && record.selector_kind == coordinate.selector_kind
            });
        let existing_quarantine = self.store.0.get_quarantine_job(&key).await?;
        let mut merged_metadata = existing_manifest
            .as_ref()
            .map(|record| record.metadata.clone())
            .unwrap_or_default();
        merged_metadata.extend(metadata);

        let storage_path = match self
            .promote_git_quarantine_mirror(
                &coordinate,
                &merged_metadata,
                existing_quarantine.as_ref(),
            )
            .await?
        {
            Some(path) => path,
            None => {
                let generic_dir = self.approved_root.join(safe_artifact_dir(&key));
                fs::create_dir_all(&generic_dir).await?;
                generic_dir
            }
        };
        let cache_entry = CacheEntry {
            artifact_key: key.clone(),
            domain: CacheDomain::Approved,
            storage_path: storage_path.display().to_string(),
            created_at: Utc::now(),
            size_bytes: None,
            digest_sha256: existing_manifest
                .as_ref()
                .map(|record| record.raw_digest_sha256.clone())
                .unwrap_or_else(|| {
                    crate::manifest::digest_for(&format!(
                        "{}:{}:{}",
                        coordinate.source, coordinate.requested_selector, resolved_target
                    ))
                }),
            content_digest_sha256: existing_manifest
                .as_ref()
                .and_then(|record| record.content_digest_sha256.clone()),
        };
        self.store.0.put_cache_entry(cache_entry.clone()).await?;
        if let Some(existing) = existing_quarantine {
            self.store
                .0
                .upsert_quarantine_job(QuarantineJob {
                    cache_entry: Some(cache_entry.clone()),
                    status: QuarantineStatus::Approved,
                    ..existing
                })
                .await?;
        }
        self.store
            .0
            .upsert_manifest_record(crate::ManifestRecord {
                ecosystem: coordinate.ecosystem,
                source: coordinate.source.clone(),
                requested_selector: coordinate.requested_selector.clone(),
                selector_kind: coordinate.selector_kind,
                resolved_target: resolved_target.clone(),
                raw_digest_sha256: existing_manifest
                    .as_ref()
                    .map(|record| record.raw_digest_sha256.clone())
                    .unwrap_or_else(|| crate::manifest::digest_for(&resolved_target)),
                normalized_digest_sha256: existing_manifest
                    .as_ref()
                    .map(|record| record.normalized_digest_sha256.clone())
                    .unwrap_or_else(|| {
                        crate::manifest::digest_for(&format!("tree:{resolved_target}"))
                    }),
                content_digest_sha256: existing_manifest
                    .as_ref()
                    .and_then(|record| record.content_digest_sha256.clone()),
                normalized_content_digest_sha256: existing_manifest
                    .as_ref()
                    .and_then(|record| record.normalized_content_digest_sha256.clone()),
                status: ApprovalStatus::Approved,
                first_seen_at: Utc::now(),
                hold_until: None,
                approved_at: Some(Utc::now()),
                fallback: None,
                detector_refs: vec![],
                metadata: merged_metadata,
            })
            .await?;
        self.store
            .0
            .record_artifact_policy_event(ArtifactPolicyEvent {
                event_id: Uuid::new_v4(),
                artifact_key: key,
                selector: coordinate,
                resolved_immutable_identity: Some(resolved_target),
                provenance_result: ProvenanceResult {
                    status: ProvenanceStatus::Verified,
                    detail: "artifact promoted into approved lane".to_string(),
                },
                verdict: CapabilityVerdict::RunDev,
                evidence_pointer: None,
                content_digest_sha256: existing_manifest
                    .as_ref()
                    .and_then(|record| record.content_digest_sha256.clone()),
                normalized_content_digest_sha256: existing_manifest
                    .as_ref()
                    .and_then(|record| record.normalized_content_digest_sha256.clone()),
                context: PolicyEventContext {
                    request_id: None,
                    session_id: None,
                    lane: Some(crate::TrafficLane::CodeIntake),
                    code_intent: None,
                    host_scope: Some("protected_host".to_string()),
                    source_coordinates: None,
                    execution_surface_flags: vec!["promotion".to_string()],
                },
                expiry_state: ExpiryState::default(),
                revocation_state: RevocationState::default(),
                created_at: Utc::now(),
            })
            .await?;
        Ok(())
    }

    async fn promote_git_quarantine_mirror(
        &self,
        coordinate: &ArtifactCoordinate,
        metadata: &BTreeMap<String, String>,
        existing_quarantine: Option<&QuarantineJob>,
    ) -> Result<Option<PathBuf>, crate::store::StoreError> {
        if coordinate.ecosystem != crate::Ecosystem::Git
            || coordinate.selector_kind != crate::SelectorKind::ExactCommit
        {
            return Ok(None);
        }
        let Some(repo_path) = metadata.get("repo_path") else {
            return Ok(None);
        };
        let Some(quarantine_job) = existing_quarantine else {
            return Ok(None);
        };
        let Some(cache_entry) = quarantine_job.cache_entry.as_ref() else {
            return Ok(None);
        };
        let quarantine_repo_root = PathBuf::from(&cache_entry.storage_path);
        if !quarantine_repo_root.join("objects").exists() {
            return Ok(None);
        }

        let approved_repo_root = self
            .approved_root
            .join(git_source_cache_dir(&coordinate.source))
            .join(repo_path);
        if let Some(parent) = approved_repo_root.parent() {
            fs::create_dir_all(parent).await?;
        }
        if approved_repo_root.exists() {
            remove_dir_if_exists(&approved_repo_root).await?;
        }

        match fs::rename(&quarantine_repo_root, &approved_repo_root).await {
            Ok(()) => Ok(Some(approved_repo_root)),
            Err(error) if error.kind() == ErrorKind::CrossesDevices => {
                copy_dir_recursive(&quarantine_repo_root, &approved_repo_root).await?;
                remove_dir_if_exists(&quarantine_repo_root).await?;
                Ok(Some(approved_repo_root))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn block_artifact(
        &self,
        coordinate: ArtifactCoordinate,
        metadata: BTreeMap<String, String>,
        fallback_selector: Option<String>,
    ) -> Result<(), crate::store::StoreError> {
        let key = ArtifactKey::from(&coordinate);
        let fallback = fallback_selector.map(|selector| crate::FallbackTarget {
            selector,
            resolved_target: None,
            reason: "operator block".to_string(),
        });
        let job = self
            .ensure_quarantine_job(
                coordinate.clone(),
                &Classification {
                    lane: crate::TrafficLane::CodeIntake,
                    ecosystem: Some(coordinate.ecosystem),
                    intent: crate::CodeIntent::UnknownCodeHost,
                    reason: "manual block".to_string(),
                    confidence: 100,
                    requires_quarantine: true,
                    host_family: None,
                },
            )
            .await?;
        self.store
            .0
            .upsert_quarantine_job(QuarantineJob {
                status: QuarantineStatus::Blocked,
                ..job
            })
            .await?;
        self.store
            .0
            .upsert_manifest_record(crate::ManifestRecord {
                ecosystem: coordinate.ecosystem,
                source: coordinate.source.clone(),
                requested_selector: coordinate.requested_selector.clone(),
                selector_kind: coordinate.selector_kind,
                resolved_target: format!("blocked:{}", key.requested_selector),
                raw_digest_sha256: crate::manifest::digest_for(&key.source),
                normalized_digest_sha256: crate::manifest::digest_for(&format!(
                    "blocked:{}:{}",
                    key.source, key.requested_selector
                )),
                content_digest_sha256: None,
                normalized_content_digest_sha256: None,
                status: ApprovalStatus::Blocked,
                first_seen_at: Utc::now(),
                hold_until: None,
                approved_at: None,
                fallback,
                detector_refs: vec!["manual-block".to_string()],
                metadata,
            })
            .await?;
        self.store
            .0
            .record_artifact_policy_event(ArtifactPolicyEvent {
                event_id: Uuid::new_v4(),
                artifact_key: key,
                selector: coordinate,
                resolved_immutable_identity: None,
                provenance_result: ProvenanceResult {
                    status: ProvenanceStatus::Failed,
                    detail: "artifact blocked by operator policy".to_string(),
                },
                verdict: CapabilityVerdict::Blocked,
                evidence_pointer: None,
                content_digest_sha256: None,
                normalized_content_digest_sha256: None,
                context: PolicyEventContext {
                    request_id: None,
                    session_id: None,
                    lane: Some(crate::TrafficLane::CodeIntake),
                    code_intent: None,
                    host_scope: Some("protected_host".to_string()),
                    source_coordinates: None,
                    execution_surface_flags: vec!["operator_block".to_string()],
                },
                expiry_state: ExpiryState::default(),
                revocation_state: RevocationState::default(),
                created_at: Utc::now(),
            })
            .await?;
        Ok(())
    }

    async fn record_policy_event(
        &self,
        selector: &ArtifactCoordinate,
        decision: &ProxyDecision,
        observed_at: Option<chrono::DateTime<Utc>>,
        context: PolicyEventContext,
        evidence_pointer: Option<Uuid>,
    ) -> Result<(), crate::store::StoreError> {
        let verdict = match decision.action {
            ProxyAction::Allow | ProxyAction::Fallback => CapabilityVerdict::RunDev,
            ProxyAction::Pending => CapabilityVerdict::FetchOnly,
            ProxyAction::Blocked | ProxyAction::Bypass | ProxyAction::Tunnel => {
                CapabilityVerdict::Blocked
            }
        };
        let provenance_status = match decision.action {
            ProxyAction::Allow | ProxyAction::Fallback => ProvenanceStatus::Verified,
            ProxyAction::Pending => ProvenanceStatus::Pending,
            ProxyAction::Blocked | ProxyAction::Bypass | ProxyAction::Tunnel => {
                ProvenanceStatus::Failed
            }
        };
        self.store
            .0
            .record_artifact_policy_event(ArtifactPolicyEvent {
                event_id: Uuid::new_v4(),
                artifact_key: ArtifactKey::from(selector),
                selector: selector.clone(),
                resolved_immutable_identity: decision
                    .matched_record
                    .as_ref()
                    .map(|record| record.resolved_target.clone()),
                provenance_result: ProvenanceResult {
                    status: provenance_status,
                    detail: decision.reason.clone(),
                },
                verdict,
                evidence_pointer,
                content_digest_sha256: decision
                    .matched_record
                    .as_ref()
                    .and_then(|record| record.content_digest_sha256.clone()),
                normalized_content_digest_sha256: decision
                    .matched_record
                    .as_ref()
                    .and_then(|record| record.normalized_content_digest_sha256.clone()),
                context,
                expiry_state: ExpiryState {
                    expires_at: decision.hold_until,
                    is_expired: decision
                        .hold_until
                        .map(|expires_at| expires_at <= observed_at.unwrap_or_else(Utc::now))
                        .unwrap_or(false),
                },
                revocation_state: RevocationState::default(),
                created_at: observed_at.unwrap_or_else(Utc::now),
            })
            .await
    }
}

fn safe_artifact_dir(key: &ArtifactKey) -> String {
    crate::manifest::digest_for(&format!(
        "{:?}|{}|{}|{:?}",
        key.ecosystem, key.source, key.requested_selector, key.selector_kind
    ))[..16]
        .to_string()
}

fn git_source_cache_dir(source: &str) -> String {
    crate::manifest::digest_for(source)[..16].to_string()
}

async fn copy_dir_recursive(from: &Path, to: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(to).await?;
    let mut entries = fs::read_dir(from).await?;
    while let Some(entry) = entries.next_entry().await? {
        let source_path = entry.path();
        let destination_path = to.join(entry.file_name());
        let file_type = entry.file_type().await?;
        if file_type.is_dir() {
            Box::pin(copy_dir_recursive(&source_path, &destination_path)).await?;
        } else {
            fs::copy(&source_path, &destination_path).await?;
        }
    }
    Ok(())
}

async fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;

    use super::ArtifactBroker;
    use crate::{
        ArtifactCoordinate, ArtifactKey, Ecosystem, SelectorHint, SelectorKind, StoreHandle,
        types::RequestObservation,
    };

    #[tokio::test]
    async fn broker_creates_quarantine_job_for_unknown_exact_request() {
        let broker = ArtifactBroker::new(
            StoreHandle::connect_from_env().await.expect("store"),
            crate::sample_policy(),
        );
        let observation = RequestObservation {
            request_id: uuid::Uuid::new_v4(),
            observed_at: Utc::now(),
            scheme: "https".to_string(),
            authority: "github.com".to_string(),
            path: "/evil/repo.git".to_string(),
            method: "CONNECT".to_string(),
            user_agent: Some("git/2.47".to_string()),
            headers: BTreeMap::new(),
            selector_hint: Some(SelectorHint {
                requested: "deadbeef".to_string(),
                kind: SelectorKind::ExactCommit,
            }),
        };
        let coordinate = ArtifactCoordinate {
            ecosystem: Ecosystem::Git,
            source: "https://github.com/evil/repo.git".to_string(),
            requested_selector: "deadbeef".to_string(),
            selector_kind: SelectorKind::ExactCommit,
        };
        let decision = broker
            .decide(observation, Some(coordinate.clone()))
            .await
            .expect("decision");
        assert!(matches!(decision.action, crate::ProxyAction::Pending));
        let job = broker
            .store
            .0
            .get_quarantine_job(&ArtifactKey::from(&coordinate))
            .await
            .expect("job lookup");
        assert!(job.is_some());
    }
}
