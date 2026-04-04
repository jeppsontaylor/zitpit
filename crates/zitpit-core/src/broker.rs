use std::{collections::BTreeMap, path::PathBuf};

use chrono::{TimeDelta, Utc};
use tokio::fs;
use uuid::Uuid;

use crate::{
    DecisionEngine, ManifestCatalog, StoreHandle,
    types::{
        ApprovalStatus, ArtifactCoordinate, ArtifactKey, CacheDomain, CacheEntry, CapturedRequest,
        Classification, DecisionRequest, PolicyConfig, ProxyAction, ProxyDecision, QuarantineJob,
        QuarantineStatus, RequestObservation,
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
        let paths = RuntimePaths::from_env();
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
                request_id: observation.request_id,
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

        if matches!(decision.action, ProxyAction::Pending | ProxyAction::Blocked) {
            if let Some(coord) = coordinate {
                self.ensure_quarantine_job(coord, &decision.classification)
                    .await?;
            }
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

        fs::create_dir_all(self.quarantine_root.join(safe_artifact_dir(&key)))
            .await
            .ok();

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
        };
        self.store.0.put_cache_entry(cache_entry.clone()).await?;

        let hold_hours = self.decision_engine.policy.hold_duration_hours;
        let job = QuarantineJob {
            job_id: Uuid::new_v4(),
            artifact_key: key,
            status: QuarantineStatus::Pending,
            created_at: Utc::now(),
            hold_until: Utc::now() + TimeDelta::hours(hold_hours),
            last_error: None,
            cache_entry: Some(cache_entry),
        };
        self.store.0.upsert_quarantine_job(job.clone()).await?;
        Ok(job)
    }

    pub async fn promote_artifact(
        &self,
        coordinate: ArtifactCoordinate,
        resolved_target: String,
        metadata: BTreeMap<String, String>,
    ) -> Result<(), crate::store::StoreError> {
        let key = ArtifactKey::from(&coordinate);
        fs::create_dir_all(self.approved_root.join(safe_artifact_dir(&key)))
            .await
            .ok();
        let cache_entry = CacheEntry {
            artifact_key: key.clone(),
            domain: CacheDomain::Approved,
            storage_path: self
                .approved_root
                .join(safe_artifact_dir(&key))
                .display()
                .to_string(),
            created_at: Utc::now(),
            size_bytes: None,
            digest_sha256: crate::manifest::digest_for(&format!(
                "{}:{}:{}",
                coordinate.source, coordinate.requested_selector, resolved_target
            )),
        };
        self.store.0.put_cache_entry(cache_entry).await?;
        if let Some(existing) = self.store.0.get_quarantine_job(&key).await? {
            self.store
                .0
                .upsert_quarantine_job(QuarantineJob {
                    status: QuarantineStatus::Approved,
                    ..existing
                })
                .await?;
        }
        self.store
            .0
            .upsert_manifest_record(crate::ManifestRecord {
                ecosystem: coordinate.ecosystem,
                source: coordinate.source,
                requested_selector: coordinate.requested_selector,
                selector_kind: coordinate.selector_kind,
                resolved_target: resolved_target.clone(),
                raw_digest_sha256: crate::manifest::digest_for(&resolved_target),
                normalized_digest_sha256: crate::manifest::digest_for(&format!(
                    "tree:{resolved_target}"
                )),
                status: ApprovalStatus::Approved,
                first_seen_at: Utc::now(),
                hold_until: None,
                approved_at: Some(Utc::now()),
                fallback: None,
                detector_refs: vec![],
                metadata,
            })
            .await?;
        Ok(())
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
                source: coordinate.source,
                requested_selector: coordinate.requested_selector,
                selector_kind: coordinate.selector_kind,
                resolved_target: format!("blocked:{}", key.requested_selector),
                raw_digest_sha256: crate::manifest::digest_for(&key.source),
                normalized_digest_sha256: crate::manifest::digest_for(&format!(
                    "blocked:{}:{}",
                    key.source, key.requested_selector
                )),
                status: ApprovalStatus::Blocked,
                first_seen_at: Utc::now(),
                hold_until: None,
                approved_at: None,
                fallback,
                detector_refs: vec!["manual-block".to_string()],
                metadata,
            })
            .await?;
        Ok(())
    }
}

fn safe_artifact_dir(key: &ArtifactKey) -> String {
    crate::manifest::digest_for(&format!(
        "{:?}|{}|{}|{:?}",
        key.ecosystem, key.source, key.requested_selector, key.selector_kind
    ))[..16]
        .to_string()
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
