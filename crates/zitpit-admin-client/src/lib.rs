use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use zitpit_core::{
    ArtifactCoordinate, CapturedRequest, EvidenceBundle, HourlyFeedRecord, LabRun, ManifestRecord,
    NodeSession, QuarantineJob,
};

#[derive(Debug, Clone)]
pub struct AdminClient {
    http: Client,
    pub proxy_base: String,
    pub manifest_base: String,
    pub lab_base: String,
    pub watch_base: String,
    pub node_base: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewModel {
    pub captured_requests: usize,
    pub manifest_records: usize,
    pub quarantine_jobs: usize,
    pub lab_runs: usize,
    pub evidence_bundles: usize,
    pub feed_records: usize,
    pub node_sessions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageSummaryModel {
    pub total_repos_downloaded: usize,
    pub total_storage_bytes: u64,
    pub latest_download_at: Option<DateTime<Utc>>,
    pub latest_download_size_bytes: Option<u64>,
    pub snapshot_generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub overview: OverviewModel,
    pub storage_summary: StorageSummaryModel,
    pub activity: Vec<CapturedRequest>,
    pub manifest_records: Vec<ManifestRecord>,
    pub quarantine_jobs: Vec<QuarantineJob>,
    pub lab_runs: Vec<LabRun>,
    pub evidence: Vec<EvidenceBundle>,
    pub feed: Vec<HourlyFeedRecord>,
    pub nodes: Vec<NodeSession>,
}

impl AdminClient {
    pub fn from_local_defaults() -> Self {
        let proxy_base = std::env::var("ZITPIT_PROXY_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:43000".to_string());
        let manifest_base = std::env::var("ZITPIT_MANIFEST_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:43001".to_string());
        let lab_base = std::env::var("ZITPIT_LAB_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:43002".to_string());
        let watch_base = std::env::var("ZITPIT_WATCH_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:43003".to_string());
        let node_base = std::env::var("ZITPIT_NODE_BASE")
            .unwrap_or_else(|_| "http://127.0.0.1:43006".to_string());
        Self::new(proxy_base, manifest_base, lab_base, watch_base, node_base)
    }

    pub fn new(
        proxy_base: impl Into<String>,
        manifest_base: impl Into<String>,
        lab_base: impl Into<String>,
        watch_base: impl Into<String>,
        node_base: impl Into<String>,
    ) -> Self {
        Self {
            http: Client::new(),
            proxy_base: proxy_base.into(),
            manifest_base: manifest_base.into(),
            lab_base: lab_base.into(),
            watch_base: watch_base.into(),
            node_base: node_base.into(),
        }
    }

    pub async fn snapshot(&self) -> Result<DashboardSnapshot> {
        let activity = self.activity().await?;
        let manifest_records = self.manifest_records().await?;
        let quarantine_jobs = self.quarantine_jobs().await?;
        let lab_runs = self.lab_runs().await?;
        let evidence = self.evidence().await?;
        let feed = self.feed().await?;
        let nodes = self.nodes().await?;
        let snapshot_generated_at = Utc::now();
        let overview = OverviewModel {
            captured_requests: activity.len(),
            manifest_records: manifest_records.len(),
            quarantine_jobs: quarantine_jobs.len(),
            lab_runs: lab_runs.len(),
            evidence_bundles: evidence.len(),
            feed_records: feed.len(),
            node_sessions: nodes.len(),
        };
        let storage_summary = build_storage_summary(&quarantine_jobs, snapshot_generated_at);
        Ok(DashboardSnapshot {
            overview,
            storage_summary,
            activity,
            manifest_records,
            quarantine_jobs,
            lab_runs,
            evidence,
            feed,
            nodes,
        })
    }

    pub async fn activity(&self) -> Result<Vec<CapturedRequest>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/captured-requests", self.proxy_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn manifest_records(&self) -> Result<Vec<ManifestRecord>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/manifest/records", self.manifest_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn quarantine_jobs(&self) -> Result<Vec<QuarantineJob>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/quarantine/jobs", self.manifest_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn lab_runs(&self) -> Result<Vec<LabRun>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/jobs", self.lab_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn evidence(&self) -> Result<Vec<EvidenceBundle>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/evidence", self.lab_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn feed(&self) -> Result<Vec<HourlyFeedRecord>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/feed/hourly", self.watch_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn nodes(&self) -> Result<Vec<NodeSession>> {
        Ok(self
            .http
            .get(format!("{}/api/v1/node/sessions", self.node_base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn approve(
        &self,
        coordinate: ArtifactCoordinate,
        resolved_target: String,
    ) -> Result<()> {
        self.http
            .post(format!("{}/api/v1/manifest/promote", self.manifest_base))
            .json(&serde_json::json!({
                "coordinate": coordinate,
                "resolved_target": resolved_target,
                "metadata": {
                    "approved_by": "zitpit-tui"
                }
            }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn block(
        &self,
        coordinate: ArtifactCoordinate,
        fallback_selector: Option<String>,
    ) -> Result<()> {
        self.http
            .post(format!("{}/api/v1/manifest/block", self.manifest_base))
            .json(&serde_json::json!({
                "coordinate": coordinate,
                "metadata": {
                    "blocked_by": "zitpit-tui"
                },
                "fallback_selector": fallback_selector
            }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn rerun_lab(&self, coordinate: ArtifactCoordinate) -> Result<()> {
        self.http
            .post(format!("{}/api/v1/jobs/run", self.lab_base))
            .json(&coordinate)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

fn build_storage_summary(
    quarantine_jobs: &[QuarantineJob],
    snapshot_generated_at: DateTime<Utc>,
) -> StorageSummaryModel {
    use std::collections::BTreeMap;

    let mut unique_entries = BTreeMap::new();
    for job in quarantine_jobs {
        if let Some(entry) = &job.cache_entry {
            unique_entries
                .entry(entry.storage_path.clone())
                .or_insert_with(|| entry.clone());
        }
    }

    let total_storage_bytes = unique_entries
        .values()
        .filter_map(|entry| entry.size_bytes)
        .sum::<u64>();
    let total_repos_downloaded = unique_entries.len();
    let latest_entry = unique_entries.values().max_by_key(|entry| entry.created_at);

    StorageSummaryModel {
        total_repos_downloaded,
        total_storage_bytes,
        latest_download_at: latest_entry.map(|entry| entry.created_at),
        latest_download_size_bytes: latest_entry.and_then(|entry| entry.size_bytes),
        snapshot_generated_at,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use zitpit_core::{
        ArtifactCoordinate, ArtifactKey, CacheDomain, CacheEntry, Ecosystem, QuarantineJob,
        QuarantineStatus, SelectorKind,
    };

    use super::build_storage_summary;

    fn artifact_key(source: &str) -> ArtifactKey {
        ArtifactCoordinate {
            ecosystem: Ecosystem::Git,
            source: source.to_string(),
            requested_selector: "refs/heads/main".to_string(),
            selector_kind: SelectorKind::Branch,
        }
        .into()
    }

    #[test]
    fn storage_summary_deduplicates_paths_and_tracks_latest_download() {
        let generated_at = Utc.with_ymd_and_hms(2026, 4, 2, 12, 0, 0).unwrap();
        let older = Utc.with_ymd_and_hms(2026, 4, 2, 11, 0, 0).unwrap();
        let newer = Utc.with_ymd_and_hms(2026, 4, 2, 11, 30, 0).unwrap();
        let shared_key = artifact_key("https://github.com/acme/one.git");
        let other_key = artifact_key("https://github.com/acme/two.git");
        let jobs = vec![
            QuarantineJob {
                job_id: uuid::Uuid::new_v4(),
                artifact_key: shared_key.clone(),
                status: QuarantineStatus::Pending,
                created_at: older,
                hold_until: older,
                last_error: None,
                cache_entry: Some(CacheEntry {
                    artifact_key: shared_key.clone(),
                    domain: CacheDomain::Quarantine,
                    storage_path: "/var/lib/zitpit/git/quarantine/acme/one.git".to_string(),
                    created_at: older,
                    size_bytes: Some(64),
                    digest_sha256: "a".repeat(64),
                    content_digest_sha256: None,
                }),
            },
            QuarantineJob {
                job_id: uuid::Uuid::new_v4(),
                artifact_key: shared_key.clone(),
                status: QuarantineStatus::ReadyForAnalysis,
                created_at: older,
                hold_until: older,
                last_error: None,
                cache_entry: Some(CacheEntry {
                    artifact_key: shared_key,
                    domain: CacheDomain::Quarantine,
                    storage_path: "/var/lib/zitpit/git/quarantine/acme/one.git".to_string(),
                    created_at: newer,
                    size_bytes: Some(64),
                    digest_sha256: "b".repeat(64),
                    content_digest_sha256: None,
                }),
            },
            QuarantineJob {
                job_id: uuid::Uuid::new_v4(),
                artifact_key: other_key.clone(),
                status: QuarantineStatus::Approved,
                created_at: newer,
                hold_until: newer,
                last_error: None,
                cache_entry: Some(CacheEntry {
                    artifact_key: other_key,
                    domain: CacheDomain::Quarantine,
                    storage_path: "/var/lib/zitpit/git/quarantine/acme/two.git".to_string(),
                    created_at: newer,
                    size_bytes: Some(128),
                    digest_sha256: "c".repeat(64),
                    content_digest_sha256: None,
                }),
            },
        ];

        let summary = build_storage_summary(&jobs, generated_at);
        assert_eq!(summary.total_repos_downloaded, 2);
        assert_eq!(summary.total_storage_bytes, 192);
        assert_eq!(summary.latest_download_at, Some(newer));
        assert_eq!(summary.latest_download_size_bytes, Some(128));
        assert_eq!(summary.snapshot_generated_at, generated_at);
    }

    #[test]
    fn storage_summary_handles_empty_cache() {
        let generated_at = Utc.with_ymd_and_hms(2026, 4, 2, 12, 0, 0).unwrap();
        let summary = build_storage_summary(&[], generated_at);
        assert_eq!(summary.total_repos_downloaded, 0);
        assert_eq!(summary.total_storage_bytes, 0);
        assert_eq!(summary.latest_download_at, None);
        assert_eq!(summary.latest_download_size_bytes, None);
    }
}
