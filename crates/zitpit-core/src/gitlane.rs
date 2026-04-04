use std::{
    collections::BTreeMap,
    ffi::OsString,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use chrono::{TimeDelta, Utc};
use http::{Method, Response, StatusCode, header::HeaderMap};
use http_body_util::Full;
use lru::LruCache;
use reqwest::Url;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use uuid::Uuid;

use crate::{
    ApprovalStatus, ArtifactCoordinate, ArtifactKey, CacheDomain, CacheEntry, DetectionSeverity,
    EvidenceBundle, FirecrackerOrchestrator, HourlyFeedRecord, LabRun, ManifestCatalog,
    ManifestRecord, ProxyTraceKind, QuarantineJob, QuarantineStatus, StoreHandle,
    TripwireEvaluator, manifest::digest_for,
};
use zitpit_config::RuntimePaths;

#[derive(Debug, Error)]
pub enum GitLaneError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("git backend failed: {0}")]
    Backend(String),
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
}

#[derive(Clone)]
pub struct GitSmartHttpAdapter {
    store: StoreHandle,
    paths: RuntimePaths,
    approved_root: PathBuf,
    quarantine_root: PathBuf,
    hold_duration_hours: i64,
    hot_cache: GitHotCache,
}

#[derive(Debug, Clone)]
pub struct GitSmartHttpResult {
    pub response: Response<Full<Bytes>>,
    pub source_url: String,
    pub repo_root: PathBuf,
    pub mirror_created: bool,
    pub cache_hit: bool,
    pub hot_cache_hit: bool,
    pub resolved_target: Option<String>,
    pub raw_digest_sha256: Option<String>,
    pub normalized_digest_sha256: Option<String>,
    pub lifecycle_events: Vec<GitLifecycleEvent>,
}

#[derive(Debug, Clone)]
pub struct GitPendingResult {
    pub response: Response<Full<Bytes>>,
    pub source_url: String,
    pub repo_root: PathBuf,
    pub cache_hit: bool,
    pub resolved_target: Option<String>,
    pub raw_digest_sha256: Option<String>,
    pub normalized_digest_sha256: Option<String>,
    pub quarantine_job: QuarantineJob,
    pub lab_run: Option<LabRun>,
    pub evidence: Option<EvidenceBundle>,
    pub lifecycle_events: Vec<GitLifecycleEvent>,
}

#[derive(Debug, Clone)]
pub struct GitLifecycleEvent {
    pub kind: ProxyTraceKind,
    pub detail: String,
}

#[derive(Debug, Clone)]
struct GitRepoIdentity {
    commit_id: String,
    tree_id: String,
    raw_digest_sha256: String,
    normalized_digest_sha256: String,
}

#[derive(Clone)]
struct GitHotCache {
    entries: Arc<Mutex<LruCache<GitHotCacheKey, Response<Full<Bytes>>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GitHotCacheKey {
    source_url: String,
    repo_path: String,
    method: String,
    request_path: String,
    query: String,
    body_digest_sha256: String,
    repo_digest_sha256: String,
}

impl GitHotCache {
    fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("hot cache capacity");
        Self {
            entries: Arc::new(Mutex::new(LruCache::new(capacity))),
        }
    }

    fn get(&self, key: &GitHotCacheKey) -> Option<Response<Full<Bytes>>> {
        self.entries.lock().ok()?.get(key).cloned()
    }

    fn put(&self, key: GitHotCacheKey, response: Response<Full<Bytes>>) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.put(key, response);
        }
    }
}

impl GitHotCacheKey {
    fn from_request(
        source_url: &str,
        request: &GitRequest,
        method: &Method,
        request_url: &Url,
        body: &[u8],
        repo_digest_sha256: &str,
    ) -> Self {
        Self {
            source_url: source_url.to_string(),
            repo_path: request.repo_path.clone(),
            method: method.as_str().to_string(),
            request_path: request_url.path().to_string(),
            query: request_url.query().unwrap_or("").to_string(),
            body_digest_sha256: sha256_hex(body),
            repo_digest_sha256: repo_digest_sha256.to_string(),
        }
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedGitUpstream {
    fetch_url: String,
    mode: GitUpstreamMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MirrorSyncResult {
    upstream: ResolvedGitUpstream,
    mirror_created: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitUpstreamMode {
    SeededMirror,
    Override,
    Direct,
}

#[derive(Debug, Clone, Default)]
pub struct GitHttpBackend;

impl GitSmartHttpAdapter {
    pub fn new(store: StoreHandle) -> Self {
        Self::with_paths(store, RuntimePaths::from_env())
    }

    pub fn with_paths(store: StoreHandle, paths: RuntimePaths) -> Self {
        Self::with_paths_and_hold_duration(store, paths, crate::sample_policy().hold_duration_hours)
    }

    pub fn with_paths_and_hold_duration(
        store: StoreHandle,
        paths: RuntimePaths,
        hold_duration_hours: i64,
    ) -> Self {
        Self::with_paths_and_hold_duration_and_hot_cache_capacity(
            store,
            paths,
            hold_duration_hours,
            32,
        )
    }

    pub fn with_paths_and_hold_duration_and_hot_cache_capacity(
        store: StoreHandle,
        paths: RuntimePaths,
        hold_duration_hours: i64,
        hot_cache_capacity: usize,
    ) -> Self {
        Self {
            store,
            approved_root: paths.git_approved_root.clone(),
            quarantine_root: paths.git_quarantine_root.clone(),
            paths,
            hold_duration_hours,
            hot_cache: GitHotCache::new(hot_cache_capacity),
        }
    }

    pub async fn handle(
        &self,
        source_url: &str,
        request_url: &Url,
        method: &Method,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<GitSmartHttpResult, GitLaneError> {
        let request = GitRequest::from_url(request_url)?;
        if !request.is_smart_http() {
            return Err(GitLaneError::Backend(
                "not a git smart-http request".to_string(),
            ));
        }

        let catalog = ManifestCatalog::new(self.store.0.list_manifest_records().await?);
        let approved = catalog.latest_approved_for_source(source_url);
        if approved.is_none() {
            return Err(GitLaneError::Backend(
                "git source is not approved yet".to_string(),
            ));
        }

        let project_root = self.approved_root.join(safe_repo_dir(source_url));
        let repo_root = project_root.join(&request.repo_path);
        let key = ArtifactKey {
            ecosystem: crate::Ecosystem::Git,
            source: source_url.to_string(),
            requested_selector: "git-smart-http".to_string(),
            selector_kind: crate::SelectorKind::Floating,
        };
        let cached = repo_root.join("objects").exists()
            && self
                .store
                .0
                .get_cache_entry(&key, CacheDomain::Approved)
                .await?
                .is_some();
        let mut lifecycle_events = Vec::new();
        let mirror_created = if cached {
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::CacheHit,
                detail: format!("served approved repo from cache {source_url}"),
            });
            false
        } else {
            let upstream = resolve_git_upstream(source_url)?;
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::FetchStarted,
                detail: upstream_fetch_detail("approved repo fetch", source_url, &upstream),
            });
            let mirror_sync = self
                .ensure_mirror(source_url, &upstream, &repo_root)
                .await?;
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::FetchCompleted,
                detail: format!(
                    "{}; mirror ready at {}",
                    upstream_fetch_detail(
                        "approved repo fetch completed",
                        source_url,
                        &mirror_sync.upstream,
                    ),
                    repo_root.display()
                ),
            });
            mirror_sync.mirror_created
        };
        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::HashStarted,
            detail: format!("computing approved Git digests for {}", repo_root.display()),
        });
        let identity = self.inspect_repo(&repo_root).await?;
        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::HashCompleted,
            detail: format!("commit={} tree={}", identity.commit_id, identity.tree_id),
        });
        self.store
            .0
            .put_cache_entry(CacheEntry {
                artifact_key: key,
                domain: CacheDomain::Approved,
                storage_path: repo_root.display().to_string(),
                created_at: Utc::now(),
                size_bytes: None,
                digest_sha256: identity.raw_digest_sha256.clone(),
            })
            .await?;
        let hot_cache_key = GitHotCacheKey::from_request(
            source_url,
            &request,
            method,
            request_url,
            body.as_ref(),
            &identity.raw_digest_sha256,
        );
        if let Some(response) = self.hot_cache.get(&hot_cache_key) {
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::HotCacheHit,
                detail: format!("served approved repo from in-memory hot cache {source_url}"),
            });
            return Ok(GitSmartHttpResult {
                response,
                source_url: source_url.to_string(),
                repo_root,
                mirror_created,
                cache_hit: cached,
                hot_cache_hit: true,
                resolved_target: Some(identity.commit_id),
                raw_digest_sha256: Some(identity.raw_digest_sha256),
                normalized_digest_sha256: Some(identity.normalized_digest_sha256),
                lifecycle_events,
            });
        }

        let response = GitHttpBackend::serve(
            &project_root,
            &request.repo_path,
            method,
            request_url,
            headers,
            body,
        )
        .await?;
        self.hot_cache.put(hot_cache_key, response.clone());
        Ok(GitSmartHttpResult {
            response,
            source_url: source_url.to_string(),
            repo_root,
            mirror_created,
            cache_hit: cached,
            hot_cache_hit: false,
            resolved_target: Some(identity.commit_id),
            raw_digest_sha256: Some(identity.raw_digest_sha256),
            normalized_digest_sha256: Some(identity.normalized_digest_sha256),
            lifecycle_events,
        })
    }

    pub async fn acquire_unknown_source(
        &self,
        source_url: &str,
        request_url: &Url,
    ) -> Result<GitPendingResult, GitLaneError> {
        let request = GitRequest::from_url(request_url)?;
        let repo_root = self
            .quarantine_root
            .join(safe_repo_dir(source_url))
            .join(&request.repo_path);
        let key = ArtifactKey {
            ecosystem: crate::Ecosystem::Git,
            source: source_url.to_string(),
            requested_selector: "git-smart-http".to_string(),
            selector_kind: crate::SelectorKind::Floating,
        };
        let mut lifecycle_events = Vec::new();
        let cached = repo_root.join("objects").exists()
            && self
                .store
                .0
                .get_cache_entry(&key, CacheDomain::Quarantine)
                .await?
                .is_some();
        if cached {
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::CacheHit,
                detail: format!("reused quarantined repo from {}", repo_root.display()),
            });
        } else {
            let upstream = resolve_git_upstream(source_url)?;
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::FetchStarted,
                detail: upstream_fetch_detail(
                    "quarantine acquisition started",
                    source_url,
                    &upstream,
                ),
            });
            let upstream = self
                .ensure_quarantine_mirror(source_url, &upstream, &repo_root)
                .await?;
            lifecycle_events.push(GitLifecycleEvent {
                kind: ProxyTraceKind::FetchCompleted,
                detail: format!(
                    "{}; quarantine mirror populated at {}",
                    upstream_fetch_detail(
                        "quarantine acquisition completed",
                        source_url,
                        &upstream
                    ),
                    repo_root.display()
                ),
            });
        }

        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::HashStarted,
            detail: format!(
                "computing quarantine Git digests for {}",
                repo_root.display()
            ),
        });
        let identity = self.inspect_repo(&repo_root).await?;
        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::HashCompleted,
            detail: format!("commit={} tree={}", identity.commit_id, identity.tree_id),
        });
        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::ManifestChecked,
            detail: format!("manifest lookup miss for pending source {source_url}"),
        });

        let cache_entry = CacheEntry {
            artifact_key: key.clone(),
            domain: CacheDomain::Quarantine,
            storage_path: repo_root.display().to_string(),
            created_at: Utc::now(),
            size_bytes: None,
            digest_sha256: identity.raw_digest_sha256.clone(),
        };
        self.store.0.put_cache_entry(cache_entry.clone()).await?;

        let job = QuarantineJob {
            job_id: Uuid::new_v4(),
            artifact_key: key.clone(),
            status: QuarantineStatus::ReadyForAnalysis,
            created_at: Utc::now(),
            hold_until: Utc::now() + TimeDelta::hours(self.hold_duration_hours),
            last_error: None,
            cache_entry: Some(cache_entry),
        };
        let job = self.store.0.upsert_quarantine_job(job).await?;
        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::QuarantineCreated,
            detail: format!("quarantine job {} created", job.job_id),
        });

        let coordinate = ArtifactCoordinate {
            ecosystem: crate::Ecosystem::Git,
            source: source_url.to_string(),
            requested_selector: "git-smart-http".to_string(),
            selector_kind: crate::SelectorKind::Floating,
        };
        self.store
            .0
            .upsert_manifest_record(ManifestRecord {
                ecosystem: coordinate.ecosystem,
                source: coordinate.source.clone(),
                requested_selector: coordinate.requested_selector.clone(),
                selector_kind: coordinate.selector_kind,
                resolved_target: identity.commit_id.clone(),
                raw_digest_sha256: identity.raw_digest_sha256.clone(),
                normalized_digest_sha256: identity.normalized_digest_sha256.clone(),
                status: ApprovalStatus::Pending,
                first_seen_at: Utc::now(),
                hold_until: Some(job.hold_until),
                approved_at: None,
                fallback: None,
                detector_refs: vec!["report://git/quarantine".to_string()],
                metadata: BTreeMap::from([
                    ("tree_id".to_string(), identity.tree_id.clone()),
                    ("repo_path".to_string(), request.repo_path.clone()),
                ]),
            })
            .await?;

        let orchestrator = FirecrackerOrchestrator::with_paths(self.paths.clone());
        let planned_run = orchestrator.plan_run(coordinate.clone());
        let stored_run = self.store.0.upsert_lab_run(planned_run).await?;
        lifecycle_events.push(GitLifecycleEvent {
            kind: ProxyTraceKind::LabScheduled,
            detail: format!("lab run {} scheduled", stored_run.run_id),
        });

        let evidence_summary = TripwireEvaluator::sample_suspicious_run(coordinate.clone());
        let evidence = EvidenceBundle {
            evidence_id: Uuid::new_v4(),
            artifact_key: key.clone(),
            run_id: Some(stored_run.run_id),
            summary: evidence_summary.clone(),
            sinkhole_transcript: vec![
                "dns query: github.com".to_string(),
                "http request held in quarantine".to_string(),
            ],
        };
        self.store
            .0
            .record_evidence_bundle(evidence.clone())
            .await?;
        self.store
            .0
            .put_feed_record(HourlyFeedRecord {
                artifact: coordinate.clone(),
                status: ApprovalStatus::Pending,
                first_seen_at: Utc::now(),
                confidence: DetectionSeverity::High,
                trigger_category: evidence_summary.tripwires.first().copied(),
                recommended_action:
                    "source quarantined for Git verification; retry after the hold window or approve from the admin console"
                        .to_string(),
                approved_fallback: None,
            })
            .await?;

        let response = pending_response(source_url, &job, &identity.commit_id);
        Ok(GitPendingResult {
            response,
            source_url: source_url.to_string(),
            repo_root,
            cache_hit: cached,
            resolved_target: Some(identity.commit_id),
            raw_digest_sha256: Some(identity.raw_digest_sha256),
            normalized_digest_sha256: Some(identity.normalized_digest_sha256),
            quarantine_job: job,
            lab_run: Some(stored_run),
            evidence: Some(evidence),
            lifecycle_events,
        })
    }

    async fn ensure_mirror(
        &self,
        source_url: &str,
        upstream: &ResolvedGitUpstream,
        repo_root: &Path,
    ) -> Result<MirrorSyncResult, GitLaneError> {
        let parent = repo_root.parent().unwrap_or(&self.approved_root);
        fs::create_dir_all(parent).await?;
        if repo_root.join("objects").exists() {
            self.fetch_update(source_url, upstream, repo_root).await?;
            return Ok(MirrorSyncResult {
                upstream: upstream.clone(),
                mirror_created: false,
            });
        }

        self.clone_mirror(source_url, upstream, repo_root).await?;
        Ok(MirrorSyncResult {
            upstream: upstream.clone(),
            mirror_created: true,
        })
    }

    async fn clone_mirror(
        &self,
        source_url: &str,
        upstream: &ResolvedGitUpstream,
        repo_root: &Path,
    ) -> Result<(), GitLaneError> {
        let mut command = git_command_with_safe_directories(upstream, Some(repo_root));
        let output = command
            .arg("clone")
            .arg("--mirror")
            .arg(&upstream.fetch_url)
            .arg(repo_root)
            .output()
            .await?;
        if output.status.success() {
            Ok(())
        } else {
            Err(GitLaneError::Backend(format!(
                "git clone --mirror failed for source {source_url} via {} ({}) with {}",
                upstream.fetch_url,
                upstream.mode.label(),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    async fn fetch_update(
        &self,
        source_url: &str,
        upstream: &ResolvedGitUpstream,
        repo_root: &Path,
    ) -> Result<(), GitLaneError> {
        let mut command = git_command_with_safe_directories(upstream, Some(repo_root));
        let output = command
            .arg("-C")
            .arg(repo_root)
            .arg("remote")
            .arg("set-url")
            .arg("origin")
            .arg(&upstream.fetch_url)
            .output()
            .await?;
        if !output.status.success() {
            return Err(GitLaneError::Backend(format!(
                "git remote set-url failed for source {source_url} via {} ({}) with {}",
                upstream.fetch_url,
                upstream.mode.label(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let mut command = git_command_with_safe_directories(upstream, Some(repo_root));
        let output = command
            .arg("-C")
            .arg(repo_root)
            .arg("remote")
            .arg("update")
            .arg("--prune")
            .output()
            .await?;
        if output.status.success() {
            Ok(())
        } else {
            Err(GitLaneError::Backend(format!(
                "git remote update failed for source {source_url} via {} ({}) with {}",
                upstream.fetch_url,
                upstream.mode.label(),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    async fn ensure_quarantine_mirror(
        &self,
        source_url: &str,
        upstream: &ResolvedGitUpstream,
        repo_root: &Path,
    ) -> Result<ResolvedGitUpstream, GitLaneError> {
        let parent = repo_root.parent().unwrap_or(&self.quarantine_root);
        fs::create_dir_all(parent).await?;
        if repo_root.join("objects").exists() {
            self.fetch_update(source_url, upstream, repo_root).await?;
            Ok(upstream.clone())
        } else {
            self.clone_mirror(source_url, upstream, repo_root).await?;
            Ok(upstream.clone())
        }
    }

    pub async fn quarantine_job(
        &self,
        source_url: &str,
        selector: &str,
    ) -> Result<CacheEntry, GitLaneError> {
        let key = ArtifactKey {
            ecosystem: crate::Ecosystem::Git,
            source: source_url.to_string(),
            requested_selector: selector.to_string(),
            selector_kind: crate::SelectorKind::Floating,
        };
        let quarantine_dir = self.quarantine_root.join(safe_repo_dir(source_url));
        fs::create_dir_all(&quarantine_dir).await?;
        let entry = CacheEntry {
            artifact_key: key,
            domain: CacheDomain::Quarantine,
            storage_path: quarantine_dir.display().to_string(),
            created_at: chrono::Utc::now(),
            size_bytes: None,
            digest_sha256: crate::manifest::digest_for(source_url),
        };
        self.store.0.put_cache_entry(entry.clone()).await?;
        Ok(entry)
    }

    async fn inspect_repo(&self, repo_root: &Path) -> Result<GitRepoIdentity, GitLaneError> {
        let commit_id = git_capture(repo_root, &["rev-parse", "HEAD"]).await?;
        let tree_id = git_capture(repo_root, &["rev-parse", "HEAD^{tree}"]).await?;
        Ok(GitRepoIdentity {
            raw_digest_sha256: digest_for(&commit_id),
            normalized_digest_sha256: digest_for(&tree_id),
            commit_id,
            tree_id,
        })
    }
}

impl GitHttpBackend {
    pub async fn serve(
        project_root: &Path,
        repo_path: &str,
        method: &Method,
        request_url: &Url,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>, GitLaneError> {
        let body_bytes: Bytes = body;
        let mut child = Command::new("git")
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", project_root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REQUEST_METHOD", method.as_str())
            .env("QUERY_STRING", request_url.query().unwrap_or(""))
            .env(
                "PATH_INFO",
                format!("/{repo_path}{}", service_path(request_url.path())),
            )
            .env("CONTENT_LENGTH", body_bytes.len().to_string())
            .env(
                "CONTENT_TYPE",
                headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value: &http::HeaderValue| value.to_str().ok())
                    .unwrap_or("application/x-git-upload-pack-request"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&body_bytes).await?;
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_end(&mut stdout).await?;
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_end(&mut stderr).await?;
        }

        let status = child.wait().await?;
        if !status.success() {
            return Err(GitLaneError::Backend(format!(
                "git http-backend failed: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }

        Ok(parse_cgi_response(&stdout))
    }
}

#[derive(Debug, Clone)]
struct GitRequest {
    repo_path: String,
    service: Option<String>,
}

impl GitRequest {
    fn from_url(url: &Url) -> Result<Self, GitLaneError> {
        let full_path = url.path().trim_start_matches('/');
        let (repo_path, _service_path) = split_git_path(full_path);
        Ok(Self {
            repo_path,
            service: url
                .query_pairs()
                .find(|(key, _)| key == "service")
                .map(|(_, value)| value.to_string()),
        })
    }

    fn is_smart_http(&self) -> bool {
        self.repo_path.contains(".git") && self.service.as_deref() == Some("git-upload-pack")
    }
}

fn split_git_path(path: &str) -> (String, String) {
    if let Some((repo, remainder)) = path.split_once(".git/") {
        (
            format!("{repo}.git"),
            format!("/{}", remainder.trim_start_matches('/')),
        )
    } else {
        (path.to_string(), String::new())
    }
}

fn service_path(path: &str) -> String {
    if let Some((_, remainder)) = path.split_once(".git/") {
        format!("/{}", remainder.trim_start_matches('/'))
    } else {
        String::new()
    }
}

fn parse_cgi_response(bytes: &[u8]) -> Response<Full<Bytes>> {
    let response = String::from_utf8_lossy(bytes);
    let (header_block, body_offset) = if let Some(split) = response.find("\r\n\r\n") {
        (&response[..split], split + 4)
    } else if let Some(split) = response.find("\n\n") {
        (&response[..split], split + 2)
    } else {
        ("", 0)
    };

    let mut builder = Response::builder().status(StatusCode::OK);
    for line in header_block.lines() {
        if let Some(status) = line.strip_prefix("Status:") {
            if let Some(code) = status.split_whitespace().next() {
                if let Ok(code) = code.parse::<u16>() {
                    builder = builder.status(StatusCode::from_u16(code).unwrap_or(StatusCode::OK));
                }
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }
    let body = &bytes[body_offset.min(bytes.len())..];
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("cgi response")
}

fn pending_response(
    source_url: &str,
    job: &QuarantineJob,
    commit_id: &str,
) -> Response<Full<Bytes>> {
    let hold_minutes = job
        .hold_until
        .signed_duration_since(Utc::now())
        .num_minutes()
        .max(5);
    let message = format!(
        "ZitPit is verifying {source_url}\nstatus: pending_verification\nresolved_commit: {commit_id}\nretry_after_seconds: 300\nhint: this Git source is quarantined; check back in about {hold_minutes} minutes or approve it from the ZitPit admin console.\n"
    );
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/plain; charset=utf-8")
        .header("retry-after", "300")
        .header("x-zitpit-status", "pending_verification")
        .body(Full::new(Bytes::from(message)))
        .expect("pending response")
}

fn safe_repo_dir(source_url: &str) -> String {
    crate::manifest::digest_for(source_url)[..16].to_string()
}

fn git_command_with_safe_directories(
    upstream: &ResolvedGitUpstream,
    repo_root: Option<&Path>,
) -> Command {
    let mut command = Command::new("git");
    let safe_directories = git_safe_directories(upstream, repo_root);
    for (index, path) in safe_directories.iter().enumerate() {
        command.env(
            OsString::from(format!("GIT_CONFIG_KEY_{index}")),
            "safe.directory",
        );
        command.env(
            OsString::from(format!("GIT_CONFIG_VALUE_{index}")),
            path.as_os_str(),
        );
    }
    if !safe_directories.is_empty() {
        command.env(
            "GIT_CONFIG_COUNT",
            OsString::from(safe_directories.len().to_string()),
        );
    }
    command
}

fn git_safe_directories(upstream: &ResolvedGitUpstream, repo_root: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = seeded_mirror_path(upstream) {
        paths.push(path);
    }
    if let Some(repo_root) = repo_root {
        paths.push(repo_root.to_path_buf());
    }
    paths
}

fn seeded_mirror_path(upstream: &ResolvedGitUpstream) -> Option<PathBuf> {
    if upstream.mode != GitUpstreamMode::SeededMirror {
        return None;
    }
    upstream
        .fetch_url
        .strip_prefix("file://")
        .map(PathBuf::from)
}

fn upstream_fetch_detail(prefix: &str, source_url: &str, upstream: &ResolvedGitUpstream) -> String {
    match upstream.mode {
        GitUpstreamMode::SeededMirror => format!(
            "{prefix}: using seeded local mirror {} for source {source_url}",
            upstream.fetch_url
        ),
        GitUpstreamMode::Override => format!(
            "{prefix}: using override upstream {} for source {source_url}",
            upstream.fetch_url
        ),
        GitUpstreamMode::Direct => format!(
            "{prefix}: no seeded mirror found for source {source_url}; fetching live via {}",
            upstream.fetch_url
        ),
    }
}

impl GitUpstreamMode {
    fn label(self) -> &'static str {
        match self {
            GitUpstreamMode::SeededMirror => "seeded_mirror",
            GitUpstreamMode::Override => "override",
            GitUpstreamMode::Direct => "direct",
        }
    }
}

fn resolve_git_upstream(source_url: &str) -> Result<ResolvedGitUpstream, GitLaneError> {
    resolve_git_upstream_with_env(
        source_url,
        std::env::var("ZITPIT_GIT_UPSTREAM_ROOT").ok().as_deref(),
        std::env::var("ZITPIT_GIT_UPSTREAM_OVERRIDE")
            .ok()
            .as_deref(),
    )
}

fn resolve_git_upstream_with_env(
    source_url: &str,
    upstream_root: Option<&str>,
    upstream_override: Option<&str>,
) -> Result<ResolvedGitUpstream, GitLaneError> {
    let source = Url::parse(source_url)?;

    if let Some(root) = upstream_root {
        let path = source.path().trim_start_matches('/');
        let file_path = Path::new(root).join(path);
        if file_path.join("HEAD").exists() || file_path.join("objects").exists() {
            return Ok(ResolvedGitUpstream {
                fetch_url: format!("file://{}", file_path.display()),
                mode: GitUpstreamMode::SeededMirror,
            });
        }
    }

    if let Some(override_base) = upstream_override {
        let override_url = Url::parse(override_base)?;
        let mut rewritten = source.clone();
        rewritten.set_scheme(override_url.scheme()).map_err(|_| {
            GitLaneError::Backend(format!(
                "failed to apply override scheme {} to {source_url}",
                override_url.scheme()
            ))
        })?;
        rewritten
            .set_host(override_url.host_str())
            .map_err(|error| {
                GitLaneError::Backend(format!(
                    "failed to apply override host {:?} to {source_url}: {error}",
                    override_url.host_str()
                ))
            })?;
        rewritten.set_port(override_url.port()).map_err(|_| {
            GitLaneError::Backend(format!(
                "failed to apply override port {:?} to {source_url}",
                override_url.port()
            ))
        })?;
        return Ok(ResolvedGitUpstream {
            fetch_url: rewritten.to_string(),
            mode: GitUpstreamMode::Override,
        });
    }

    Ok(ResolvedGitUpstream {
        fetch_url: source.to_string(),
        mode: GitUpstreamMode::Direct,
    })
}

async fn git_capture(repo_root: &Path, args: &[&str]) -> Result<String, GitLaneError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        return Err(GitLaneError::Backend(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use bytes::Bytes;
    use http::{Method, header::HeaderMap};
    use http_body_util::BodyExt;
    use reqwest::Url;
    use tempfile::tempdir;

    use super::{
        GitSmartHttpAdapter, GitUpstreamMode, git_safe_directories, resolve_git_upstream_with_env,
        seeded_mirror_path, upstream_fetch_detail,
    };
    use crate::{
        ApprovalStatus, CacheDomain, CacheEntry, Ecosystem, ManifestRecord, MemoryStore,
        ProxyTraceKind, SelectorKind, StoreHandle,
    };
    use http::StatusCode;
    use zitpit_config::RuntimePaths;

    fn git(cmd: &mut Command) {
        let status = cmd.status().expect("run git");
        assert!(status.success(), "git command failed: {status:?}");
    }

    fn init_repo() -> (tempfile::TempDir, String) {
        let dir = tempdir().expect("tempdir");
        let work = dir.path().join("work");
        let bare = dir.path().join("repo.git");
        git(Command::new("git").arg("init").arg(&work));
        git(Command::new("git").current_dir(&work).args([
            "config",
            "user.email",
            "zitpit@example.com",
        ]));
        git(Command::new("git")
            .current_dir(&work)
            .args(["config", "user.name", "ZitPit"]));
        fs::write(work.join("README.md"), "hello").expect("write");
        git(Command::new("git").current_dir(&work).args(["add", "."]));
        git(Command::new("git")
            .current_dir(&work)
            .args(["commit", "-m", "initial"]));
        git(Command::new("git")
            .args(["clone", "--mirror"])
            .arg(&work)
            .arg(&bare));
        (dir, format!("file://{}", bare.display()))
    }

    fn write_seeded_mirror(root: &Path, source_url: &str) {
        let source = Url::parse(source_url).expect("source url");
        let repo_root = root.join(source.path().trim_start_matches('/'));
        fs::create_dir_all(repo_root.join("objects")).expect("objects dir");
        fs::write(repo_root.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    }

    fn test_safe_repo_dir(source_url: &str) -> String {
        crate::manifest::digest_for(source_url)[..16].to_string()
    }

    #[test]
    fn seeded_mirror_safe_directories_include_upstream_and_repo_root() {
        let upstream = super::ResolvedGitUpstream {
            fetch_url: "file:///var/lib/zitpit/git/upstream/jeppsontaylor/approved.git".to_string(),
            mode: GitUpstreamMode::SeededMirror,
        };
        let repo_root = Path::new("/var/lib/zitpit/git/approved/1234/jeppsontaylor/approved.git");

        assert_eq!(
            seeded_mirror_path(&upstream),
            Some(PathBuf::from(
                "/var/lib/zitpit/git/upstream/jeppsontaylor/approved.git"
            ))
        );
        assert_eq!(
            git_safe_directories(&upstream, Some(repo_root)),
            vec![
                PathBuf::from("/var/lib/zitpit/git/upstream/jeppsontaylor/approved.git"),
                PathBuf::from("/var/lib/zitpit/git/approved/1234/jeppsontaylor/approved.git"),
            ]
        );
    }

    #[tokio::test]
    async fn serves_git_http_backend_from_approved_mirror() {
        let (_dir, source_url) = init_repo();
        let temp = tempdir().expect("tempdir");
        let store = StoreHandle::connect_from_env().await.expect("store");
        store
            .0
            .upsert_manifest_record(ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: source_url.clone(),
                requested_selector: "refs/heads/main".to_string(),
                selector_kind: SelectorKind::Branch,
                resolved_target: "main".to_string(),
                raw_digest_sha256: crate::manifest::digest_for("raw"),
                normalized_digest_sha256: crate::manifest::digest_for("normalized"),
                status: ApprovalStatus::Approved,
                first_seen_at: chrono::Utc::now(),
                hold_until: None,
                approved_at: Some(chrono::Utc::now()),
                fallback: None,
                detector_refs: vec![],
                metadata: BTreeMap::new(),
            })
            .await
            .expect("seed manifest");

        let adapter = GitSmartHttpAdapter::with_paths(
            store.clone(),
            RuntimePaths::new(temp.path().join("state")),
        );
        let request_url =
            Url::parse("https://git.example/owner/repo.git/info/refs?service=git-upload-pack")
                .expect("url");
        let result = adapter
            .handle(
                &source_url,
                &request_url,
                &Method::GET,
                &HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .expect("git handle");
        let body = result
            .response
            .into_body()
            .collect()
            .await
            .expect("collect body");
        let body = body.to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("git-upload-pack"));
    }

    #[tokio::test]
    async fn unknown_git_source_is_quarantined_hashed_and_scheduled() {
        let (_repo_dir, source_url) = init_repo();
        let temp = tempdir().expect("tempdir");
        let runtime = RuntimePaths::new(temp.path().join("state"));
        runtime.ensure_dirs().expect("runtime dirs");
        let store = StoreHandle::connect_from_env().await.expect("store");
        let adapter = GitSmartHttpAdapter::with_paths(store.clone(), runtime);
        let request_url =
            Url::parse("https://git.example/owner/repo.git/info/refs?service=git-upload-pack")
                .expect("url");
        let result = adapter
            .acquire_unknown_source(&source_url, &request_url)
            .await
            .expect("acquire unknown source");
        assert_eq!(result.response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let cache = store
            .0
            .get_cache_entry(
                &crate::ArtifactKey {
                    ecosystem: crate::Ecosystem::Git,
                    source: source_url.clone(),
                    requested_selector: "git-smart-http".to_string(),
                    selector_kind: crate::SelectorKind::Floating,
                },
                CacheDomain::Quarantine,
            )
            .await
            .expect("cache lookup");
        assert!(cache.is_some());
        assert!(result.raw_digest_sha256.is_some());
        assert!(result.normalized_digest_sha256.is_some());
        assert!(result.lab_run.is_some());
        assert!(result.evidence.is_some());
        assert!(
            result
                .lifecycle_events
                .iter()
                .any(|event| { matches!(event.kind, ProxyTraceKind::HashCompleted) })
        );
        assert!(
            store
                .0
                .list_manifest_records()
                .await
                .expect("manifest records")
                .iter()
                .any(|record| {
                    record.source == source_url && record.status == ApprovalStatus::Pending
                })
        );
    }

    #[tokio::test]
    async fn approved_git_source_promotes_hot_cache_after_disk_hit() {
        let (_repo_dir, source_url) = init_repo();
        let temp = tempdir().expect("tempdir");
        let runtime = RuntimePaths::new(temp.path().join("state"));
        runtime.ensure_dirs().expect("runtime dirs");
        let store = StoreHandle::from_memory(MemoryStore::seeded().await);

        store
            .0
            .upsert_manifest_record(ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: source_url.clone(),
                requested_selector: "refs/heads/main".to_string(),
                selector_kind: SelectorKind::Branch,
                resolved_target: "main".to_string(),
                raw_digest_sha256: crate::manifest::digest_for("raw"),
                normalized_digest_sha256: crate::manifest::digest_for("normalized"),
                status: ApprovalStatus::Approved,
                first_seen_at: chrono::Utc::now(),
                hold_until: None,
                approved_at: Some(chrono::Utc::now()),
                fallback: None,
                detector_refs: vec![],
                metadata: BTreeMap::new(),
            })
            .await
            .expect("seed manifest");

        let project_root = runtime
            .git_approved_root
            .join(test_safe_repo_dir(&source_url));
        let repo_root = project_root.join("owner/repo.git");
        fs::create_dir_all(repo_root.parent().expect("repo parent")).expect("project root");
        git(Command::new("git")
            .args(["clone", "--mirror"])
            .arg(source_url.trim_start_matches("file://"))
            .arg(&repo_root));

        store
            .0
            .put_cache_entry(CacheEntry {
                artifact_key: crate::ArtifactKey {
                    ecosystem: Ecosystem::Git,
                    source: source_url.clone(),
                    requested_selector: "git-smart-http".to_string(),
                    selector_kind: SelectorKind::Floating,
                },
                domain: CacheDomain::Approved,
                storage_path: repo_root.display().to_string(),
                created_at: chrono::Utc::now(),
                size_bytes: None,
                digest_sha256: crate::manifest::digest_for("approved"),
            })
            .await
            .expect("approved cache");

        let adapter = GitSmartHttpAdapter::with_paths_and_hold_duration_and_hot_cache_capacity(
            store.clone(),
            runtime,
            24,
            4,
        );
        let request_url =
            Url::parse("https://git.example/owner/repo.git/info/refs?service=git-upload-pack")
                .expect("url");

        let first = adapter
            .handle(
                &source_url,
                &request_url,
                &Method::GET,
                &HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .expect("first approved request");
        assert!(!first.hot_cache_hit);
        assert!(first.cache_hit);

        let second = adapter
            .handle(
                &source_url,
                &request_url,
                &Method::GET,
                &HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .expect("second approved request");
        assert!(second.hot_cache_hit);
        assert!(second.cache_hit);
        assert!(
            second
                .lifecycle_events
                .iter()
                .any(|event| matches!(event.kind, ProxyTraceKind::HotCacheHit))
        );

        let first_body = first
            .response
            .into_body()
            .collect()
            .await
            .expect("first body")
            .to_bytes();
        let second_body = second
            .response
            .into_body()
            .collect()
            .await
            .expect("second body")
            .to_bytes();
        assert_eq!(first_body, second_body);
    }

    #[test]
    fn resolve_git_upstream_prefers_seeded_local_mirror_when_present() {
        let temp = tempdir().expect("tempdir");
        let source_url = "http://github.com/jeppsontaylor/approved.git";
        write_seeded_mirror(temp.path(), source_url);

        let upstream = resolve_git_upstream_with_env(source_url, temp.path().to_str(), None)
            .expect("resolve upstream");

        assert_eq!(upstream.mode, GitUpstreamMode::SeededMirror);
        assert!(upstream.fetch_url.starts_with("file://"));
        assert!(upstream.fetch_url.contains("/jeppsontaylor/approved.git"));
    }

    #[test]
    fn resolve_git_upstream_preserves_live_source_when_seeded_mirror_is_missing() {
        let temp = tempdir().expect("tempdir");
        let source_url = "http://github.com/axios/axios.git";

        let upstream = resolve_git_upstream_with_env(source_url, temp.path().to_str(), None)
            .expect("resolve upstream");

        assert_eq!(upstream.mode, GitUpstreamMode::Direct);
        assert_eq!(upstream.fetch_url, source_url);
    }

    #[test]
    fn resolve_git_upstream_uses_override_when_no_seeded_mirror_exists() {
        let temp = tempdir().expect("tempdir");
        let source_url = "http://github.com/axios/axios.git";

        let upstream = resolve_git_upstream_with_env(
            source_url,
            temp.path().to_str(),
            Some("https://mirror.internal:8443"),
        )
        .expect("resolve upstream");

        assert_eq!(upstream.mode, GitUpstreamMode::Override);
        assert_eq!(
            upstream.fetch_url,
            "https://mirror.internal:8443/axios/axios.git"
        );
    }

    #[test]
    fn upstream_fetch_detail_reports_live_fetch_without_seeded_mirror() {
        let upstream = resolve_git_upstream_with_env(
            "http://github.com/axios/axios.git",
            Some("/tmp/nonexistent-zitpit-upstream"),
            None,
        )
        .expect("resolve upstream");

        let detail = upstream_fetch_detail(
            "quarantine acquisition started",
            "http://github.com/axios/axios.git",
            &upstream,
        );

        assert!(detail.contains("no seeded mirror found"));
        assert!(detail.contains("fetching live via http://github.com/axios/axios.git"));
    }
}
