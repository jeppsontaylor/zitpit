use std::{net::SocketAddr, time::Duration};

use reqwest::Client;
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};
use zitpit_config::RuntimePaths;
use zitpit_core::{
    ArtifactBroker, FirecrackerOrchestrator, ManifestSigner, MemoryStore, StoreHandle,
};

pub struct ServiceHandle {
    pub name: &'static str,
    pub addr: SocketAddr,
    join: JoinHandle<()>,
}

impl ServiceHandle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        self.join.abort();
    }
}

pub struct TestHarness {
    pub tempdir: TempDir,
    pub paths: RuntimePaths,
    pub store: StoreHandle,
    pub client: Client,
    pub proxy: ServiceHandle,
    pub manifest: ServiceHandle,
    pub lab: ServiceHandle,
    pub watch: ServiceHandle,
    pub node_agent: ServiceHandle,
}

pub async fn seeded_store() -> StoreHandle {
    StoreHandle::from_memory(MemoryStore::seeded().await)
}

pub fn temp_runtime_paths(prefix: &str) -> (TempDir, RuntimePaths) {
    let tempdir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("tempdir");
    let paths = RuntimePaths::new(tempdir.path().join("state"));
    (tempdir, paths)
}

pub async fn spawn() -> TestHarness {
    let (tempdir, paths) = temp_runtime_paths("zitpit-harness");
    paths.ensure_dirs().expect("create runtime dirs");

    let store = seeded_store().await;
    let client = Client::builder().build().expect("build client");

    let policy = store
        .0
        .get_policy_snapshot()
        .await
        .expect("policy")
        .expect("seeded policy")
        .config;

    let proxy_state = zitpit_gateway::AppState {
        store: store.clone(),
        broker: ArtifactBroker::new(store.clone(), policy.clone()),
        git_adapter: zitpit_core::GitSmartHttpAdapter::with_paths(store.clone(), paths.clone()),
        lockdown_mode: std::sync::Arc::new(std::sync::RwLock::new(policy.lockdown_mode)),
        policy,
        http_client: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("proxy client"),
    };
    let manifest_state = zitpit_manifest::AppState {
        store: store.clone(),
        signer: ManifestSigner::from_seed([7; 32]),
    };
    let lab_state = zitpit_lab::AppState {
        store: store.clone(),
        orchestrator: FirecrackerOrchestrator::with_paths(paths.clone()),
    };
    let watch_state = zitpit_watch::AppState {
        store: store.clone(),
    };
    let node_state = zitpit_node_agent::AppState {
        store: store.clone(),
    };

    let proxy = spawn_service("proxy", zitpit_gateway::build_admin_app(proxy_state)).await;
    let manifest = spawn_service("manifest", zitpit_manifest::build_app(manifest_state)).await;
    let lab = spawn_service("lab", zitpit_lab::build_app(lab_state)).await;
    let watch = spawn_service("watch", zitpit_watch::build_app(watch_state)).await;
    let node_agent = spawn_service("node-agent", zitpit_node_agent::build_app(node_state)).await;

    for handle in [&proxy, &manifest, &lab, &watch, &node_agent] {
        wait_ready(&client, &handle.base_url()).await;
    }

    TestHarness {
        tempdir,
        paths,
        store,
        client,
        proxy,
        manifest,
        lab,
        watch,
        node_agent,
    }
}

async fn spawn_service(name: &'static str, app: axum::Router) -> ServiceHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let join = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve app");
    });
    ServiceHandle { name, addr, join }
}

async fn wait_ready(client: &Client, base_url: &str) {
    let url = format!("{base_url}/healthz");
    for _ in 0..100 {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                return;
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("service at {base_url} did not become healthy");
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap, fs, net::SocketAddr, path::PathBuf, process::Command, time::Instant,
    };

    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use chrono::Utc;
    use reqwest::Proxy;
    use serde::Deserialize;
    use serial_test::serial;
    use uuid::Uuid;
    use zitpit_core::{
        ApprovalStatus, ArtifactBroker, ArtifactCoordinate, ArtifactKey, DetonationPersona,
        DetonationScenario, Ecosystem, EvidenceEvent, GitHttpBackend, QuarantineStatus,
        RequestObservation, SelectorHint, SelectorKind, TripwireEvaluator, TripwireKind, Verdict,
    };

    use super::*;

    #[derive(Debug, Deserialize)]
    struct HoneypotFixtureCase {
        name: String,
        artifact: ArtifactCoordinate,
        persona: DetonationPersona,
        scenario: DetonationScenario,
        events: Vec<EvidenceEvent>,
        expected_verdict: Verdict,
        expected_tripwires: Vec<TripwireKind>,
    }

    #[tokio::test]
    async fn harness_spawns_all_services_and_serves_health() {
        let harness = spawn().await;
        for url in [
            harness.proxy.base_url(),
            harness.manifest.base_url(),
            harness.lab.base_url(),
            harness.watch.base_url(),
            harness.node_agent.base_url(),
        ] {
            let response = harness
                .client
                .get(format!("{url}/healthz"))
                .send()
                .await
                .expect("health request");
            assert!(response.status().is_success());
        }
    }

    #[tokio::test]
    async fn manifest_promote_and_watch_feed_round_trip() {
        let harness = spawn().await;
        let coordinate = ArtifactCoordinate {
            ecosystem: Ecosystem::Git,
            source: "https://github.com/acme/widget.git".to_string(),
            requested_selector: "refs/heads/main".to_string(),
            selector_kind: SelectorKind::Branch,
        };

        let promote = harness
            .client
            .post(format!(
                "{}/api/v1/manifest/promote",
                harness.manifest.base_url()
            ))
            .json(&serde_json::json!({
                "coordinate": coordinate,
                "resolved_target": "abc123",
                "metadata": { "tree_id": "tree-1" }
            }))
            .send()
            .await
            .expect("promote request");
        assert!(promote.status().is_success());

        let feed = harness
            .client
            .get(format!("{}/api/v1/feed/hourly", harness.watch.base_url()))
            .send()
            .await
            .expect("feed request")
            .json::<serde_json::Value>()
            .await
            .expect("feed json");
        assert!(feed.as_array().is_some());
    }

    #[tokio::test]
    async fn node_agent_apply_bootstrap_writes_files() {
        let harness = spawn().await;
        let target_root = harness.tempdir.path().join("node-root");
        let mut request: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/attacks/node-apply-bootstrap.json"
        ))
        .expect("request fixture");
        request["target_root"] = serde_json::Value::String(target_root.to_string_lossy().into());
        let response = harness
            .client
            .post(format!(
                "{}/api/v1/node/bootstrap/apply",
                harness.node_agent.base_url()
            ))
            .json(&request)
            .send()
            .await
            .expect("bootstrap apply");
        assert!(response.status().is_success());
        assert!(
            harness
                .tempdir
                .path()
                .join("node-root/usr/local/share/ca-certificates/zitpit-ca.crt")
                .exists()
        );
    }

    #[tokio::test]
    async fn proxy_and_lab_handle_attack_samples() {
        let harness = spawn().await;
        let observation: RequestObservation =
            serde_json::from_str(include_str!("../fixtures/attacks/git-connect.json"))
                .expect("attack fixture");
        let classify = harness
            .client
            .post(format!("{}/api/v1/classify", harness.proxy.base_url()))
            .json(&observation)
            .send()
            .await
            .expect("classify");
        let classify_json = classify.json::<serde_json::Value>().await.expect("json");
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/golden/git-connect-classification.json"
        ))
        .expect("golden fixture");
        assert_eq!(classify_json, golden);

        let run = harness
            .client
            .post(format!("{}/api/v1/jobs/run", harness.lab.base_url()))
            .json(&serde_json::json!({
                "ecosystem": "archive",
                "source": "https://github.com/acme/tool/releases/download/v2.0.0/tool-linux-amd64.tar.gz",
                "requested_selector": "v2.0.0",
                "selector_kind": "tag"
            }))
            .send()
            .await
            .expect("lab run");
        assert!(run.status().is_success());

        let evidence = harness
            .client
            .get(format!("{}/api/v1/evidence", harness.lab.base_url()))
            .send()
            .await
            .expect("evidence")
            .json::<serde_json::Value>()
            .await
            .expect("evidence json");
        assert!(
            evidence
                .as_array()
                .map(|items| !items.is_empty())
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn broker_quarantine_and_approval_round_trip() {
        let harness = spawn().await;
        let policy = harness
            .store
            .0
            .get_policy_snapshot()
            .await
            .expect("policy lookup")
            .expect("seeded policy")
            .config;
        let broker = ArtifactBroker::new(harness.store.clone(), policy);
        let coordinate = ArtifactCoordinate {
            ecosystem: Ecosystem::Git,
            source: "https://github.com/jeppsontaylor/unknown.git".to_string(),
            requested_selector: "deadbeef".to_string(),
            selector_kind: SelectorKind::ExactCommit,
        };
        let decision = broker
            .decide(
                RequestObservation {
                    request_id: Uuid::new_v4(),
                    observed_at: Utc::now(),
                    scheme: "https".to_string(),
                    authority: "github.com".to_string(),
                    path: "/jeppsontaylor/unknown.git".to_string(),
                    method: "GET".to_string(),
                    user_agent: Some("git/2.47".to_string()),
                    headers: BTreeMap::new(),
                    selector_hint: Some(SelectorHint {
                        requested: "deadbeef".to_string(),
                        kind: SelectorKind::ExactCommit,
                    }),
                },
                Some(coordinate.clone()),
            )
            .await
            .expect("decision");
        assert_eq!(decision.action, zitpit_core::ProxyAction::Pending);

        let captured = harness
            .store
            .0
            .list_captured_requests()
            .await
            .expect("captured requests");
        assert_eq!(captured.len(), 1);
        assert!(captured[0].stored_body);

        let quarantine = harness
            .store
            .0
            .get_quarantine_job(&ArtifactKey::from(&coordinate))
            .await
            .expect("quarantine lookup")
            .expect("quarantine job");
        assert_eq!(quarantine.status, QuarantineStatus::Pending);

        broker
            .promote_artifact(
                coordinate.clone(),
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                BTreeMap::from([("tree_id".to_string(), "tree-unknown".to_string())]),
            )
            .await
            .expect("promote artifact");

        let records = harness
            .store
            .0
            .list_manifest_records()
            .await
            .expect("manifest records");
        assert!(records.iter().any(|record| {
            record.source == coordinate.source
                && record.requested_selector == coordinate.requested_selector
                && record.status == ApprovalStatus::Approved
        }));
    }

    #[tokio::test]
    async fn proxy_fixture_endpoint_creates_visible_quarantine_job() {
        let harness = spawn().await;
        let response = harness
            .client
            .get(format!(
                "{}/api/v1/fixtures/npm-pending",
                harness.proxy.base_url()
            ))
            .send()
            .await
            .expect("fixture endpoint");
        assert!(response.status().is_success());
        let payload = response.json::<serde_json::Value>().await.expect("json");
        assert_eq!(payload["decision"]["action"], "fallback");
        assert_eq!(payload["artifact_key"]["source"], "npm:lodash");
        assert_eq!(payload["decision"]["manifest_status"], "approved");
    }

    #[tokio::test]
    #[serial]
    async fn real_git_request_through_proxy_records_full_trace() {
        let (tempdir, paths) = temp_runtime_paths("zitpit-git-flow");
        paths.ensure_dirs().expect("runtime dirs");

        let upstream_repo_root = tempdir.path().join("upstream/acme/proxy-demo.git");
        let upstream_repo_parent = upstream_repo_root
            .parent()
            .expect("upstream parent")
            .to_path_buf();
        fs::create_dir_all(&upstream_repo_parent).expect("upstream parent");
        let workdir = tempdir.path().join("work");
        init_git_repo(&workdir, &upstream_repo_root);

        let upstream_port = free_tcp_port();
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        let upstream_state = GitUpstreamState {
            project_root: tempdir.path().join("upstream"),
            repo_path: "acme/proxy-demo.git".to_string(),
        };
        let upstream_handle = tokio::spawn(spawn_git_upstream(upstream_addr, upstream_state));
        wait_tcp(upstream_addr).await;

        unsafe {
            std::env::set_var(
                "ZITPIT_GIT_UPSTREAM_OVERRIDE",
                format!("http://127.0.0.1:{upstream_port}/"),
            );
        }

        let store = seeded_store().await;
        let source_url = "http://github.com/acme/proxy-demo.git".to_string();
        store
            .0
            .upsert_manifest_record(zitpit_core::ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: source_url.clone(),
                requested_selector: "git-smart-http".to_string(),
                selector_kind: SelectorKind::Floating,
                resolved_target: "refs/heads/main".to_string(),
                raw_digest_sha256: zitpit_core::manifest::digest_for("raw"),
                normalized_digest_sha256: zitpit_core::manifest::digest_for("normalized"),
                status: ApprovalStatus::Approved,
                first_seen_at: Utc::now(),
                hold_until: None,
                approved_at: Some(Utc::now()),
                fallback: None,
                detector_refs: vec!["report://test/git".to_string()],
                metadata: BTreeMap::new(),
            })
            .await
            .expect("seed approved manifest");

        let policy = store
            .0
            .get_policy_snapshot()
            .await
            .expect("policy")
            .expect("seeded policy")
            .config;
        let proxy_port = free_tcp_port();
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        let proxy_state = zitpit_gateway::AppState {
            store: store.clone(),
            broker: ArtifactBroker::new(store.clone(), policy.clone()),
            git_adapter: zitpit_core::GitSmartHttpAdapter::with_paths(store.clone(), paths),
            lockdown_mode: std::sync::Arc::new(std::sync::RwLock::new(policy.lockdown_mode)),
            policy: zitpit_core::PolicyConfig {
                proxy_port,
                ..policy
            },
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("proxy client"),
        };
        let proxy_handle =
            tokio::spawn(zitpit_gateway::run_proxy_listener(proxy_addr, proxy_state));
        wait_tcp(proxy_addr).await;

        let client = reqwest::Client::builder()
            .proxy(Proxy::http(format!("http://{proxy_addr}")).expect("proxy"))
            .build()
            .expect("reqwest client");
        let response = client
            .get("http://github.com/acme/proxy-demo.git/info/refs?service=git-upload-pack")
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("proxy git request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.expect("body");
        assert!(body.contains("git-upload-pack"));

        let requests = store.0.list_captured_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let trace = &requests[0].trace;
        assert!(trace.peer_addr.is_some());
        assert!(trace.local_addr.is_some());
        assert!(trace.decision_at.is_some());
        assert!(trace.completed_at.is_some());
        assert!(
            trace
                .events
                .iter()
                .any(|event| matches!(event.kind, zitpit_core::ProxyTraceKind::RoutedToGitAdapter))
        );
        assert!(
            trace
                .events
                .iter()
                .any(|event| matches!(event.kind, zitpit_core::ProxyTraceKind::Completed))
        );
        assert!(trace.completed_at >= trace.decision_at);

        proxy_handle.abort();
        upstream_handle.abort();
        unsafe {
            std::env::remove_var("ZITPIT_GIT_UPSTREAM_OVERRIDE");
        }
    }

    #[tokio::test]
    #[serial]
    async fn unknown_git_request_through_proxy_creates_quarantine_lab_and_feed() {
        let (tempdir, paths) = temp_runtime_paths("zitpit-git-pending");
        paths.ensure_dirs().expect("runtime dirs");

        let upstream_repo_root = tempdir.path().join("upstream/acme/unknown-demo.git");
        let upstream_repo_parent = upstream_repo_root
            .parent()
            .expect("upstream parent")
            .to_path_buf();
        fs::create_dir_all(&upstream_repo_parent).expect("upstream parent");
        let workdir = tempdir.path().join("work");
        init_git_repo(&workdir, &upstream_repo_root);

        let upstream_port = free_tcp_port();
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        let upstream_state = GitUpstreamState {
            project_root: tempdir.path().join("upstream"),
            repo_path: "acme/unknown-demo.git".to_string(),
        };
        let upstream_handle = tokio::spawn(spawn_git_upstream(upstream_addr, upstream_state));
        wait_tcp(upstream_addr).await;

        unsafe {
            std::env::set_var(
                "ZITPIT_GIT_UPSTREAM_OVERRIDE",
                format!("http://127.0.0.1:{upstream_port}/"),
            );
        }

        let store = seeded_store().await;
        let policy = store
            .0
            .get_policy_snapshot()
            .await
            .expect("policy")
            .expect("seeded policy")
            .config;
        let proxy_port = free_tcp_port();
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        let proxy_state = zitpit_gateway::AppState {
            store: store.clone(),
            broker: ArtifactBroker::new(store.clone(), policy.clone()),
            git_adapter: zitpit_core::GitSmartHttpAdapter::with_paths_and_hold_duration(
                store.clone(),
                paths,
                policy.hold_duration_hours,
            ),
            lockdown_mode: std::sync::Arc::new(std::sync::RwLock::new(policy.lockdown_mode)),
            policy: zitpit_core::PolicyConfig {
                proxy_port,
                ..policy
            },
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("proxy client"),
        };
        let proxy_handle =
            tokio::spawn(zitpit_gateway::run_proxy_listener(proxy_addr, proxy_state));
        wait_tcp(proxy_addr).await;

        let client = reqwest::Client::builder()
            .proxy(Proxy::http(format!("http://{proxy_addr}")).expect("proxy"))
            .build()
            .expect("reqwest client");
        let response = client
            .get("http://github.com/acme/unknown-demo.git/info/refs?service=git-upload-pack")
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("proxy git request");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("x-zitpit-status")
                .and_then(|value| value.to_str().ok()),
            Some("pending_verification")
        );
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("300")
        );
        let body = response.text().await.expect("body");
        assert!(body.contains("pending_verification"));
        assert!(body.contains("check back"));
        assert!(body.contains("retry_after_seconds: 300"));

        let requests = store.0.list_captured_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let trace = &requests[0].trace;
        assert_eq!(
            requests[0].client_outcome,
            Some(zitpit_core::ClientVisibleOutcome::TemporaryFailure)
        );
        for kind in [
            zitpit_core::ProxyTraceKind::FetchStarted,
            zitpit_core::ProxyTraceKind::FetchCompleted,
            zitpit_core::ProxyTraceKind::HashStarted,
            zitpit_core::ProxyTraceKind::HashCompleted,
            zitpit_core::ProxyTraceKind::QuarantineCreated,
            zitpit_core::ProxyTraceKind::LabScheduled,
            zitpit_core::ProxyTraceKind::ResponseSent,
        ] {
            assert!(
                trace.events.iter().any(|event| event.kind == kind),
                "missing trace event {kind:?}"
            );
        }

        assert!(
            store
                .0
                .list_quarantine_jobs()
                .await
                .expect("jobs")
                .iter()
                .any(|job| job.artifact_key.source == "http://github.com/acme/unknown-demo.git")
        );
        assert!(
            store
                .0
                .list_lab_runs()
                .await
                .expect("runs")
                .iter()
                .any(|run| run.artifact_key.source == "http://github.com/acme/unknown-demo.git")
        );
        assert!(
            store
                .0
                .list_evidence_bundles()
                .await
                .expect("evidence")
                .iter()
                .any(|bundle| bundle.artifact_key.source
                    == "http://github.com/acme/unknown-demo.git")
        );
        assert!(
            store
                .0
                .list_feed_records()
                .await
                .expect("feed")
                .iter()
                .any(|record| record.artifact.source == "http://github.com/acme/unknown-demo.git")
        );

        proxy_handle.abort();
        upstream_handle.abort();
        unsafe {
            std::env::remove_var("ZITPIT_GIT_UPSTREAM_OVERRIDE");
        }
    }

    #[tokio::test]
    #[serial]
    async fn approved_git_second_request_hits_cache_and_is_faster() {
        let (tempdir, paths) = temp_runtime_paths("zitpit-git-cache");
        paths.ensure_dirs().expect("runtime dirs");

        let upstream_repo_root = tempdir.path().join("upstream/acme/cache-demo.git");
        let upstream_repo_parent = upstream_repo_root
            .parent()
            .expect("upstream parent")
            .to_path_buf();
        fs::create_dir_all(&upstream_repo_parent).expect("upstream parent");
        let workdir = tempdir.path().join("work");
        init_git_repo(&workdir, &upstream_repo_root);

        let upstream_port = free_tcp_port();
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        let upstream_state = GitUpstreamState {
            project_root: tempdir.path().join("upstream"),
            repo_path: "acme/cache-demo.git".to_string(),
        };
        let upstream_handle = tokio::spawn(spawn_git_upstream(upstream_addr, upstream_state));
        wait_tcp(upstream_addr).await;

        unsafe {
            std::env::set_var(
                "ZITPIT_GIT_UPSTREAM_OVERRIDE",
                format!("http://127.0.0.1:{upstream_port}/"),
            );
        }

        let store = seeded_store().await;
        let source_url = "http://github.com/acme/cache-demo.git".to_string();
        store
            .0
            .upsert_manifest_record(zitpit_core::ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: source_url.clone(),
                requested_selector: "git-smart-http".to_string(),
                selector_kind: SelectorKind::Floating,
                resolved_target: "refs/heads/main".to_string(),
                raw_digest_sha256: zitpit_core::manifest::digest_for("raw"),
                normalized_digest_sha256: zitpit_core::manifest::digest_for("normalized"),
                status: ApprovalStatus::Approved,
                first_seen_at: Utc::now(),
                hold_until: None,
                approved_at: Some(Utc::now()),
                fallback: None,
                detector_refs: vec!["report://test/git-cache".to_string()],
                metadata: BTreeMap::new(),
            })
            .await
            .expect("seed approved manifest");

        let policy = store
            .0
            .get_policy_snapshot()
            .await
            .expect("policy")
            .expect("seeded policy")
            .config;
        let proxy_port = free_tcp_port();
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        let proxy_state = zitpit_gateway::AppState {
            store: store.clone(),
            broker: ArtifactBroker::new(store.clone(), policy.clone()),
            git_adapter: zitpit_core::GitSmartHttpAdapter::with_paths_and_hold_duration(
                store.clone(),
                paths,
                policy.hold_duration_hours,
            ),
            lockdown_mode: std::sync::Arc::new(std::sync::RwLock::new(policy.lockdown_mode)),
            policy: zitpit_core::PolicyConfig {
                proxy_port,
                ..policy
            },
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("proxy client"),
        };
        let proxy_handle =
            tokio::spawn(zitpit_gateway::run_proxy_listener(proxy_addr, proxy_state));
        wait_tcp(proxy_addr).await;

        let client = reqwest::Client::builder()
            .proxy(Proxy::http(format!("http://{proxy_addr}")).expect("proxy"))
            .build()
            .expect("reqwest client");
        let url = "http://github.com/acme/cache-demo.git/info/refs?service=git-upload-pack";

        let first_start = Instant::now();
        let first_response = client
            .get(url)
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("first request");
        let first_elapsed = first_start.elapsed();
        assert_eq!(first_response.status(), StatusCode::OK);
        let _ = first_response.text().await.expect("first body");

        let second_start = Instant::now();
        let second_response = client
            .get(url)
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("second request");
        let second_elapsed = second_start.elapsed();
        assert_eq!(second_response.status(), StatusCode::OK);
        let _ = second_response.text().await.expect("second body");

        let requests = store.0.list_captured_requests().await.expect("requests");
        let cache_requests = requests
            .into_iter()
            .filter(|request| {
                request
                    .artifact_key
                    .as_ref()
                    .map(|key| key.source == source_url)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        assert_eq!(cache_requests.len(), 2);
        assert!(
            cache_requests[0]
                .trace
                .events
                .iter()
                .any(|event| event.kind == zitpit_core::ProxyTraceKind::FetchStarted)
        );
        assert!(
            cache_requests[1]
                .trace
                .events
                .iter()
                .any(|event| event.kind == zitpit_core::ProxyTraceKind::CacheHit)
        );
        assert!(second_elapsed <= first_elapsed);

        proxy_handle.abort();
        upstream_handle.abort();
        unsafe {
            std::env::remove_var("ZITPIT_GIT_UPSTREAM_OVERRIDE");
        }
    }

    #[tokio::test]
    #[serial]
    async fn pending_git_request_can_be_approved_and_retried() {
        let (tempdir, paths) = temp_runtime_paths("zitpit-git-approve-retry");
        paths.ensure_dirs().expect("runtime dirs");

        let upstream_repo_root = tempdir.path().join("upstream/acme/retry-demo.git");
        let upstream_repo_parent = upstream_repo_root
            .parent()
            .expect("upstream parent")
            .to_path_buf();
        fs::create_dir_all(&upstream_repo_parent).expect("upstream parent");
        let workdir = tempdir.path().join("work");
        init_git_repo(&workdir, &upstream_repo_root);

        let upstream_port = free_tcp_port();
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        let upstream_state = GitUpstreamState {
            project_root: tempdir.path().join("upstream"),
            repo_path: "acme/retry-demo.git".to_string(),
        };
        let upstream_handle = tokio::spawn(spawn_git_upstream(upstream_addr, upstream_state));
        wait_tcp(upstream_addr).await;

        unsafe {
            std::env::set_var(
                "ZITPIT_GIT_UPSTREAM_OVERRIDE",
                format!("http://127.0.0.1:{upstream_port}/"),
            );
        }

        let store = seeded_store().await;
        let policy = store
            .0
            .get_policy_snapshot()
            .await
            .expect("policy")
            .expect("seeded policy")
            .config;
        let broker = ArtifactBroker::new(store.clone(), policy.clone());
        let proxy_port = free_tcp_port();
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        let proxy_state = zitpit_gateway::AppState {
            store: store.clone(),
            broker: broker.clone(),
            git_adapter: zitpit_core::GitSmartHttpAdapter::with_paths_and_hold_duration(
                store.clone(),
                paths,
                policy.hold_duration_hours,
            ),
            lockdown_mode: std::sync::Arc::new(std::sync::RwLock::new(policy.lockdown_mode)),
            policy: zitpit_core::PolicyConfig {
                proxy_port,
                ..policy
            },
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("proxy client"),
        };
        let proxy_handle =
            tokio::spawn(zitpit_gateway::run_proxy_listener(proxy_addr, proxy_state));
        wait_tcp(proxy_addr).await;

        let client = reqwest::Client::builder()
            .proxy(Proxy::http(format!("http://{proxy_addr}")).expect("proxy"))
            .build()
            .expect("reqwest client");
        let url = "http://github.com/acme/retry-demo.git/info/refs?service=git-upload-pack";
        let first = client
            .get(url)
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("first request");
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);

        let resolved_target = run_capture(
            Command::new("git")
                .arg("--git-dir")
                .arg(&upstream_repo_root)
                .args(["rev-parse", "HEAD"]),
        );
        broker
            .promote_artifact(
                ArtifactCoordinate {
                    ecosystem: Ecosystem::Git,
                    source: "http://github.com/acme/retry-demo.git".to_string(),
                    requested_selector: "git-smart-http".to_string(),
                    selector_kind: SelectorKind::Floating,
                },
                resolved_target.trim().to_string(),
                BTreeMap::from([("approved_by".to_string(), "test".to_string())]),
            )
            .await
            .expect("promote");

        let second = client
            .get(url)
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("second request");
        assert_eq!(second.status(), StatusCode::OK);
        let body = second.text().await.expect("body");
        assert!(body.contains("git-upload-pack"));

        let requests = store.0.list_captured_requests().await.expect("requests");
        let retry_requests = requests
            .iter()
            .filter(|request| {
                request
                    .artifact_key
                    .as_ref()
                    .map(|key| key.source == "http://github.com/acme/retry-demo.git")
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        assert_eq!(retry_requests.len(), 2);
        assert_eq!(
            retry_requests[0].client_outcome,
            Some(zitpit_core::ClientVisibleOutcome::TemporaryFailure)
        );
        assert_eq!(
            retry_requests[1].client_outcome,
            Some(zitpit_core::ClientVisibleOutcome::Success)
        );

        proxy_handle.abort();
        upstream_handle.abort();
        unsafe {
            std::env::remove_var("ZITPIT_GIT_UPSTREAM_OVERRIDE");
        }
    }

    #[tokio::test]
    #[serial]
    async fn blocked_git_request_stays_blocked_after_retry() {
        let (tempdir, paths) = temp_runtime_paths("zitpit-git-block-retry");
        paths.ensure_dirs().expect("runtime dirs");

        let upstream_repo_root = tempdir.path().join("upstream/acme/block-demo.git");
        let upstream_repo_parent = upstream_repo_root
            .parent()
            .expect("upstream parent")
            .to_path_buf();
        fs::create_dir_all(&upstream_repo_parent).expect("upstream parent");
        let workdir = tempdir.path().join("work");
        init_git_repo(&workdir, &upstream_repo_root);

        let upstream_port = free_tcp_port();
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        let upstream_state = GitUpstreamState {
            project_root: tempdir.path().join("upstream"),
            repo_path: "acme/block-demo.git".to_string(),
        };
        let upstream_handle = tokio::spawn(spawn_git_upstream(upstream_addr, upstream_state));
        wait_tcp(upstream_addr).await;

        unsafe {
            std::env::set_var(
                "ZITPIT_GIT_UPSTREAM_OVERRIDE",
                format!("http://127.0.0.1:{upstream_port}/"),
            );
        }

        let store = seeded_store().await;
        let policy = store
            .0
            .get_policy_snapshot()
            .await
            .expect("policy")
            .expect("seeded policy")
            .config;
        let broker = ArtifactBroker::new(store.clone(), policy.clone());
        let proxy_port = free_tcp_port();
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        let proxy_state = zitpit_gateway::AppState {
            store: store.clone(),
            broker: broker.clone(),
            git_adapter: zitpit_core::GitSmartHttpAdapter::with_paths_and_hold_duration(
                store.clone(),
                paths,
                policy.hold_duration_hours,
            ),
            lockdown_mode: std::sync::Arc::new(std::sync::RwLock::new(policy.lockdown_mode)),
            policy: zitpit_core::PolicyConfig {
                proxy_port,
                ..policy
            },
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("proxy client"),
        };
        let proxy_handle =
            tokio::spawn(zitpit_gateway::run_proxy_listener(proxy_addr, proxy_state));
        wait_tcp(proxy_addr).await;

        let client = reqwest::Client::builder()
            .proxy(Proxy::http(format!("http://{proxy_addr}")).expect("proxy"))
            .build()
            .expect("reqwest client");
        let url = "http://github.com/acme/block-demo.git/info/refs?service=git-upload-pack";
        let first = client
            .get(url)
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("first request");
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);

        broker
            .block_artifact(
                ArtifactCoordinate {
                    ecosystem: Ecosystem::Git,
                    source: "http://github.com/acme/block-demo.git".to_string(),
                    requested_selector: "git-smart-http".to_string(),
                    selector_kind: SelectorKind::Floating,
                },
                BTreeMap::from([("blocked_by".to_string(), "test".to_string())]),
                None,
            )
            .await
            .expect("block");

        let second = client
            .get(url)
            .header("User-Agent", "git/2.47")
            .send()
            .await
            .expect("second request");
        assert_eq!(second.status(), StatusCode::FORBIDDEN);
        let body = second.text().await.expect("body");
        assert!(body.contains("blocked"));

        let requests = store.0.list_captured_requests().await.expect("requests");
        let retry_requests = requests
            .iter()
            .filter(|request| {
                request
                    .artifact_key
                    .as_ref()
                    .map(|key| key.source == "http://github.com/acme/block-demo.git")
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        assert_eq!(retry_requests.len(), 2);
        assert_eq!(
            retry_requests[1].proxy_action,
            zitpit_core::ProxyAction::Blocked
        );
        assert_eq!(
            retry_requests[1].client_outcome,
            Some(zitpit_core::ClientVisibleOutcome::Blocked)
        );

        proxy_handle.abort();
        upstream_handle.abort();
        unsafe {
            std::env::remove_var("ZITPIT_GIT_UPSTREAM_OVERRIDE");
        }
    }

    #[test]
    fn honeypot_corpus_flags_common_exploit_behaviors() {
        let cases: Vec<HoneypotFixtureCase> =
            serde_json::from_str(include_str!("../fixtures/honeypot/corpus.json"))
                .expect("honeypot corpus");

        for case in cases {
            let evidence = TripwireEvaluator::evaluate(
                case.artifact.clone(),
                case.persona,
                case.scenario,
                case.events.clone(),
            );
            assert_eq!(
                evidence.verdict, case.expected_verdict,
                "case {}",
                case.name
            );
            assert_eq!(
                evidence.tripwires, case.expected_tripwires,
                "case {}",
                case.name
            );
            assert!(
                evidence.tripwires.iter().any(|kind| matches!(
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
                        | TripwireKind::NetworkConnection
                )),
                "case {} should trip a honeypot signal",
                case.name
            );
        }
    }

    #[derive(Clone)]
    struct GitUpstreamState {
        project_root: PathBuf,
        repo_path: String,
    }

    async fn spawn_git_upstream(
        addr: SocketAddr,
        state: GitUpstreamState,
    ) -> Result<(), std::io::Error> {
        let app = axum::Router::new()
            .route("/{*path}", axum::routing::any(git_upstream))
            .with_state(state);
        axum::serve(
            tokio::net::TcpListener::bind(addr)
                .await
                .expect("bind upstream"),
            app,
        )
        .await
    }

    async fn git_upstream(
        State(state): State<GitUpstreamState>,
        req: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.expect("collect body");
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let url = reqwest::Url::parse(&format!("http://127.0.0.1{path}")).expect("parse url");
        GitHttpBackend::serve(
            &state.project_root,
            &state.repo_path,
            &parts.method,
            &url,
            &parts.headers,
            bytes,
        )
        .await
        .expect("git upstream")
        .into_response()
    }

    fn init_git_repo(workdir: &PathBuf, bare_repo: &PathBuf) {
        if workdir.exists() {
            fs::remove_dir_all(workdir).expect("cleanup workdir");
        }
        if let Some(parent) = bare_repo.parent() {
            fs::create_dir_all(parent).expect("bare parent");
        }
        fs::create_dir_all(workdir).expect("workdir");

        run_git(
            Command::new("git")
                .arg("init")
                .arg("-b")
                .arg("main")
                .arg(workdir),
        );
        fs::write(workdir.join("README.md"), "# ZitPit proxy demo\n").expect("write readme");
        run_git(Command::new("git").arg("-C").arg(workdir).args([
            "config",
            "user.email",
            "zitpit@example.com",
        ]));
        run_git(
            Command::new("git")
                .arg("-C")
                .arg(workdir)
                .args(["config", "user.name", "ZitPit"]),
        );
        run_git(
            Command::new("git")
                .arg("-C")
                .arg(workdir)
                .args(["add", "."]),
        );
        run_git(
            Command::new("git")
                .arg("-C")
                .arg(workdir)
                .args(["commit", "-m", "initial"]),
        );
        run_git(
            Command::new("git")
                .args(["clone", "--mirror"])
                .arg(workdir)
                .arg(bare_repo),
        );
    }

    fn run_git(cmd: &mut Command) {
        let status = cmd.status().expect("run git");
        assert!(status.success(), "git command failed");
    }

    fn run_capture(cmd: &mut Command) -> String {
        let output = cmd.output().expect("run command");
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn free_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    async fn wait_tcp(addr: SocketAddr) {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {addr}");
    }
}
