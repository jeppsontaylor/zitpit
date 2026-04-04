use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use axum::{
    Json, Router,
    extract::{Request as AxumRequest, State},
    http::{self, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use zitpit_core::{NodeBootstrapper, PolicyConfig, PolicySnapshot, StoreHandle, sample_policy};
use zitpit_flags::CommonFlags;

#[derive(Clone)]
pub struct AppState {
    pub store: StoreHandle,
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize)]
struct BootstrapRequest {
    node_id: String,
    hostname: String,
    user_label: String,
}

#[derive(Debug, Deserialize)]
struct ApplyBootstrapRequest {
    node_id: String,
    hostname: String,
    user_label: String,
    target_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct HeartbeatRequest {
    node_id: String,
}

pub async fn app_state_from_flags(flags: &CommonFlags) -> AppState {
    let store = StoreHandle::connect(flags.database_url.as_deref())
        .await
        .expect("connect store");
    let policy = store
        .0
        .get_policy_snapshot()
        .await
        .expect("load policy")
        .map(|snapshot| snapshot.config)
        .unwrap_or_else(sample_policy);
    AppState { store, policy }
}

pub fn build_app(state: AppState) -> Router {
    let protected_state = state.clone();
    let protected = Router::new()
        .route("/api/v1/node/bootstrap", post(bootstrap))
        .route("/api/v1/node/bootstrap/apply", post(apply_bootstrap))
        .route("/api/v1/node/heartbeat", post(heartbeat))
        .route("/api/v1/node/sessions", get(list_sessions))
        .route("/api/v1/node/policy", get(policy))
        .route("/api/v1/node/interception-plan", get(interception_plan))
        .route_layer(middleware::from_fn_with_state(
            protected_state,
            require_admin_bearer_token,
        ));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

pub async fn run(state: AppState) {
    let addr = socket_addr(
        &state.policy.node_agent_bind_addr,
        state.policy.node_agent_port,
    )
    .expect("resolve node-agent bind address");
    let app = build_app(state);
    tracing::info!("zitpit-node-agent listening on {addr}");
    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind node-agent listener"),
        app,
    )
    .await
    .expect("run node agent");
}

async fn require_admin_bearer_token(
    State(state): State<AppState>,
    request: AxumRequest,
    next: Next,
) -> AxumResponse {
    if has_valid_bearer_token(request.headers(), &state.policy.admin_auth_token) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response()
    }
}

fn has_valid_bearer_token(headers: &http::HeaderMap, expected: &str) -> bool {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token == expected)
        .unwrap_or(false)
}

fn socket_addr(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, host))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "zitpit-node-agent",
        "status": "ok",
        "linux_first": true,
    }))
}

async fn policy(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state
        .store
        .0
        .get_policy_snapshot()
        .await
        .unwrap_or(None)
        .unwrap_or(PolicySnapshot {
            version: "v1".to_string(),
            generated_at: chrono::Utc::now(),
            config: sample_policy(),
        });
    Json(snapshot)
}

async fn bootstrap(
    State(state): State<AppState>,
    Json(request): Json<BootstrapRequest>,
) -> impl IntoResponse {
    let snapshot = load_policy_snapshot(&state).await;
    let bundle = NodeBootstrapper::bootstrap(&request.node_id, &request.hostname, snapshot.clone())
        .expect("bootstrap node bundle");
    let session = NodeBootstrapper::session(
        &request.node_id,
        &request.hostname,
        &request.user_label,
        &snapshot,
    );
    state
        .store
        .0
        .upsert_node_session(session)
        .await
        .expect("store node session");
    Json(bundle)
}

async fn apply_bootstrap(
    State(state): State<AppState>,
    Json(request): Json<ApplyBootstrapRequest>,
) -> impl IntoResponse {
    let snapshot = load_policy_snapshot(&state).await;
    let bundle = NodeBootstrapper::bootstrap(&request.node_id, &request.hostname, snapshot.clone())
        .expect("bootstrap node bundle");
    let session = NodeBootstrapper::session(
        &request.node_id,
        &request.hostname,
        &request.user_label,
        &snapshot,
    );
    state
        .store
        .0
        .upsert_node_session(session)
        .await
        .expect("store node session");
    NodeBootstrapper::apply_bundle(&bundle, &request.target_root)
        .await
        .expect("apply node bootstrap");
    Json(serde_json::json!({
        "status": "applied",
        "node_id": request.node_id,
        "target_root": request.target_root,
        "files": [
            "usr/local/share/ca-certificates/zitpit-ca.crt",
            "etc/nftables.d/zitpit.nft",
            "usr/local/bin/zitpit-apply-bootstrap",
        ]
    }))
}

async fn heartbeat(
    State(state): State<AppState>,
    Json(request): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    match state.store.0.heartbeat_node(&request.node_id).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(error) => Json(serde_json::json!({ "status": "error", "error": error.to_string() }))
            .into_response(),
    }
}

async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.0.list_node_sessions().await.unwrap_or_default())
}

async fn interception_plan(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = load_policy_snapshot(&state).await;
    Json(serde_json::json!({
        "transparent_capture": snapshot.config.transparent_capture,
        "proxy_port": snapshot.config.proxy_port,
        "admin_port": snapshot.config.admin_port,
        "bypass_hosts": snapshot.config.bypass_hosts,
        "notes": [
            "install CA into system trust store",
            "apply nftables ruleset on Linux",
            "keep ZitPit control-plane endpoints in bypass set",
        ]
    }))
}

async fn load_policy_snapshot(state: &AppState) -> PolicySnapshot {
    state
        .store
        .0
        .get_policy_snapshot()
        .await
        .unwrap_or(None)
        .unwrap_or(PolicySnapshot {
            version: "v1".to_string(),
            generated_at: chrono::Utc::now(),
            config: sample_policy(),
        })
}
