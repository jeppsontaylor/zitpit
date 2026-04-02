use std::{collections::BTreeMap, net::SocketAddr};

use axum::{
    Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tower_http::trace::TraceLayer;
use tracing::info;
use zitpit_core::{
    ArtifactBroker, ArtifactCoordinate, Ecosystem, ManifestCatalog, ManifestRoot, ManifestShard,
    ManifestSigner, SignedEnvelope, StoreHandle,
};
use zitpit_flags::CommonFlags;

#[derive(Clone)]
pub struct AppState {
    pub store: StoreHandle,
    pub signer: ManifestSigner,
}

#[derive(Debug, Deserialize)]
struct PromoteRequest {
    coordinate: ArtifactCoordinate,
    resolved_target: String,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct BlockRequest {
    coordinate: ArtifactCoordinate,
    metadata: BTreeMap<String, String>,
    fallback_selector: Option<String>,
}

pub async fn app_state_from_flags(flags: &CommonFlags) -> AppState {
    AppState {
        store: StoreHandle::connect(flags.database_url.as_deref())
            .await
            .expect("connect store"),
        signer: ManifestSigner::from_seed([7; 32]),
    }
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/manifest/root", get(root))
        .route("/api/v1/manifest/shards/{ecosystem}/{shard}", get(shard))
        .route("/api/v1/manifest/lookup", post(lookup))
        .route("/api/v1/manifest/records", get(records))
        .route("/api/v1/manifest/promote", post(promote))
        .route("/api/v1/manifest/block", post(block))
        .route("/api/v1/quarantine/jobs", get(quarantine_jobs))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

pub async fn run(state: AppState) {
    let app = build_app(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    info!("zitpit-manifest listening on {addr}");
    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind manifest listener"),
        app,
    )
    .await
    .expect("run manifest");
}

async fn healthz() -> impl IntoResponse {
    Json(json!({ "service": "zitpit-manifest", "status": "ok", "generated_at": Utc::now() }))
}

async fn root(State(state): State<AppState>) -> Response {
    let root: ManifestRoot = load_catalog(&state).await.root(&state.signer);
    Json(signed_payload(&state.signer, &root)).into_response()
}

async fn shard(
    Path((ecosystem, shard)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Response {
    let ecosystem = match parse_ecosystem(&ecosystem) {
        Some(ecosystem) => ecosystem,
        None => {
            return Json(json!({
                "error": "unknown ecosystem",
                "allowed": ["git", "npm", "pypi", "cargo", "go", "oci", "archive", "generic_web"]
            }))
            .into_response();
        }
    };

    let shard_payload: ManifestShard = load_catalog(&state).await.shard(ecosystem, &shard);
    Json(signed_payload(&state.signer, &shard_payload)).into_response()
}

async fn lookup(
    State(state): State<AppState>,
    Json(coordinate): Json<ArtifactCoordinate>,
) -> impl IntoResponse {
    let catalog = load_catalog(&state).await;
    let exact = catalog.find_exact(&coordinate).cloned();
    let fallback = catalog.latest_approved_fallback(&coordinate);
    Json(json!({
        "coordinate": coordinate,
        "exact": exact,
        "fallback": fallback,
    }))
}

async fn records(State(state): State<AppState>) -> impl IntoResponse {
    Json(
        state
            .store
            .0
            .list_manifest_records()
            .await
            .unwrap_or_default(),
    )
}

async fn promote(
    State(state): State<AppState>,
    Json(request): Json<PromoteRequest>,
) -> impl IntoResponse {
    let broker = ArtifactBroker::new(
        state.store.clone(),
        state
            .store
            .0
            .get_policy_snapshot()
            .await
            .ok()
            .flatten()
            .map(|snapshot| snapshot.config)
            .unwrap_or_else(zitpit_core::sample_policy),
    );
    match broker
        .promote_artifact(
            request.coordinate,
            request.resolved_target,
            request.metadata,
        )
        .await
    {
        Ok(()) => Json(json!({ "status": "promoted" })).into_response(),
        Err(error) => {
            Json(json!({ "status": "error", "error": error.to_string() })).into_response()
        }
    }
}

async fn block(
    State(state): State<AppState>,
    Json(request): Json<BlockRequest>,
) -> impl IntoResponse {
    let broker = ArtifactBroker::new(
        state.store.clone(),
        state
            .store
            .0
            .get_policy_snapshot()
            .await
            .ok()
            .flatten()
            .map(|snapshot| snapshot.config)
            .unwrap_or_else(zitpit_core::sample_policy),
    );
    match broker
        .block_artifact(
            request.coordinate,
            request.metadata,
            request.fallback_selector,
        )
        .await
    {
        Ok(()) => Json(json!({ "status": "blocked" })).into_response(),
        Err(error) => {
            Json(json!({ "status": "error", "error": error.to_string() })).into_response()
        }
    }
}

async fn quarantine_jobs(State(state): State<AppState>) -> impl IntoResponse {
    Json(
        state
            .store
            .0
            .list_quarantine_jobs()
            .await
            .unwrap_or_default(),
    )
}

async fn load_catalog(state: &AppState) -> ManifestCatalog {
    ManifestCatalog::new(
        state
            .store
            .0
            .list_manifest_records()
            .await
            .unwrap_or_default(),
    )
}

fn signed_payload<T: serde::Serialize + Clone>(
    signer: &ManifestSigner,
    payload: &T,
) -> SignedEnvelope<T> {
    signer.sign(payload).expect("sign payload")
}

fn parse_ecosystem(value: &str) -> Option<Ecosystem> {
    match value {
        "git" => Some(Ecosystem::Git),
        "npm" => Some(Ecosystem::Npm),
        "pypi" => Some(Ecosystem::Pypi),
        "cargo" => Some(Ecosystem::Cargo),
        "go" => Some(Ecosystem::Go),
        "oci" => Some(Ecosystem::Oci),
        "archive" => Some(Ecosystem::Archive),
        "generic_web" => Some(Ecosystem::GenericWeb),
        _ => None,
    }
}
