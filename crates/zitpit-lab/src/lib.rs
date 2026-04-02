use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use tower_http::trace::TraceLayer;
use tracing::info;
use zitpit_core::{
    ArtifactCoordinate, EvidenceBundle, FirecrackerOrchestrator, LabPlanner, StoreHandle,
    TripwireEvaluator, types::CacheDomain,
};
use zitpit_flags::CommonFlags;

#[derive(Clone)]
pub struct AppState {
    pub store: StoreHandle,
    pub orchestrator: FirecrackerOrchestrator,
}

pub async fn app_state_from_flags(flags: &CommonFlags) -> AppState {
    let paths = flags.runtime_paths();
    AppState {
        store: StoreHandle::connect(flags.database_url.as_deref())
            .await
            .expect("connect store"),
        orchestrator: FirecrackerOrchestrator::with_paths(paths),
    }
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/personas", get(personas))
        .route("/api/v1/jobs/plan", post(plan))
        .route("/api/v1/jobs/run", post(run_job))
        .route("/api/v1/jobs", get(list_runs))
        .route("/api/v1/evidence", get(list_evidence))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

pub async fn run(state: AppState) {
    let app = build_app(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3002));
    info!("zitpit-lab listening on {addr}");
    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind lab listener"),
        app,
    )
    .await
    .expect("run lab");
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "zitpit-lab",
        "status": "ok",
        "firecracker_available": state.orchestrator.is_available(),
        "firecracker_assets_present": state.orchestrator.config_exists(),
    }))
}

async fn personas() -> impl IntoResponse {
    Json(serde_json::json!({
        "personas": [
            "developer_workstation",
            "ci_runner",
            "container_build_node",
            "cloud_operator"
        ],
        "scenarios": [
            "install_build",
            "import_load",
            "cli_smoke",
            "warm_cache",
            "cold_cache",
            "delayed_rerun",
            "baited_vs_sterile"
        ],
        "cache_domains": [CacheDomain::Approved, CacheDomain::Quarantine],
    }))
}

async fn plan(Json(artifact): Json<ArtifactCoordinate>) -> impl IntoResponse {
    Json(LabPlanner::plan(artifact))
}

async fn run_job(
    State(state): State<AppState>,
    Json(artifact): Json<ArtifactCoordinate>,
) -> impl IntoResponse {
    let lab_run = state.orchestrator.plan_run(artifact.clone());
    let stored_run = state
        .store
        .0
        .upsert_lab_run(lab_run.clone())
        .await
        .expect("persist lab run");

    if !state.orchestrator.is_available() {
        let evidence = TripwireEvaluator::sample_suspicious_run(artifact.clone());
        state
            .store
            .0
            .record_evidence_bundle(EvidenceBundle {
                evidence_id: uuid::Uuid::new_v4(),
                artifact_key: (&artifact).into(),
                run_id: Some(stored_run.run_id),
                summary: evidence,
                sinkhole_transcript: vec![
                    "dns query: cdn.bad.invalid".to_string(),
                    "https post: https://sinkhole.zitpit.invalid/upload".to_string(),
                ],
            })
            .await
            .expect("persist evidence");
    }

    Json(stored_run)
}

async fn list_runs(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.0.list_lab_runs().await.unwrap_or_default())
}

async fn list_evidence(State(state): State<AppState>) -> impl IntoResponse {
    Json(
        state
            .store
            .0
            .list_evidence_bundles()
            .await
            .unwrap_or_default(),
    )
}
