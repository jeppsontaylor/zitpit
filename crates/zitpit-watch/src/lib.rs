use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use tracing::info;
use zitpit_core::{
    ApprovalStatus, ArtifactCoordinate, DetectionSeverity, Ecosystem, FallbackTarget,
    HourlyFeedRecord, ManifestCatalog, SelectorKind, StoreHandle, TripwireKind,
};
use zitpit_flags::CommonFlags;

#[derive(Debug, Deserialize)]
struct FeedQuery {
    ecosystem: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub store: StoreHandle,
}

pub async fn app_state_from_flags(flags: &CommonFlags) -> AppState {
    AppState {
        store: StoreHandle::connect(flags.database_url.as_deref())
            .await
            .expect("connect store"),
    }
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/feed/hourly", get(feed))
        .route("/api/v1/incidents/sample", get(sample_incident))
        .route("/api/v1/evidence", get(evidence))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

pub async fn run(state: AppState) {
    let app = build_app(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3003));
    info!("zitpit-watch listening on {addr}");
    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind watch listener"),
        app,
    )
    .await
    .expect("run watch");
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "service": "zitpit-watch", "status": "ok" }))
}

async fn feed(State(state): State<AppState>, Query(query): Query<FeedQuery>) -> impl IntoResponse {
    let mut records = state.store.0.list_feed_records().await.unwrap_or_default();
    if records.is_empty() {
        records = derived_feed(&state).await;
    }
    if let Some(filter) = query.ecosystem {
        records.retain(|record| {
            format!("{:?}", record.artifact.ecosystem).eq_ignore_ascii_case(&filter)
        });
    }
    Json(records)
}

async fn sample_incident(State(state): State<AppState>) -> impl IntoResponse {
    let evidence = state
        .store
        .0
        .list_evidence_bundles()
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    Json(evidence)
}

async fn evidence(State(state): State<AppState>) -> impl IntoResponse {
    Json(
        state
            .store
            .0
            .list_evidence_bundles()
            .await
            .unwrap_or_default(),
    )
}

async fn derived_feed(state: &AppState) -> Vec<HourlyFeedRecord> {
    let catalog = ManifestCatalog::new(
        state
            .store
            .0
            .list_manifest_records()
            .await
            .unwrap_or_default(),
    );
    let mut records = Vec::new();
    if let Some(blocked) = catalog
        .records
        .iter()
        .find(|record| record.status == ApprovalStatus::Blocked)
    {
        records.push(HourlyFeedRecord {
            artifact: blocked.coordinate(),
            status: blocked.status,
            first_seen_at: blocked.first_seen_at,
            confidence: DetectionSeverity::Critical,
            trigger_category: Some(TripwireKind::Downloader),
            recommended_action: "stay on the approved fallback and inspect the evidence bundle"
                .to_string(),
            approved_fallback: blocked.fallback.clone(),
        });
    }
    if let Some(pending) = catalog
        .records
        .iter()
        .find(|record| record.status == ApprovalStatus::Pending)
    {
        records.push(HourlyFeedRecord {
            artifact: pending.coordinate(),
            status: pending.status,
            first_seen_at: pending.first_seen_at,
            confidence: DetectionSeverity::Medium,
            trigger_category: None,
            recommended_action:
                "continue hold window and serve the latest approved compatible version".to_string(),
            approved_fallback: pending.fallback.clone().or_else(|| {
                catalog.latest_approved_fallback(&ArtifactCoordinate {
                    ecosystem: Ecosystem::Npm,
                    source: "npm:lodash".to_string(),
                    requested_selector: "^4.17".to_string(),
                    selector_kind: SelectorKind::SemverRange,
                })
            }),
        });
    }
    if records.is_empty() {
        records.push(HourlyFeedRecord {
            artifact: ArtifactCoordinate {
                ecosystem: Ecosystem::Archive,
                source:
                    "https://github.com/acme/tool/releases/download/v2.0.0/tool-linux-amd64.tar.gz"
                        .to_string(),
                requested_selector: "v2.0.0".to_string(),
                selector_kind: SelectorKind::Tag,
            },
            status: ApprovalStatus::Pending,
            first_seen_at: chrono::Utc::now(),
            confidence: DetectionSeverity::Low,
            trigger_category: None,
            recommended_action: "feed is empty because no incidents were persisted yet".to_string(),
            approved_fallback: Some(FallbackTarget {
                selector: "v1.9.4".to_string(),
                resolved_target: Some("tool-v1.9.4-archive".to_string()),
                reason: "seed fallback".to_string(),
            }),
        });
    }
    records
}
