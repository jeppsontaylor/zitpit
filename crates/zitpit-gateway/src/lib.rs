use std::{collections::BTreeMap, net::SocketAddr};

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri, header::HOST};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use reqwest::Client;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use url::Url;
use zitpit_core::{
    ArtifactBroker, ArtifactCoordinate, ArtifactKey, ClientVisibleOutcome, GitSmartHttpAdapter,
    PolicyConfig, ProxyAction, ProxyTunnelDecision, RequestClassifier, RequestObservation,
    SelectorHint, SelectorKind, StoreHandle, manifest::digest_for, sample_policy,
};
use zitpit_flags::CommonFlags;

#[derive(Clone)]
pub struct AppState {
    pub store: StoreHandle,
    pub broker: ArtifactBroker,
    pub git_adapter: GitSmartHttpAdapter,
    pub policy: PolicyConfig,
    pub http_client: Client,
}

#[derive(Debug, Clone)]
pub struct ProxyConnectionContext {
    pub peer_addr: Option<String>,
    pub local_addr: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct HealthResponse {
    pub service: &'static str,
    pub status: &'static str,
    pub proxy_port: u16,
    pub admin_port: u16,
}

pub async fn app_state_from_flags(flags: &CommonFlags) -> AppState {
    let paths = flags.runtime_paths();
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

    AppState {
        store: store.clone(),
        broker: ArtifactBroker::new(store.clone(), policy.clone()),
        git_adapter: GitSmartHttpAdapter::with_paths_and_hold_duration(
            store.clone(),
            paths,
            policy.hold_duration_hours,
        ),
        policy,
        http_client: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build proxy http client"),
    }
}

pub fn build_admin_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/policy/default", get(get_policy))
        .route("/api/v1/classify", post(classify))
        .route("/api/v1/captured-requests", get(captured_requests))
        .route("/api/v1/fixtures/npm-pending", get(sample_npm_pending))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

pub async fn run(state: AppState) {
    let admin_state = state.clone();
    let admin_app = build_admin_app(admin_state);

    let admin_addr = SocketAddr::from(([0, 0, 0, 0], state.policy.admin_port));
    let proxy_addr = SocketAddr::from(([0, 0, 0, 0], state.policy.proxy_port));

    let admin = async move {
        info!("zitpit-proxy admin API listening on {admin_addr}");
        axum::serve(
            tokio::net::TcpListener::bind(admin_addr)
                .await
                .expect("bind admin listener"),
            admin_app,
        )
        .await
        .expect("run admin api");
    };

    let proxy = run_proxy_listener(proxy_addr, state);
    tokio::join!(admin, proxy);
}

pub async fn run_proxy_listener(addr: SocketAddr, state: AppState) {
    let listener = TcpListener::bind(addr).await.expect("bind proxy listener");
    let local_addr = listener.local_addr().ok();
    info!("zitpit forward proxy listening on {addr}");
    loop {
        let (stream, peer) = listener.accept().await.expect("accept proxy connection");
        let io = TokioIo::new(stream);
        let state = state.clone();
        let context = ProxyConnectionContext {
            peer_addr: Some(peer.to_string()),
            local_addr: local_addr.map(|addr| addr.to_string()),
        };
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                proxy_service_with_context(req, state.clone(), Some(context.clone()))
            });
            if let Err(error) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                warn!("proxy connection error from {peer}: {error}");
            }
        });
    }
}

pub async fn proxy_service(
    req: Request<Incoming>,
    state: AppState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    proxy_service_with_context(req, state, None).await
}

pub async fn proxy_service_with_context(
    req: Request<Incoming>,
    state: AppState,
    context: Option<ProxyConnectionContext>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, state, context).await;
    }
    handle_forward(req, state, context).await
}

async fn handle_connect(
    req: Request<Incoming>,
    state: AppState,
    context: Option<ProxyConnectionContext>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let authority = req
        .uri()
        .authority()
        .map(|authority| authority.to_string())
        .unwrap_or_else(|| "unknown:443".to_string());
    let observation = RequestObservation {
        request_id: uuid::Uuid::new_v4(),
        observed_at: chrono::Utc::now(),
        scheme: "https".to_string(),
        authority: authority.clone(),
        path: String::new(),
        method: "CONNECT".to_string(),
        user_agent: header_value(req.headers(), "user-agent"),
        headers: normalize_headers(req.headers()),
        selector_hint: None,
    };
    let decision = match state.broker.decide(observation.clone(), None).await {
        Ok(decision) => decision,
        Err(error) => {
            error!("broker decision failed for CONNECT {authority}: {error}");
            return Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": error.to_string() }),
            ));
        }
    };
    let trace = trace_for(&observation, context.as_ref())
        .with_decision(decision.reason.clone())
        .with_event(
            zitpit_core::ProxyTraceKind::TunnelAccepted,
            "CONNECT evaluated by proxy",
        );

    let tunnel_decision = ProxyTunnelDecision {
        authority: authority.clone(),
        action: if decision.classification.lane == zitpit_core::TrafficLane::Browse
            && matches!(decision.action, ProxyAction::Allow)
        {
            ProxyAction::Tunnel
        } else {
            decision.action
        },
        classification: decision.classification.clone(),
        reason: if decision.classification.lane == zitpit_core::TrafficLane::Browse
            && matches!(decision.action, ProxyAction::Allow)
        {
            "browse-lane CONNECT tunnel allowed".to_string()
        } else {
            "code-intake CONNECT requires a dedicated ecosystem adapter before tunneling"
                .to_string()
        },
        should_intercept: false,
    };

    if decision.classification.lane != zitpit_core::TrafficLane::Browse {
        let trace = trace
            .with_event(
                zitpit_core::ProxyTraceKind::Blocked,
                "code-intake CONNECT blocked before tunneling",
            )
            .with_completion("blocked");
        let _ = state
            .store
            .0
            .update_captured_request_trace(observation.request_id, trace)
            .await;
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "message": "ZitPit blocked a code-intake CONNECT tunnel because this path must be served by an ecosystem adapter.",
                "decision": decision,
                "tunnel": tunnel_decision,
            }),
        ));
    }

    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                match TcpStream::connect(&authority).await {
                    Ok(mut server) => {
                        if let Err(error) = copy_bidirectional(&mut upgraded, &mut server).await {
                            warn!("tunnel copy failed for {authority}: {error}");
                        }
                    }
                    Err(error) => {
                        warn!("failed to connect to CONNECT upstream {authority}: {error}")
                    }
                }
            }
            Err(error) => warn!("upgrade failed for CONNECT {authority}: {error}"),
        }
    });

    let trace = trace.with_completion("tunnel established");
    let _ = state
        .store
        .0
        .update_captured_request_trace(observation.request_id, trace)
        .await;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .expect("connect response"))
}

async fn handle_forward(
    req: Request<Incoming>,
    state: AppState,
    context: Option<ProxyConnectionContext>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let url = match absolute_url(&uri, req.headers()) {
        Some(url) => url,
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": "proxy request did not include an absolute URL or Host header" }),
            ));
        }
    };
    let request_url = Url::parse(&url).ok();
    let git_coordinate = request_url.as_ref().and_then(git_coordinate_from_url);
    let observation = RequestObservation {
        request_id: uuid::Uuid::new_v4(),
        observed_at: chrono::Utc::now(),
        scheme: request_url
            .as_ref()
            .map(|parsed| parsed.scheme().to_string())
            .unwrap_or_else(|| "http".to_string()),
        authority: request_url
            .as_ref()
            .and_then(|parsed| parsed.host_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string()),
        path: request_url
            .as_ref()
            .map(|parsed| parsed.path().to_string())
            .unwrap_or_else(|| uri.path().to_string()),
        method: method.to_string(),
        user_agent: header_value(req.headers(), "user-agent"),
        headers: normalize_headers(req.headers()),
        selector_hint: maybe_selector_hint(&url),
    };

    let decision = match state
        .broker
        .decide(observation.clone(), git_coordinate.clone())
        .await
    {
        Ok(decision) => decision,
        Err(error) => {
            error!("broker decision failed for {url}: {error}");
            return Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": error.to_string() }),
            ));
        }
    };
    let mut trace = trace_for(&observation, context.as_ref())
        .with_decision(decision.reason.clone())
        .with_event(
            zitpit_core::ProxyTraceKind::Classified,
            format!("action={:?}", decision.action),
        );

    let artifact_key = git_coordinate.as_ref().map(ArtifactKey::from);

    if matches!(decision.action, ProxyAction::Blocked) {
        trace = trace
            .with_event(
                zitpit_core::ProxyTraceKind::Blocked,
                "proxy denied request before upstream routing",
            )
            .with_event(
                zitpit_core::ProxyTraceKind::ResponseSent,
                "blocked response sent to client",
            )
            .with_completion("blocked");
        let _ = persist_request_result(
            &state,
            &observation,
            &decision,
            artifact_key.clone(),
            trace,
            StatusCode::FORBIDDEN,
            ClientVisibleOutcome::Blocked,
        )
        .await;
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({ "decision": decision }),
        ));
    }
    if matches!(decision.action, ProxyAction::Pending) {
        if let (Some(git_coordinate), Some(request_url)) =
            (git_coordinate.as_ref(), request_url.as_ref())
        {
            if decision.classification.ecosystem == Some(zitpit_core::Ecosystem::Git) {
                let source_url =
                    git_source_url(request_url).unwrap_or_else(|| git_coordinate.source.clone());
                return match state
                    .git_adapter
                    .acquire_unknown_source(&source_url, request_url)
                    .await
                {
                    Ok(result) => {
                        for event in result.lifecycle_events {
                            trace = trace.with_event(event.kind, event.detail);
                        }
                        trace = trace
                            .with_event(
                                zitpit_core::ProxyTraceKind::Pending,
                                "proxy returned a temporary Git verification response",
                            )
                            .with_event(
                                zitpit_core::ProxyTraceKind::ResponseSent,
                                "temporary verification response sent to client",
                            )
                            .with_completion("pending verification response sent");
                        let status = result.response.status();
                        let _ = persist_request_result(
                            &state,
                            &observation,
                            &decision,
                            artifact_key.clone(),
                            trace,
                            status,
                            ClientVisibleOutcome::TemporaryFailure,
                        )
                        .await;
                        Ok(result.response)
                    }
                    Err(error) => {
                        trace = trace
                            .with_event(
                                zitpit_core::ProxyTraceKind::UpstreamError,
                                format!("quarantine acquisition failed: {error}"),
                            )
                            .with_event(
                                zitpit_core::ProxyTraceKind::ResponseSent,
                                "temporary acquisition failure sent to client",
                            )
                            .with_completion("pending acquisition failed");
                        let _ = persist_request_result(
                            &state,
                            &observation,
                            &decision,
                            artifact_key.clone(),
                            trace,
                            StatusCode::SERVICE_UNAVAILABLE,
                            ClientVisibleOutcome::UpstreamError,
                        )
                        .await;
                        Ok(json_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            serde_json::json!({
                                "message": "ZitPit could not complete quarantine acquisition for this Git source yet",
                                "decision": decision,
                                "error": error.to_string(),
                            }),
                        ))
                    }
                };
            }
        }

        trace = trace
            .with_event(
                zitpit_core::ProxyTraceKind::Pending,
                "proxy held request pending approval",
            )
            .with_event(
                zitpit_core::ProxyTraceKind::ResponseSent,
                "pending response sent to client",
            )
            .with_completion("pending");
        let _ = persist_request_result(
            &state,
            &observation,
            &decision,
            artifact_key.clone(),
            trace,
            StatusCode::TOO_EARLY,
            ClientVisibleOutcome::TemporaryFailure,
        )
        .await;
        return Ok(json_response(
            StatusCode::TOO_EARLY,
            serde_json::json!({ "decision": decision }),
        ));
    }

    let request_headers = req.headers().clone();
    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": format!("failed to read request body: {error}") }),
            ));
        }
    };

    if let (Some(git_coordinate), Some(request_url)) = (git_coordinate, request_url.as_ref()) {
        if matches!(decision.action, ProxyAction::Allow | ProxyAction::Fallback)
            && decision.classification.ecosystem == Some(zitpit_core::Ecosystem::Git)
        {
            let source_url =
                git_source_url(request_url).unwrap_or_else(|| git_coordinate.source.clone());
            return match state
                .git_adapter
                .handle(
                    &source_url,
                    request_url,
                    &method,
                    &request_headers,
                    body_bytes.clone(),
                )
                .await
            {
                Ok(result) => {
                    let mut trace = trace.with_event(
                        zitpit_core::ProxyTraceKind::RoutedToGitAdapter,
                        format!("source_url={source_url}"),
                    );
                    for event in result.lifecycle_events {
                        trace = trace.with_event(event.kind, event.detail);
                    }
                    trace = trace
                        .with_event(
                            zitpit_core::ProxyTraceKind::ResponseSent,
                            "git smart-http response sent to client",
                        )
                        .with_completion("git adapter completed");
                    let _ = persist_request_result(
                        &state,
                        &observation,
                        &decision,
                        artifact_key.clone(),
                        trace,
                        result.response.status(),
                        ClientVisibleOutcome::Success,
                    )
                    .await;
                    Ok(result.response)
                }
                Err(error) => Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({
                        "error": error.to_string(),
                        "url": url,
                        "decision": decision,
                    }),
                )),
            };
        }
    }

    let mut upstream = state.http_client.request(method.clone(), &url);
    for (name, value) in &request_headers {
        if name == HOST || name.as_str().eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    if !body_bytes.is_empty() {
        upstream = upstream.body(body_bytes.clone());
    }

    let upstream_response = match upstream.send().await {
        Ok(response) => response,
        Err(error) => {
            let trace = trace
                .with_event(
                    zitpit_core::ProxyTraceKind::UpstreamError,
                    format!("upstream send failed: {error}"),
                )
                .with_event(
                    zitpit_core::ProxyTraceKind::ResponseSent,
                    "upstream error response sent to client",
                )
                .with_completion("upstream error");
            let _ = persist_request_result(
                &state,
                &observation,
                &decision,
                artifact_key.clone(),
                trace,
                StatusCode::BAD_GATEWAY,
                ClientVisibleOutcome::UpstreamError,
            )
            .await;
            return Ok(json_response(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "error": error.to_string(),
                    "url": url,
                    "decision": decision,
                }),
            ));
        }
    };

    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();
    let response_bytes = upstream_response.bytes().await.unwrap_or_default();
    let trace = trace
        .with_event(
            zitpit_core::ProxyTraceKind::RoutedUpstream,
            format!("status={status}"),
        )
        .with_event(
            zitpit_core::ProxyTraceKind::ResponseSent,
            "upstream response sent to client",
        )
        .with_completion(format!("upstream completed with {status}"));
    let _ = persist_request_result(
        &state,
        &observation,
        &decision,
        artifact_key,
        trace,
        status,
        ClientVisibleOutcome::Success,
    )
    .await;

    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        response = response.header(name, value);
    }
    Ok(response
        .body(Full::new(response_bytes))
        .expect("proxy forward response"))
}

async fn persist_request_result(
    state: &AppState,
    observation: &RequestObservation,
    decision: &zitpit_core::ProxyDecision,
    artifact_key: Option<ArtifactKey>,
    trace: zitpit_core::ProxyTrace,
    status: StatusCode,
    client_outcome: ClientVisibleOutcome,
) -> Result<(), zitpit_core::store::StoreError> {
    state
        .store
        .0
        .record_captured_request(zitpit_core::CapturedRequest {
            request_id: observation.request_id,
            observation: observation.clone(),
            classification: decision.classification.clone(),
            proxy_action: decision.action,
            status_code: Some(status.as_u16()),
            bytes_in: None,
            bytes_out: None,
            stored_body: decision.classification.lane == zitpit_core::TrafficLane::CodeIntake,
            client_outcome: Some(client_outcome),
            decision_reason: decision.reason.clone(),
            artifact_key,
            trace,
        })
        .await
}

fn absolute_url(uri: &Uri, headers: &http::HeaderMap) -> Option<String> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Some(uri.to_string());
    }
    let host = headers.get(HOST)?.to_str().ok()?;
    Some(format!("http://{host}{}", uri))
}

fn git_source_url(url: &Url) -> Option<String> {
    let path = url.path();
    let git_pos = path.find(".git")?;
    let mut source = url.clone();
    source.set_path(&path[..git_pos + 4]);
    source.set_query(None);
    source.set_fragment(None);
    Some(source.to_string())
}

fn git_coordinate_from_url(url: &Url) -> Option<ArtifactCoordinate> {
    let source = git_source_url(url)?;
    Some(ArtifactCoordinate {
        ecosystem: zitpit_core::Ecosystem::Git,
        source,
        requested_selector: "git-smart-http".to_string(),
        selector_kind: SelectorKind::Floating,
    })
}

fn json_response(status: StatusCode, payload: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(payload.to_string())))
        .expect("json response")
}

fn normalize_headers(headers: &http::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn maybe_selector_hint(url: &str) -> Option<SelectorHint> {
    if let Some(fragment) = url.split('#').nth(1) {
        return Some(SelectorHint {
            requested: fragment.to_string(),
            kind: if fragment.len() == 40 && fragment.chars().all(|ch| ch.is_ascii_hexdigit()) {
                SelectorKind::ExactCommit
            } else {
                SelectorKind::Floating
            },
        });
    }
    None
}

fn trace_for(
    observation: &RequestObservation,
    context: Option<&ProxyConnectionContext>,
) -> zitpit_core::ProxyTrace {
    zitpit_core::ProxyTrace::new(
        context.and_then(|ctx| ctx.peer_addr.clone()),
        context.and_then(|ctx| ctx.local_addr.clone()),
        observation.observed_at,
    )
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        service: "zitpit-proxy",
        status: "ok",
        proxy_port: state.policy.proxy_port,
        admin_port: state.policy.admin_port,
    })
}

async fn get_policy(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.policy.clone())
}

async fn classify(Json(observation): Json<RequestObservation>) -> impl IntoResponse {
    Json(RequestClassifier::classify(&observation))
}

async fn captured_requests(State(state): State<AppState>) -> impl IntoResponse {
    Json(
        state
            .store
            .0
            .list_captured_requests()
            .await
            .unwrap_or_default(),
    )
}

async fn sample_npm_pending(State(state): State<AppState>) -> impl IntoResponse {
    let observation = RequestObservation {
        request_id: uuid::Uuid::new_v4(),
        observed_at: chrono::Utc::now(),
        scheme: "https".to_string(),
        authority: "registry.npmjs.org".to_string(),
        path: "/lodash".to_string(),
        method: "GET".to_string(),
        user_agent: Some("npm/10".to_string()),
        headers: BTreeMap::new(),
        selector_hint: Some(SelectorHint {
            requested: "^4.17".to_string(),
            kind: SelectorKind::SemverRange,
        }),
    };
    let coordinate = ArtifactCoordinate {
        ecosystem: zitpit_core::Ecosystem::Npm,
        source: "npm:lodash".to_string(),
        requested_selector: "^4.17".to_string(),
        selector_kind: SelectorKind::SemverRange,
    };
    let decision = state
        .broker
        .decide(observation, Some(coordinate.clone()))
        .await
        .expect("decision");
    Json(serde_json::json!({
        "decision": decision,
        "artifact_key": ArtifactKey::from(coordinate),
        "request_fingerprint": digest_for("registry.npmjs.org/lodash/^4.17"),
    }))
}
