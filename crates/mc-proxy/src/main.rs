mod auth;
mod bridge;
mod error;

use auth::{Poll, Sessions};
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use error::AppError;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

struct Config {
    client_id: Option<String>,
    allow_private: bool,
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    http: reqwest::Client,
    sessions: Sessions,
}

impl AppState {
    fn client_id(&self) -> Result<&str, AppError> {
        self.cfg.client_id.as_deref().ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server has no MS_CLIENT_ID configured; see README",
            )
        })
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg = Config {
        client_id: std::env::var("MS_CLIENT_ID").ok().filter(|s| !s.is_empty()),
        allow_private: std::env::var("ALLOW_PRIVATE_TARGETS").is_ok_and(|v| v == "1"),
    };
    if cfg.client_id.is_none() {
        tracing::warn!("MS_CLIENT_ID is not set: Microsoft sign-in will be unavailable");
    }
    if cfg.allow_private {
        tracing::warn!("ALLOW_PRIVATE_TARGETS=1: the bridge may dial loopback/LAN addresses");
    }
    let state = AppState {
        cfg: Arc::new(cfg),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(concat!("mc-web-proxy/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("http client"),
        sessions: Sessions::default(),
    };

    let web_dir = std::env::var("WEB_DIR").unwrap_or_else(|_| "web".into());
    let app = Router::new()
        .route("/api/config", get(config))
        .route("/api/auth/start", post(auth_start))
        .route("/api/auth/poll", post(auth_poll))
        .route("/api/auth/me", get(me))
        .route("/api/session/join", post(session_join))
        .route("/ws", get(ws_bridge))
        .fallback_service(ServeDir::new(web_dir))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    tracing::info!("listening on http://{bind}");
    axum::serve(listener, app).await.expect("serve");
}

async fn config(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "game_version": mc_proto::GAME_VERSION,
        "protocol_version": mc_proto::PROTOCOL_VERSION,
        "auth_configured": st.cfg.client_id.is_some(),
    }))
}

async fn auth_start(State(st): State<AppState>) -> Result<Json<auth::DeviceStart>, AppError> {
    Ok(Json(auth::device_start(&st.http, st.client_id()?).await?))
}

#[derive(Deserialize)]
struct PollReq {
    device_code: String,
}

async fn auth_poll(State(st): State<AppState>, Json(req): Json<PollReq>) -> Result<Response, AppError> {
    let out = match auth::device_poll(&st.http, st.client_id()?, &req.device_code).await? {
        Poll::Pending => json!({ "status": "pending" }),
        Poll::SlowDown => json!({ "status": "slow_down" }),
        Poll::Done(s) => {
            let body = json!({
                "status": "done",
                "name": s.name,
                "uuid": s.uuid,
                "owns_java": s.owns_java,
            });
            let id = st.sessions.insert(s);
            let mut body = body;
            body["session"] = json!(id);
            body
        }
    };
    Ok(Json(out).into_response())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn me(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, AppError> {
    let s = st
        .sessions
        .get(bearer(&headers).unwrap_or_default())
        .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "not signed in"))?;
    Ok(Json(json!({ "name": s.name, "uuid": s.uuid, "owns_java": s.owns_java })))
}

#[derive(Deserialize)]
struct JoinReq {
    server_hash: String,
}

async fn session_join(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<JoinReq>,
) -> Result<StatusCode, AppError> {
    let s = st.sessions.get_owner(bearer(&headers).unwrap_or_default())?;
    // Minecraft server hashes are signed hex of a SHA-1 digest: at most 41 chars.
    if req.server_hash.is_empty()
        || req.server_hash.len() > 41
        || !req.server_hash.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "malformed server hash"));
    }
    auth::join_server(&st.http, &s, &req.server_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WsQuery {
    session: String,
    host: String,
    port: Option<u16>,
}

async fn ws_bridge(
    State(st): State<AppState>,
    Query(q): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    // Browsers always send Origin on WebSocket handshakes; require same-origin
    // so other sites can't drive the bridge from a visitor's browser.
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
        let origin_host = origin.split("://").nth(1).unwrap_or_default();
        if origin_host != host {
            return Err(AppError::new(StatusCode::FORBIDDEN, "cross-origin WebSocket refused"));
        }
    }
    st.sessions.get_owner(&q.session)?;
    let target = bridge::resolve_target(&q.host, q.port.unwrap_or(25565), st.cfg.allow_private).await?;
    Ok(ws.on_upgrade(move |socket| bridge::pump(socket, target)))
}
