//! 学校端 REST API（axum）

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::service;

#[derive(Deserialize)]
pub struct InitRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct InitResponse {
    pub name: String,
    pub did: String,
}

#[derive(Deserialize)]
pub struct IssueRequest {
    pub holder: String,
    #[serde(rename = "credentialType")]
    pub credential_type: String,
    pub claims: serde_json::Value,
    pub expiration: Option<String>,
}

/// 构建路由器
pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/init", post(init))
        .route("/did", get(did))
        .route("/issue", post(issue))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "issuer" }))
}

async fn init(Json(req): Json<InitRequest>) -> Result<Json<InitResponse>, ApiError> {
    let identity = service::init_identity(&req.name).map_err(ApiError::internal)?;
    Ok(Json(InitResponse {
        name: identity.name,
        did: identity.did,
    }))
}

async fn did() -> Result<Json<serde_json::Value>, ApiError> {
    let identity = service::load_identity().map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "name": identity.name,
        "did": identity.did,
    })))
}

async fn issue(Json(req): Json<IssueRequest>) -> Result<Json<serde_json::Value>, ApiError> {
    let identity = service::load_identity().map_err(ApiError::internal)?;
    let vc = service::issue(
        &identity,
        &req.holder,
        &req.credential_type,
        req.claims,
        req.expiration,
    )
    .map_err(ApiError::internal)?;

    let json = serde_json::to_value(&vc).map_err(|e| ApiError::internal(e.into()))?;
    Ok(Json(json))
}

/// 简单 API 错误类型
pub struct ApiError(StatusCode, String);

impl ApiError {
    fn internal(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}
