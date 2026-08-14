//! 验证方 REST API（axum）

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::service;

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub credential: zkdid_core::vc::VerifiableCredential,
}

/// 构建路由器
pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/verify", post(verify))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "verifier" }))
}

async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<service::VerifyReport>, ApiError> {
    Ok(Json(service::verify(&req.credential)))
}

/// 简单 API 错误类型
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}
