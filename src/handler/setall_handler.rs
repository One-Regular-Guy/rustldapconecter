

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::service::ldap_service::LdapService;

#[derive(Deserialize)]
pub struct SigninPayload {
    email: String
}

#[derive(Serialize)]
pub struct SigninBadResponsePayload {
    message: String
}

#[derive(Serialize)]
pub struct SigninGoodResponsePayload {
    token: String
}

pub async fn handler(
    State(service): State<LdapService>,
    Json(payload): Json<SigninPayload>
) -> impl IntoResponse {
    match service.signin_execute(payload.email).await {
        Ok(token) => {
            (StatusCode::OK, Json(SigninGoodResponsePayload{token})).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(SigninBadResponsePayload{message: e.to_string()})).into_response()
        }
    }
}