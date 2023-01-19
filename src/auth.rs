use std::sync::Arc;
use axum::{extract::{Extension, Path}, http::StatusCode, Json, response::{IntoResponse, Response}};
use axum::extract::State;
use axum_sessions::extractors::WritableSession;
use sqlx::{PgPool, Postgres};

use webauthn_rs::prelude::*;
use thiserror::Error;

use crate::models::{Credential, User};

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("Unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
}

#[derive(Clone)]
pub struct AuthState {
    pub webauthn: Arc<Webauthn>
}

impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let body = match self {
            WebauthnError::CorruptSession => "Corrupt Session",
            WebauthnError::UserNotFound => "User Not Found",
            WebauthnError::Unknown => "Unknown Error",
            WebauthnError::UserHasNoCredentials => "User Has No Credentials",
        };

        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

pub async fn start_register(
    Extension(state): Extension<AuthState>,
    mut session: WritableSession,
    Path(username): Path<String>,
    State(db): State<PgPool>,
) -> Result<impl IntoResponse, WebauthnError> {

    let user_unique_id = Uuid::new_v4();

    // Remove any previous registrations that may have occurred from the session.
    session.remove("reg_state");

    // If the user has any other credentials, we exclude these so they can't be registered twice.
    // It also hints to the browser that only new credentials should be "blinked" for interaction.
    let exclude_credentials: Vec<CredentialID> = {
        sqlx::query_as::<Postgres, Credential>("SELECT * FROM passkeys WHERE user_id = $1")
            .bind(user_unique_id.to_string())
            .fetch_all(&db)
            .await
            .expect("Failed to pull existing credentials")
            .iter()
            .map(|cred| cred.passkey.cred_id().clone())
            .collect()
    };

    let res = match state.webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        Some(exclude_credentials),
    ) {
        Ok((ccr, reg_state)) => {
            session
                .insert("reg_state", (username, user_unique_id, reg_state))
                .expect("Failed to insert registration state into session");
            info!("Successfully started registration!");
            Json(ccr)
        },
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };

    Ok(res)
}

pub async fn finish_register(
    Extension(state): Extension<AuthState>,
    mut session: WritableSession,
    Json(reg): Json<RegisterPublicKeyCredential>,
    State(db): State<PgPool>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (username, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) = session
        .get("reg_state")
        .ok_or(WebauthnError::CorruptSession)?;

    session.remove("reg_state");
    let res = match state.webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(passkey) => {
            let user_query = r#"
                INSERT INTO users
                    ( username )
                VALUES
                    ( $1 )
                returning *
            "#;

            let user_result = sqlx::query_as::<Postgres, User>(user_query)
                .bind(username)
                .fetch_one(&db)
                .await
                .expect("Could not create user");

            let cred_query = r#"
                INSERT INTO credentials
                    ( user_id, passkey )
                VALUES
                    ( $1, $2 )
                RETURNING *
            "#;

            let cred_result = sqlx::query_as::<Postgres, Credential>(cred_query)
                .bind(1)
                .bind(sqlx::types::Json(passkey))
                .fetch_one(&db)
                .await
                .expect("Could not create credential");

            StatusCode::OK
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}

