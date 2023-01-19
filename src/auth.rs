use std::sync::Arc;
use axum::{extract::{Extension, Path}, http::StatusCode, Json, response::{IntoResponse, Response}, Router};
use axum::extract::State;
use axum::routing::{post};
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

impl AuthState {
    pub fn new() -> AuthState {
        let rp_id = std::env::var("CURIOUSWOLF_HOSTNAME").unwrap();
        let rp_origin = Url::parse(&format!("https://{rp_id}")).unwrap();
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin).unwrap();
        let builder = builder.rp_name("curiouswolf");

        let webauthn = Arc::new(builder.build().unwrap());
        AuthState { webauthn }
    }
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
        sqlx::query_as::<Postgres, Credential>("SELECT * FROM credentials WHERE user_uuid = $1")
            .bind(user_unique_id)
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
    State(db): State<PgPool>,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {

    info!("Attempting to complete registration");
    let (username, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) = session
        .get("reg_state")
        .ok_or(WebauthnError::CorruptSession)?;

    info!("Got registration state from session");

    session.remove("reg_state");

    let res = match state.webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(passkey) => {

            // Batch inserts so we can rollback if either fails.
            let mut tx = db.begin()
                .await
                .expect("Failed to begin transaction");

            let user_query = r#"
                INSERT INTO users
                    ( username, uuid )
                VALUES
                    ( $1, $2 )
                returning *
            "#;

            sqlx::query(user_query)
                .bind(username)
                .bind(user_unique_id)
                .execute(&mut tx)
                .await
                .expect("Could not create user");

            let cred_query = r#"
                INSERT INTO credentials
                    ( user_uuid, passkey )
                VALUES
                    ( $1, $2 )
                RETURNING *
            "#;

            sqlx::query(cred_query)
                .bind(user_unique_id)
                .bind(sqlx::types::Json(passkey))
                .execute(&mut tx)
                .await
                .expect("Could not create credential");

            tx.commit().await.expect("Failed to commit transaction");

            StatusCode::OK
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}

