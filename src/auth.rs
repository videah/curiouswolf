use std::sync::Arc;
use axum::{extract::{Extension, Path}, http::StatusCode, Json, response::{IntoResponse, Response}};
use axum::extract::State;
use axum_login::PostgresStore;
use axum_sessions::extractors::WritableSession;
use sqlx::{PgPool, Postgres};

use webauthn_rs::prelude::*;
use thiserror::Error;

use crate::models::{Credential, User};

pub type AuthContext = axum_login::extractors::AuthContext<i32, User, PostgresStore<User>>;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
    #[error("User Already Exists")]
    UserAlreadyExists,
    #[error("Invalid Username")]
    InvalidUsername,
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

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::CorruptSession => (StatusCode::INTERNAL_SERVER_ERROR, "Corrupt Session"),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "No such user exists"),
            AuthError::Unknown => (StatusCode::INTERNAL_SERVER_ERROR, "Unknown Error"),
            AuthError::UserHasNoCredentials => (StatusCode::NOT_FOUND, "User has no credentials"),
            AuthError::UserAlreadyExists => (StatusCode::CONFLICT, "This username is already taken"),
            AuthError::InvalidUsername => (StatusCode::UNPROCESSABLE_ENTITY, "Username is invalid"),
        };

        status.into_response()
    }
}

pub async fn start_register(
    Extension(state): Extension<AuthState>,
    mut session: WritableSession,
    Path(username): Path<String>,
    State(db): State<PgPool>,
) -> Result<impl IntoResponse, AuthError> {
    let user_unique_id = Uuid::new_v4();

    // Make sure username is valid (doesn't contain spaces, only alphanumeric, etc.)
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AuthError::InvalidUsername);
    }

    // Make sure username is not already taken
    let user = sqlx::query_as::<Postgres, User>("SELECT * FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&db)
        .await
        .expect("Failed to pull user from database");
    if user.is_some() {
        return Err(AuthError::UserAlreadyExists);
    }

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
            return Err(AuthError::Unknown);
        }
    };

    Ok(res)
}

pub async fn finish_register(
    Extension(state): Extension<AuthState>,
    mut session: WritableSession,
    State(db): State<PgPool>,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, AuthError> {
    info!("Attempting to complete registration");
    let (username, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) = session
        .get("reg_state")
        .ok_or(AuthError::CorruptSession)?;
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

pub async fn start_authentication(
    Extension(state): Extension<AuthState>,
    mut session: WritableSession,
    Path(username): Path<String>,
    State(db): State<PgPool>,
) -> Result<impl IntoResponse, AuthError> {

    session.remove("auth_state");

    // Get the user from the database if it exists.
    let user = {
        sqlx::query_as::<Postgres, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&db)
            .await
            .unwrap()
            .ok_or(AuthError::UserNotFound)?
    };

    let passkeys: Vec<Passkey> = {
        sqlx::query_as::<Postgres, Credential>("SELECT * FROM credentials WHERE user_uuid = $1")
            .bind(user.uuid)
            .fetch_all(&db)
            .await
            .expect("Failed to pull existing credentials")
            .iter()
            .map(|cred| cred.passkey.0.clone())
            .collect()
    };

    let allow_credentials = passkeys.as_slice();

    let res = match state.webauthn.start_passkey_authentication(allow_credentials) {
        Ok((rcr, auth_state)) => {
            session
                .insert("auth_state", (user.uuid, auth_state, user))
                .expect("Failed to insert");
            info!("Successfully started authentication!");
            Json(rcr)
        }
        Err(e) => {
            debug!("challenge_authenticate -> {:?}", e);
            return Err(AuthError::Unknown);
        }
    };

    Ok(res)
}

pub async fn finish_authentication(
    Extension(state): Extension<AuthState>,
    mut session: WritableSession,
    mut auth_provider: AuthContext,
    State(db): State<PgPool>,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, AuthError> {

    info!("Attempting to complete authentication");
    let (user_unique_id, auth_state, user): (Uuid, PasskeyAuthentication, User) = session
        .get("auth_state")
        .ok_or(AuthError::CorruptSession)?;
    info!("Got authentication state from session");

    session.remove("auth_state");

    let res = match state.webauthn.finish_passkey_authentication(&auth, &auth_state) {
        Ok(auth_result) => {
            // Update the credential counter if needed.
            // Unlikely to be necessary since most passkeys don't even have a mechanism
            // for holding their count, but should be handled regardless just in case 🤞
            if auth_result.needs_update() {
                let mut credentials = {
                    sqlx::query_as::<Postgres, Credential>("SELECT * FROM credentials WHERE user_uuid = $1")
                        .bind(user_unique_id)
                        .fetch_all(&db)
                        .await
                        .expect("Failed to pull existing credentials")
                };

                for cred in credentials.iter_mut() {
                    let is_valid_credential = cred.passkey.update_credential(&auth_result);
                    if let Some(updated) = is_valid_credential {
                        if updated {
                            sqlx::query("UPDATE credentials SET passkey = $1 WHERE id = $2")
                                .bind(cred.passkey.clone())
                                .bind(cred.id.clone())
                                .execute(&db)
                                .await
                                .expect("Could not update passkey");
                            break;
                        }
                    }
                }
            }

            // We need to drop our current handle or the auth_provide will deadlock us when it
            // tries to grab a lock on the session.
            drop(session);

            auth_provider.login(&user).await.expect("Failed to sign in user via session.");
            info!("User successfully logged in: {:?}", user);

            StatusCode::OK
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}