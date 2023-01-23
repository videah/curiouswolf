use sqlx::FromRow;
use sqlx::types::Json;
use webauthn_rs::prelude::{Passkey, Uuid};

use axum_login::{
    axum_sessions::{async_session::MemoryStore, SessionLayer},
    secrecy::SecretVec,
    AuthLayer, AuthUser, RequireAuthorizationLayer,
};

use axum_sessions::async_session::chrono::{DateTime, NaiveDateTime, Utc};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, FromRow)]
pub struct Question {
    pub id: i32,
    pub body: String,
    pub recipient_id: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Answer {
    pub id: i32,
    pub body: String,
    pub question_id: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct QnAPair {
    pub question: Question,
    pub answer: Answer,
}

#[derive(Debug, FromRow)]
pub struct Credential {
    pub id: i32,
    pub user_uuid: Uuid,
    pub passkey: Json<Passkey>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub uuid: Uuid,
    pub username: String,
}

impl AuthUser<i32> for User {
    fn get_id(&self) -> i32 {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.username.clone().into())
    }
}