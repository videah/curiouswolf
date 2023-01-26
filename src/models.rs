use std::fmt::Display;
use axum::Extension;
use axum::extract::FromRequestParts;
use sqlx::FromRow;
use sqlx::types::Json;
use webauthn_rs::prelude::{Passkey, Uuid};
use async_trait::async_trait;

use axum_login::{
    axum_sessions::{async_session::MemoryStore, SessionLayer},
    secrecy::SecretVec,
    AuthLayer, AuthUser, RequireAuthorizationLayer,
};

use axum_sessions::async_session::chrono::{DateTime, NaiveDateTime, Utc};
use http::request::Parts;
use http::StatusCode;

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

#[derive(Debug, FromRow)]
pub struct Credential {
    pub id: i32,
    pub user_uuid: Uuid,
    pub passkey: Json<Passkey>,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "role", rename_all = "lowercase")]
pub enum Role {
    User,
    Admin,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub uuid: Uuid,
    pub username: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthUser<i32, Role> for User {
    fn get_id(&self) -> i32 {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.username.clone().into())
    }

    fn get_role(&self) -> Option<Role> {
        Some(self.role.clone())
    }
}

pub struct RequireAdmin(pub User);

#[async_trait]
impl<S> FromRequestParts<S> for RequireAdmin
    where
        S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        info!("RequireAdmin::from_request_parts");
        let Extension(user): Extension<User> = Extension::from_request_parts(parts, state)
            .await
            .map_err(|_err| StatusCode::FORBIDDEN)?;

        info!("User: {:?}", user);

        if user
            .get_role()
            .map_or(false, |role| matches!(role, Role::Admin))
        {
            Ok(RequireAdmin(user))
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleAppSiteAssociation {
    pub applinks: DetailedAppList,
    pub webcredentials: AppList,
    pub appclips: AppList,
}

impl AppleAppSiteAssociation {
    pub fn new(apps: Vec<String>) -> Self {
        Self {
            applinks: DetailedAppList { details: vec![] },
            webcredentials: AppList { apps },
            appclips: AppList { apps: vec![] },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppList {
    pub apps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedAppList {
    // TODO: Placeholder, implement this properly
    pub details: Vec<String>,
}