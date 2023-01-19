use sqlx::FromRow;
use sqlx::types::Json;
use webauthn_rs::prelude::Passkey;

#[derive(Debug, FromRow)]
pub struct Credential {
    pub id: i32,
    pub user_id: i32,
    pub passkey: Json<Passkey>,
}

#[derive(Debug, FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
}