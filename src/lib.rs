mod htmx;
mod api;
mod auth;
mod models;

use std::path::PathBuf;
use axum::{routing::get, routing::post, Router, Extension};
use sync_wrapper::SyncWrapper;
use askama::Template;
use axum_extra::routing::SpaRouter;
use axum_sessions::async_session::MemoryStore;
use axum_sessions::{SameSite, SessionLayer};
use sqlx::PgPool;

use dotenv::dotenv;

use rand::prelude::*;
use crate::auth::AuthState;

#[macro_use]
extern crate tracing;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage;

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPage;

async fn index() -> IndexPage {
    IndexPage {}
}

async fn login() -> RegisterPage {
    RegisterPage {}
}

#[shuttle_service::main]
async fn axum(
    #[shuttle_shared_db::Postgres] pool: PgPool,
    #[shuttle_static_folder::StaticFolder] static_folder: PathBuf,
) -> shuttle_service::ShuttleAxum {

    dotenv().ok();

    println!("Running database migrations...");
    sqlx::migrate!().run(&pool).await.unwrap();
    println!("All migrations ran successfully!");

    println!("Creating session memory store");
    let store = MemoryStore::new();
    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(store, &secret)
        .with_cookie_name("curiouswolf")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(true);

    let auth_state = AuthState::new();

    let router = Router::new()
        .merge(SpaRouter::new("/static", static_folder))
        .route("/", get(index))
        .route("/register", get(login))
        .route("/auth/register_start/:username", post(auth::start_register))
        .route("/auth/register_finish", post(auth::finish_register))
        .layer(Extension(auth_state))
        .with_state(pool)
        .layer(session_layer);

    let sync_wrapper = SyncWrapper::new(router);

    Ok(sync_wrapper)
}