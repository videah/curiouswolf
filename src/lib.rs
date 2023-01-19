mod htmx;
mod api;
mod auth;
mod models;

use axum::{routing::get, routing::post, Router};
use sync_wrapper::SyncWrapper;
use askama::Template;
use axum_sessions::async_session::MemoryStore;
use axum_sessions::{SameSite, SessionLayer};
use sqlx::PgPool;

use rand::prelude::*;

#[macro_use]
extern crate tracing;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

async fn index() -> IndexTemplate {
    IndexTemplate {}
}

#[shuttle_service::main]
async fn axum(#[shuttle_shared_db::Postgres] pool: PgPool) -> shuttle_service::ShuttleAxum {

    println!("Running database migrations...");
    sqlx::migrate!().run(&pool).await.unwrap();
    println!("All migrations ran successfully!");

    println!("Creating session memory store");
    let store = MemoryStore::new();
    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(store, &secret)
        .with_cookie_name("")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(true);

    let router = Router::new()
        .route("/", get(index))
        .route("/hello", post(api::hello))
        .layer(session_layer)
        .with_state(pool);

    let sync_wrapper = SyncWrapper::new(router);

    Ok(sync_wrapper)
}