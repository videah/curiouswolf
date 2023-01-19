mod htmx;
mod api;

use axum::{routing::get, routing::post, Router};
use sync_wrapper::SyncWrapper;
use askama::Template;
use sqlx::PgPool;

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

    let router = Router::new()
        .route("/", get(index))
        .route("/hello", post(api::hello));
    let sync_wrapper = SyncWrapper::new(router);

    Ok(sync_wrapper)
}