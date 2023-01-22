mod htmx;
mod auth;
mod models;
mod ogp;
mod api;

use std::path::PathBuf;
use axum::{routing::get, routing::post, routing::put, Router, Extension};
use sync_wrapper::SyncWrapper;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::Redirect;
use axum_extra::routing::SpaRouter;
use axum_login::{AuthLayer, PostgresStore};
use axum_login::axum_sessions::async_session::MemoryStore;
use axum_sessions::{SameSite, SessionLayer};
use sqlx::{PgPool, Postgres};

use dotenv::dotenv;

use rand::prelude::*;
use crate::auth::{AuthContext, AuthState};
use crate::models::User;

#[macro_use]
extern crate tracing;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    pub current_user: Option<User>,
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPage {
    pub current_user: Option<User>
}

#[derive(Template)]
#[template(path = "sign_in.html")]
struct SignInPage {
    pub current_user: Option<User>,
}

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfilePage {
    pub current_user: Option<User>,
    pub user: User,
}

async fn index(auth: AuthContext) -> IndexPage {
    IndexPage {
        current_user: auth.current_user
    }
}

async fn register() -> RegisterPage {
    RegisterPage {
        current_user: None,
    }
}

async fn sign_in() -> SignInPage {
    SignInPage {
        current_user: None,
    }
}

async fn profile(
    auth: AuthContext,
    Path(username): Path<String>,
    State(db): State<PgPool>,
) -> ProfilePage {
    let user = sqlx::query_as::<Postgres, User>("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(&db)
        .await
        .unwrap()
        .unwrap();

    ProfilePage {
        current_user: auth.current_user,
        user
    }
}

async fn sign_out(mut auth: AuthContext) -> Redirect {
    let user = auth.current_user.clone();
    if let Some(user) = user {
        auth.logout().await;
        info!("User logged out: {:?}", user);
    }
    Redirect::permanent("/")
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
    let session_store = MemoryStore::new();
    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(session_store, &secret)
        .with_cookie_name("curiouswolf")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(true);


    let user_store = PostgresStore::<User>::new(pool.clone());
    let auth_layer = AuthLayer::new(user_store, &secret);
    let auth_state = AuthState::new();

    let router = Router::new()
        .merge(SpaRouter::new("/static", static_folder))
        .route("/", get(index))
        .route("/register", get(register))
        .route("/sign-in", get(sign_in))
        .route("/sign-out", get(sign_out))
        .route("/auth/register_start/:username", post(auth::start_register))
        .route("/auth/register_finish", post(auth::finish_register))
        .route("/auth/authenticate_start/:username", post(auth::start_authentication))
        .route("/auth/authenticate_finish", post(auth::finish_authentication))
        .route("/@:user", get(profile))
        .route("/ogp/image/:text", get(ogp::render_open_graph_card))
        .route("/htmx/question", put(api::htmx::post_question))
        .layer(Extension(auth_state))
        .with_state(pool)
        .layer(auth_layer)
        .layer(session_layer);

    let sync_wrapper = SyncWrapper::new(router);

    Ok(sync_wrapper)
}