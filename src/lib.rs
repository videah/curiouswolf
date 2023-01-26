mod htmx;
mod auth;
mod models;
mod ogp;
mod api;

use std::cmp::Reverse;
use std::path::PathBuf;
use axum::{routing::get, routing::post, routing::put, routing::delete, Router, Extension, Json};
use sync_wrapper::SyncWrapper;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::Redirect;
use axum_extra::routing::SpaRouter;
use axum_login::{AuthLayer, PostgresStore, RequireAuthorizationLayer};
use axum_login::axum_sessions::async_session::MemoryStore;
use axum_sessions::{SameSite, SessionLayer};
use sqlx::{PgPool, Postgres};

use shuttle_secrets::SecretStore;

use rand::prelude::*;
use serde::Serialize;
use crate::auth::{AuthContext, AuthState};
use crate::models::{Answer, AppleAppSiteAssociation, Question, RequireAdmin, Role, User};

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
    pub answers: Vec<(Question, Answer)>,
}

#[derive(Template)]
#[template(path = "inbox.html")]
struct InboxPage {
    pub current_user: Option<User>,
    pub questions: Vec<Question>,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminPage {
    pub current_user: Option<User>,
    pub users: Vec<User>,
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

    let user_query = r#"
        SELECT * FROM users
        WHERE lower(username) = lower($1)
    "#;

    let user = sqlx::query_as::<Postgres, User>(user_query)
        .bind(username)
        .fetch_optional(&db)
        .await
        .unwrap()
        .unwrap();

    // Get all questions with an answer
    let question_query = r#"
        SELECT * FROM questions
        WHERE recipient_id = $1
        AND EXISTS (
            SELECT * FROM answers
            WHERE answers.question_id = questions.id
        )
        ORDER BY created_at DESC
    "#;

    let questions = sqlx::query_as::<Postgres, Question>(question_query)
        .bind(user.id)
        .fetch_all(&db)
        .await
        .unwrap();

    // Get list of question ids
    let question_ids: Vec<i32> = questions.iter().map(|q| q.id).collect();
    println!("{:?}", question_ids);

    // Get answers for each question
    let answer_query = r#"
        SELECT answers.id, answers.* FROM answers
        JOIN unnest($1::int[]) WITH ORDINALITY AS qid(id, ord)
            ON answers.question_id = qid.id
        ORDER BY qid.ord
    "#;

    let answers = sqlx::query_as::<Postgres, Answer>(answer_query)
        .bind(&question_ids[..])
        .fetch_all(&db)
        .await
        .unwrap();

    // Create a vector of QnAPairs
    let mut pairs: Vec<(Question, Answer)> = questions
        .into_iter()
        .zip(answers.into_iter())
        .collect();

    pairs.sort_by_key(|(_, a)| Reverse(a.created_at));

    ProfilePage {
        current_user: auth.current_user,
        user,
        answers: pairs,
    }
}

async fn inbox(
    auth: AuthContext,
    State(db): State<PgPool>,
) -> InboxPage {

    let query = r#"
        SELECT * FROM questions
        WHERE recipient_id = $1
        AND NOT EXISTS (
            SELECT * FROM answers
            WHERE answers.question_id = questions.id
        )
    "#;

    let mut questions = sqlx::query_as::<Postgres, Question>(query)
        .bind(auth.current_user.clone().unwrap().id)
        .fetch_all(&db)
        .await
        .unwrap();

    questions.sort_by_key(|q| Reverse(q.created_at));

    InboxPage {
        current_user: auth.current_user,
        questions
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

async fn admin(
    RequireAdmin(user): RequireAdmin,
    State(db): State<PgPool>,
) -> AdminPage {

    let users = sqlx::query_as::<Postgres, User>("SELECT * FROM users")
        .fetch_all(&db)
        .await
        .unwrap();

    AdminPage {
        current_user: Some(user),
        users,
    }
}

async fn apple_association_file(Extension(state): Extension<AuthState>) -> String {
    let file = AppleAppSiteAssociation::new(vec![state.appid]);
    serde_json::to_string(&file).unwrap()
}

#[shuttle_service::main]
async fn axum(
    #[shuttle_shared_db::Postgres] pool: PgPool,
    #[shuttle_static_folder::StaticFolder] static_folder: PathBuf,
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_service::ShuttleAxum {
    let hostname = secret_store.get("CURIOUSWOLF_HOSTNAME").unwrap();
    let appid = secret_store.get("CURIOUSWOLF_APPID").unwrap();

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

    let user_store = PostgresStore::<User, Role>::new(pool.clone());
    let auth_layer = AuthLayer::new(user_store, &secret);
    let auth_state = AuthState::new(hostname, appid);

    let router = Router::new()
        .route("/admin", get(admin))
        .route_layer(RequireAuthorizationLayer::<i32, User, Role>::login())
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
        .route("/inbox", get(inbox))
        .route("/ogp/image/:text", get(ogp::render_open_graph_card))
        .route("/htmx/question", put(api::htmx::post_question))
        .route("/htmx/question/:id", delete(api::htmx::delete_question))
        .route("/htmx/answer/:id", put(api::htmx::post_answer))
        .route("/htmx/answer/:id", delete(api::htmx::delete_answer))
        .route("/.well-known/apple-app-site-association", get(apple_association_file))
        .layer(Extension(auth_state))
        .with_state(pool)
        .layer(auth_layer)
        .layer(session_layer);

    let sync_wrapper = SyncWrapper::new(router);

    Ok(sync_wrapper)
}