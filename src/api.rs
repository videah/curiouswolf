use axum::extract::{Path, State};
use axum::Json;
use sqlx::{PgPool, Postgres};

use crate::htmx;
use crate::models::User;

pub async fn hello() -> htmx::HelloWorld {
    htmx::HelloWorld {}
}

pub async fn user(
    Path(username): Path<String>,
    State(db): State<PgPool>,
) -> Json<User> {
    // Get the user from the database if it exists.
    let user = {
        sqlx::query_as::<Postgres, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&db)
            .await
            .unwrap()
            .unwrap()
    };

    Json(user)
}