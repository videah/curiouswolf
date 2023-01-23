use axum::extract::{Path, State};
use axum::{Form, Json};
use sqlx::{PgPool, Postgres};

use serde::Deserialize;
use crate::auth::AuthContext;

use crate::htmx;
use crate::models::{Question, User};

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

#[derive(Deserialize)]
pub struct PostQuestion {
    username: String,
    body: String,
}

pub async fn post_question(
    State(db): State<PgPool>,
    form: Form<PostQuestion>,
) -> htmx::Banner {
    let form = form.0;

    let user_query = r#"
        SELECT * FROM users
        WHERE username = $1
    "#;

    let user = sqlx::query_as::<Postgres, User>(user_query)
        .bind(form.username)
        .fetch_one(&db)
        .await
        .unwrap();

    let query = r#"
        INSERT INTO questions
            ( body, recipient_id )
        VALUES
            ( $1, $2 )
        RETURNING *
    "#;

    let question = sqlx::query_as::<Postgres, Question>(query)
        .bind(form.body)
        .bind(user.id)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Banner {
        body: "Question posted!",
    }
}

#[derive(Deserialize)]
pub struct DeleteQuestion {
    id: i32,
}

pub async fn delete_question(
    State(db): State<PgPool>,
    Path(id): Path<i32>,
    mut auth: AuthContext,
) -> htmx::Empty {

    let query = r#"
        DELETE FROM questions
        WHERE
            id = $1
            AND recipient_id = $2
        RETURNING *
    "#;

    let question = sqlx::query_as::<Postgres, Question>(query)
        .bind(id)
        .bind(auth.current_user.unwrap().id)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Empty {}
}