use axum::extract::{Path, State};
use axum::{Form, Json};
use http::HeaderMap;
use sqlx::{PgPool, Postgres};

use serde::Deserialize;
use urlencoding::decode;
use crate::auth::AuthContext;

use crate::htmx;
use crate::models::{Answer, Question, User};

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

    // Make sure the question body string is not empty
    if form.body.is_empty() {
        panic!("Question body cannot be empty");
    }

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
        body: format!("Question sent! @{} will hopefully read and answer it soon.", user.username),
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

#[derive(Deserialize)]
pub struct PostAnswer {
    question_id: i32,
}

pub async fn post_answer(
    headers: HeaderMap,
    Path(id): Path<i32>,
    State(db): State<PgPool>,
) -> htmx::Banner {
    let body = headers.get("HX-Prompt").unwrap().to_str().unwrap();
    let decoded = decode(body).unwrap().into_owned();

    let query = r#"
        INSERT INTO answers
            ( body, question_id )
        VALUES
            ( $1, $2 )
        RETURNING *
    "#;

    let question = sqlx::query_as::<Postgres, Answer>(query)
        .bind(decoded)
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Banner {
        body: "Answer posted!".to_string(),
    }
}

pub async fn delete_answer(
    Path(id): Path<i32>,
    State(db): State<PgPool>,
    auth: AuthContext,
) -> htmx::Empty {

    let query = r#"
        DELETE FROM answers
        WHERE
            id = $1
            AND question_id IN (
                SELECT id FROM questions
                WHERE recipient_id = $2
            )
        RETURNING *
    "#;

    info!("Deleting answer with id {}", id);
    let answer = sqlx::query_as::<Postgres, Answer>(query)
        .bind(id)
        .bind(auth.current_user.unwrap().id)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Empty {}
}