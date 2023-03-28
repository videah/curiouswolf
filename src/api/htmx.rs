use axum::extract::{Path, State};
use axum::{Extension, Form, Json};
use futures::future::join_all;
use http::HeaderMap;
use sqlx::{PgPool, Postgres};

use serde::Deserialize;
use urlencoding::decode;
use crate::auth::AuthContext;

use crate::htmx;
use crate::models::{Answer, Question, User};
use crate::web_push::{PushSubscription, WebPushState};

pub async fn hello() -> htmx::HelloWorld {
    htmx::HelloWorld {}
}

pub async fn user(
    Path(username): Path<String>,
    State(db): State<PgPool>,
) -> Json<User> {

    // Get the user from the database if it exists.
    let user_query = r#"
        SELECT * FROM users
        WHERE lower(username) = lower($1)
    "#;

    let user = {
        sqlx::query_as::<Postgres, User>(user_query)
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
    Extension(state): Extension<WebPushState>,
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

    sqlx::query_as::<Postgres, Question>(query)
        .bind(&form.body)
        .bind(user.id)
        .fetch_one(&db)
        .await
        .unwrap();

    // Send push notifications to the user
    if state.vapid_public_key.is_some() && state.vapid_private_key.is_some() {
        let username = user.username.clone();
        tokio::spawn(async move {
            // Get all push subscriptions for the user
            let query = r#"
            SELECT * FROM push_subscriptions
            WHERE user_id = $1
        "#;

            let subscriptions = sqlx::query_as::<Postgres, PushSubscription>(query)
                .bind(user.id)
                .fetch_all(&db)
                .await
                .unwrap();

            // Send a push notification to each subscription
            let message = format!("You have a new question @{}!\n{}", username, form.body);

            // Get a future for each subscription
            let key = state.vapid_private_key.unwrap();
            let futures = subscriptions.iter().map(|subscription| {
                subscription.send_message(&key, &message)
            });

            // Wait for all futures to complete
            join_all(futures).await;
        });
    }

    htmx::Banner {
        body: format!("Question sent! @{} will hopefully read and answer it soon.", user.username),
    }
}

pub async fn delete_question(
    State(db): State<PgPool>,
    Path(id): Path<i32>,
    auth: AuthContext,
) -> htmx::Empty {

    let query = r#"
        DELETE FROM questions
        WHERE
            id = $1
            AND recipient_id = $2
        RETURNING *
    "#;

    sqlx::query_as::<Postgres, Question>(query)
        .bind(id)
        .bind(auth.current_user.unwrap().id)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Empty {}
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

    sqlx::query_as::<Postgres, Answer>(query)
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
    sqlx::query_as::<Postgres, Answer>(query)
        .bind(id)
        .bind(auth.current_user.unwrap().id)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Empty {}
}