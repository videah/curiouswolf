use axum::extract::{Path, State};
use axum::{Form, Json};
use sqlx::{PgPool, Postgres};

use serde::Deserialize;

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
    body: String,
}

pub async fn post_question(
    State(db): State<PgPool>,
    form: Form<PostQuestion>,
) -> htmx::Banner {
    let form = form.0;

    let query = r#"
        INSERT INTO questions
            ( body, recipient_id )
        VALUES
            ( $1, $2 )
        RETURNING *
    "#;

    let question = sqlx::query_as::<Postgres, Question>(query)
        .bind(form.body)
        .bind(1)
        .fetch_one(&db)
        .await
        .unwrap();

    htmx::Banner {
        body: "Question posted!",
    }
}