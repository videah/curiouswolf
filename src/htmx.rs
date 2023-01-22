use askama::Template;

#[derive(Template)]
#[template(path = "htmx/hello-world.html")]
pub struct HelloWorld;

#[derive(Template)]
#[template(path = "htmx/question.html")]
pub struct Question {
    pub question: crate::models::Question,
}