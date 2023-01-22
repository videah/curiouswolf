use askama::Template;

#[derive(Template)]
#[template(path = "htmx/hello-world.html")]
pub struct HelloWorld;

#[derive(Template)]
#[template(path = "htmx/empty.html")]
pub struct Empty;

#[derive(Template)]
#[template(path = "htmx/question.html")]
pub struct Question {
    pub question: crate::models::Question,
}

#[derive(Template)]
#[template(path = "htmx/banner.html")]
pub struct Banner {
    pub body: &'static str,
}