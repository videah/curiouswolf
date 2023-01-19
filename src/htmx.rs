use askama::Template;

#[derive(Template)]
#[template(path = "htmx/hello-world.html")]
pub struct HelloWorld;