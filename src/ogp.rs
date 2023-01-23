use std::io::Cursor;
use axum::extract::{Path, Query};
use axum::response::{IntoResponse, IntoResponseParts, ResponseParts};
use http::{HeaderMap, StatusCode};
use image::DynamicImage;

use og_image_writer::{style, writer::OGImageWriter};
use og_image_writer::img::ImageInputFormat;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ImageQuery {
    pub is_twitter: Option<bool>,
}

pub async fn render_open_graph_card(
    Query(query): Query<ImageQuery>,
    Path(text): Path<String>,
) -> impl IntoResponse {
    let text = format!("Ask {} a question", text);
    let card = include_bytes!("../assets/ogp_template.png");
    let card_twitter = include_bytes!("../assets/ogp_template_twitter.png");

    let mut writer = OGImageWriter::from_data(
        style::WindowStyle {
            align_items: style::AlignItems::Center,
            justify_content: style::JustifyContent::Center,
            ..style::WindowStyle::default()
        },
        if query.is_twitter.unwrap_or(false) {
            card_twitter
        } else {
            card
        },
        ImageInputFormat::Png
    ).unwrap();

    let font = Vec::from(include_bytes!("../assets/helvetica.ttf") as &[u8]);

    writer.set_text(
        &text,
        style::Style {
            margin: style::Margin(0, 20, 0, 20),
            line_height: 2.4,
            font_size: 100.,
            word_break: style::WordBreak::Normal,
            color: style::Rgba([255, 255, 255, 255]),
            text_align: style::TextAlign::Center,
            white_space: style::WhiteSpace::PreLine,
            ..style::Style::default()
        },
        Some(font),
    ).unwrap();

    writer.paint().unwrap();
    let rendered_image = writer.into_rgba().unwrap();

    let mut w = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(rendered_image)
        .write_to(&mut w, image::ImageOutputFormat::Png)
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, "image/png".parse().unwrap());

    (headers, w.into_inner())
}