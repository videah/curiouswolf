use axum::extract::Path;
use axum::response::{IntoResponse, IntoResponseParts, ResponseParts};
use http::{HeaderMap, StatusCode};
use resvg::tiny_skia::Pixmap;
use resvg::usvg::{Tree, Options};
use resvg::usvg_text_layout::{fontdb, TreeTextToPath};

pub async fn render_open_graph_card(Path(text): Path<String>,) -> impl IntoResponse {
    let mut fontdb = fontdb::Database::new();
    fontdb.load_system_fonts();

    let svg = format!(r#"
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 viewBox="0 0 1200 630" style="enable-background:new 0 0 1200 630;" xml:space="preserve">
<style type="text/css">
	.st0{{fill:#2E2E2F;stroke:#000000;stroke-miterlimit:10;}}
	.st1{{fill:#FFFFFF;}}
	.st2{{font-family:'Helvetica';}}
	.st3{{font-size:72px;}}
	.st4{{font-size:48px;}}
</style>
<rect class="st0" width="1200" height="630"/>
<text font-weight="bold" transform="matrix(1 0 0 1 32 93.8223)" class="st1 st2 st3">curiouswolf</text>
<text transform="matrix(1 0 0 1 31.9998 189.9102)" class="st1 st2 st4">{text}</text>
</svg>
    "#);

    let opt = Options::default();
    let mut tree = Tree::from_data(svg.as_ref(), &opt).unwrap();
    tree.convert_text(&fontdb, opt.keep_named_groups);

    let pixmap_size = tree.size.to_screen_size();
    let mut pixmap = Pixmap::new(pixmap_size.width(), pixmap_size.height()).unwrap();
    resvg::render(
        &tree,
        resvg::usvg::FitTo::Original,
        resvg::tiny_skia::Transform::default(),
        pixmap.as_mut(),
    ).unwrap();
    let rendered_image = pixmap.encode_png().unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, "image/png".parse().unwrap());

    (headers, rendered_image)
}