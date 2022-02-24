use axum::{extract::MatchedPath, middleware::Next, response::IntoResponse};
use http::{header, Request};
use std::time::Instant;

pub(crate) async fn track_metrics<B>(req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let start = Instant::now();
    let path = path(&req).to_owned();
    let method = req.method().clone();

    let res = next.run(req).await;

    let latency = start.elapsed().as_secs_f64();
    let status = res.status().as_u16().to_string();
    let labels = [
        ("method", method.to_string()),
        ("path", path),
        ("status", status),
    ];

    metrics::increment_counter!("http_requests_total", &labels);
    metrics::histogram!("http_requests_duration_seconds", latency, &labels);

    res
}

fn path<B>(req: &Request<B>) -> &str {
    if is_grpc(req) {
        req.uri().path()
    } else if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        let path = matched_path.as_str();

        // In axum, if you nest an opaque `Service` at "/" then that will hijack all requests and
        // the matched path in the route will simply be `/*axum_nest`. This is what
        // `Server::with_service` does.
        //
        // So if the matched path starts with a wildcard then we don't have the pattern for the
        // route (such as `/users/:id`) but have to instead use the literal URI on the request.
        if path.starts_with("/*") {
            req.uri().path()
        } else {
            path
        }
    } else {
        req.uri().path()
    }
}

fn is_grpc<B>(req: &Request<B>) -> bool {
    if let Some(content_type) = content_type(req) {
        content_type.starts_with("application/grpc")
    } else {
        false
    }
}

fn content_type<B>(req: &Request<B>) -> Option<&str> {
    req.headers().get(header::CONTENT_TYPE)?.to_str().ok()
}
