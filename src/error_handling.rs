use axum::{extract::Extension, response::IntoResponse, BoxError};
use http::{header::CONTENT_TYPE, HeaderMap, Method, StatusCode, Uri};
use std::future::{ready, Ready};
use tower_http::request_id::RequestId;

#[allow(unreachable_pub)]
pub type DefaultErrorHandler = fn(
    Method,
    Uri,
    HeaderMap,
    Extension<RequestId>,
    Extension<TimeoutSec>,
    BoxError,
) -> Ready<axum::response::Response>;

#[cfg(feature = "tonic")]
fn timeout_response(is_grpc: bool) -> axum::response::Response {
    if is_grpc {
        // Deadline exceeded isn't _completely_ accurate here since the timeout isn't
        // propagated to downstream services but it's the most accurate status code we can
        // provide
        let response = tonic::Status::deadline_exceeded("request timed out");
        // Grpc have internal status codes which differ from the HTTP status codes
        (StatusCode::OK, response.to_http()).into_response()
    } else {
        (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response()
    }
}

#[cfg(not(feature = "tonic"))]
fn timeout_response(_is_grpc: bool) -> axum::response::Response {
    (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response()
}

#[cfg(feature = "tonic")]
fn internal_error_response(is_grpc: bool, body: String) -> axum::response::Response {
    if is_grpc {
        let response = tonic::Status::internal(body);
        // Grpc have internal status codes which differ from the HTTP status codes
        (StatusCode::OK, response.to_http()).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[cfg(not(feature = "tonic"))]
fn internal_error_response(_is_grpc: bool, body: String) -> axum::response::Response {
    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
}

pub(crate) fn default_error_handler(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Extension(TimeoutSec(timeout_sec)): Extension<TimeoutSec>,
    err: BoxError,
) -> Ready<axum::response::Response> {
    let request_id = request_id
        .header_value()
        .to_str()
        .unwrap_or("<mising request id>");

    let is_grpc = headers
        .get(CONTENT_TYPE)
        .map(|content_type| {
            content_type
                .to_str()
                .unwrap_or_default()
                .starts_with("application/grpc")
        })
        .unwrap_or_default();

    if err.is::<tower::timeout::error::Elapsed>() {
        tracing::warn!(
            %method,
            %uri,
            request_id = %request_id,
            timeout_sec = %timeout_sec,
            "{}",
            error_display_chain(&*err)
        );

        ready(timeout_response(is_grpc))
    } else {
        tracing::error!(
            err = %error_display_chain(&*err),
            %method,
            %uri,
            request_id = %request_id,
            "{}",
            error_display_chain(&*err)
        );

        let body = format!("Unhandled internal error: {}", err);
        ready(internal_error_response(is_grpc, body))
    }
}

pub(crate) fn error_display_chain(error: &dyn std::error::Error) -> String {
    let mut s = error.to_string();
    if let Some(source) = error.source() {
        s.push_str(" -> ");
        s.push_str(&error_display_chain(source));
    }
    s
}

#[derive(Clone, Copy, Debug)]
#[allow(unreachable_pub)]
pub struct TimeoutSec(pub(crate) u64);
