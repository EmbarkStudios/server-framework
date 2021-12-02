use axum::{extract::Extension, BoxError};
use http::{Method, StatusCode, Uri};
use std::future::{ready, Ready};
use tower_http::request_id::RequestId;

#[allow(unreachable_pub)]
pub type DefaultErrorHandler =
    fn(Method, Uri, Extension<RequestId>, BoxError) -> std::future::Ready<(StatusCode, String)>;

pub(crate) fn default_error_handler(
    method: Method,
    uri: Uri,
    Extension(request_id): Extension<RequestId>,
    err: BoxError,
) -> Ready<(StatusCode, String)> {
    if let Ok(request_id) = request_id.header_value().to_str() {
        tracing::error!(
            %err,
            %method,
            %uri,
            request_id = %request_id,
            "error from middleware",
        );
    } else {
        tracing::error!(
            %err,
            %method,
            %uri,
            "error from middleware",
        );
    }

    if err.is::<tower::timeout::error::Elapsed>() {
        ready((
            StatusCode::REQUEST_TIMEOUT,
            "Request took too long".to_string(),
        ))
    } else {
        ready((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", err),
        ))
    }
}
