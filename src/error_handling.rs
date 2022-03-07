use axum::{extract::Extension, BoxError};
use http::{Method, StatusCode, Uri};
use std::future::{ready, Ready};
use tower_http::request_id::RequestId;

#[allow(unreachable_pub)]
pub type DefaultErrorHandler = fn(
    Method,
    Uri,
    Extension<RequestId>,
    Extension<TimeoutSec>,
    BoxError,
) -> Ready<(StatusCode, String)>;

pub(crate) fn default_error_handler(
    method: Method,
    uri: Uri,
    Extension(request_id): Extension<RequestId>,
    Extension(TimeoutSec(timeout_sec)): Extension<TimeoutSec>,
    err: BoxError,
) -> Ready<(StatusCode, String)> {
    let request_id = request_id
        .header_value()
        .to_str()
        .unwrap_or("<mising request id>");

    if err.is::<tower::timeout::error::Elapsed>() {
        tracing::error!(
            %method,
            %uri,
            request_id = %request_id,
            timeout_sec = %timeout_sec,
            "{}",
            error_display_chain(&*err)
        );

        ready((
            StatusCode::REQUEST_TIMEOUT,
            "Request took too long".to_string(),
        ))
    } else {
        tracing::error!(
            err = %error_display_chain(&*err),
            %method,
            %uri,
            request_id = %request_id,
            "{}",
            error_display_chain(&*err)
        );

        ready((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", err),
        ))
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
