use super::classify::{self, HttpOrGrpcClassification};
use axum::extract::{ConnectInfo, MatchedPath};
use http::{header, uri::Scheme, Method, Request, Response, Version};
use opentelemetry::trace::TraceContextExt;
use std::{borrow::Cow, net::SocketAddr, time::Duration};
use tower_http::{
    request_id::RequestId,
    trace::{MakeSpan, OnEos, OnFailure, OnResponse},
};
use tracing::{field::Empty, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A [`MakeSpan`] that creates tracing spans using [OpenTelemetry's conventional field names][otel].
///
/// [otel]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/http.md
#[derive(Clone, Copy)]
pub(crate) struct OtelMakeSpan;

impl<B> MakeSpan<B> for OtelMakeSpan {
    fn make_span(&mut self, req: &Request<B>) -> Span {
        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .map_or("", |h| h.to_str().unwrap_or(""));

        let host = req
            .headers()
            .get(header::HOST)
            .map_or("", |h| h.to_str().unwrap_or(""));

        let scheme = req
            .uri()
            .scheme()
            .map_or_else(|| "HTTP".into(), http_scheme);

        let http_route = if classify::is_grpc(req.headers()) {
            req.uri().path().to_owned()
        } else if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
            matched_path.as_str().to_owned()
        } else {
            req.uri().path().to_owned()
        };

        let client_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(client_ip)| Cow::from(client_ip.to_string()))
            .unwrap_or_default();

        let request_id = req
            .extensions()
            .get::<RequestId>()
            .and_then(|id| id.header_value().to_str().ok())
            .unwrap_or_default();

        let remote_context = extract_remote_context(req.headers());
        let remote_span = remote_context.span();
        let span_context = remote_span.span_context();
        let trace_id = span_context
            .is_valid()
            .then(|| Cow::from(span_context.trace_id().to_string()))
            .unwrap_or_default();

        let span = tracing::info_span!(
            "HTTP request",
            grpc.code = Empty,
            http.client_ip = %client_ip,
            http.flavor = %http_flavor(req.version()),
            http.host = %host,
            http.method = %http_method(req.method()),
            http.route = %http_route,
            http.scheme = %scheme,
            http.status_code = Empty,
            http.target = %req.uri().path_and_query().map_or("", |p| p.as_str()),
            http.user_agent = %user_agent,
            otel.kind = "server",
            otel.status_code = Empty,
            request_id = request_id,
            trace_id = %trace_id,
        );

        span.set_parent(remote_context);

        span
    }
}

fn http_method(method: &Method) -> Cow<'static, str> {
    match method {
        &Method::CONNECT => "CONNECT".into(),
        &Method::DELETE => "DELETE".into(),
        &Method::GET => "GET".into(),
        &Method::HEAD => "HEAD".into(),
        &Method::OPTIONS => "OPTIONS".into(),
        &Method::PATCH => "PATCH".into(),
        &Method::POST => "POST".into(),
        &Method::PUT => "PUT".into(),
        &Method::TRACE => "TRACE".into(),
        other => other.to_string().into(),
    }
}

fn http_flavor(version: Version) -> Cow<'static, str> {
    match version {
        Version::HTTP_09 => "0.9".into(),
        Version::HTTP_10 => "1.0".into(),
        Version::HTTP_11 => "1.1".into(),
        Version::HTTP_2 => "2.0".into(),
        Version::HTTP_3 => "3.0".into(),
        other => format!("{:?}", other).into(),
    }
}

fn http_scheme(scheme: &Scheme) -> Cow<'static, str> {
    if scheme == &Scheme::HTTP {
        "http".into()
    } else if scheme == &Scheme::HTTPS {
        "https".into()
    } else {
        scheme.to_string().into()
    }
}

// If remote request has no span data the propagator defaults to an unsampled context
fn extract_remote_context(headers: &http::HeaderMap) -> opentelemetry::Context {
    let extractor = opentelemetry_http::HeaderExtractor(headers);
    opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(&extractor))
}

/// Callback that [`Trace`] will call when it receives a response. This is called regardless if the
/// response is classified as a success or failure.
///
/// [`Trace`]: tower_http::trace::TRACE
#[derive(Clone, Debug)]
pub(crate) struct OtelOnResponse;

impl<B> OnResponse<B> for OtelOnResponse {
    fn on_response(self, response: &Response<B>, _latency: Duration, span: &Span) {
        let status = response.status().as_u16().to_string();
        span.record("http.status_code", &tracing::field::display(status));

        if let Some(code) = classify::grpc_code_from_headers(response.headers()) {
            span.record("grpc.code", &code);
        }

        // assume there is no error, if there is `OtelOnFailure` will be called and override this
        span.record("otel.status_code", &"OK");
    }
}

/// Callback that [`Trace`] will call when a streaming response completes. This is called
/// regardless if the stream is classified as a success or failure.
///
/// [`Trace`]: tower_http::trace::TRACE
#[derive(Clone, Debug)]
pub(crate) struct OtelOnEos;

impl OnEos for OtelOnEos {
    fn on_eos(self, trailers: Option<&http::HeaderMap>, _stream_duration: Duration, span: &Span) {
        if let Some(code) = trailers.and_then(classify::grpc_code_from_headers) {
            span.record("grpc.code", &code);
        }
    }
}

/// Callback that [`Trace`] will call when a response or end-of-stream is classified as a failure.
///
/// Since we require all services and middleware to be infallible this will never be called for
/// "errors" in the `tower::Service::Error` sense. A response will always be produced.
///
/// [`Trace`]: tower_http::trace::TRACE
#[derive(Clone, Debug)]
pub(crate) struct OtelOnFailure;

impl OnFailure<HttpOrGrpcClassification> for OtelOnFailure {
    fn on_failure(&mut self, failure: HttpOrGrpcClassification, _latency: Duration, span: &Span) {
        match failure {
            HttpOrGrpcClassification::Http(status) => {
                if status.is_server_error() {
                    span.record("otel.status_code", &"ERROR");
                }
            }
            HttpOrGrpcClassification::Grpc(code) => {
                if classify::classify_grpc_code(code).is_err() {
                    span.record("otel.status_code", &"ERROR");
                }
            }
        }
    }
}
