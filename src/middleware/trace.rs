use self::{
    classify::MakeHttpOrGrpcClassifier,
    opentelemetry::{OtelMakeSpan, OtelOnFailure, OtelOnResponse},
};
use tower_http::trace::TraceLayer;

pub(crate) mod classify;
pub(crate) mod opentelemetry;

pub(crate) fn layer(
) -> TraceLayer<MakeHttpOrGrpcClassifier, OtelMakeSpan, (), OtelOnResponse, (), (), OtelOnFailure> {
    TraceLayer::new(MakeHttpOrGrpcClassifier)
        .make_span_with(OtelMakeSpan)
        .on_request(())
        .on_response(OtelOnResponse)
        .on_body_chunk(())
        .on_eos(())
        .on_failure(OtelOnFailure)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_include;
    use axum::{body::Body, Router};
    use http::{Method, Request, StatusCode};
    use serde_json::{json, Value};
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use tower::ServiceExt;
    use tracing_subscriber::{
        fmt::{format::FmtSpan, MakeWriter},
        util::SubscriberInitExt,
        EnvFilter,
    };

    #[tokio::test]
    async fn correct_fields_on_span() {
        let svc = crate::Server::new(crate::config::test())
            .with(Router::new().route(
                "/users/:id",
                axum::routing::get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            ))
            .into_service();

        let (make_writer, rx) = duplex_writer();
        let subscriber = tracing_subscriber::fmt::fmt()
            .json()
            .with_env_filter(
                EnvFilter::try_new("server_framework::middleware::trace::opentelemetry=trace")
                    .unwrap(),
            )
            .with_writer(make_writer)
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .finish();
        let _guard = subscriber.set_default();

        svc.oneshot(
            Request::builder()
                .method(Method::GET)
                .header("x-request-id", "request-id")
                .header("user-agent", "tests")
                .uri("/users/123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        let logs = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
            .collect::<Vec<_>>();

        let [new, close]: [_; 2] = logs.try_into().unwrap();

        assert_json_include!(
            actual: new,
            expected: json!({
                "fields": {
                    "message": "new",
                },
                "level": "INFO",
                "span": {
                    "http.client_ip": "",
                    "http.flavor": "1.1",
                    "http.host": "",
                    "http.method": "GET",
                    "http.route": "/users/:id",
                    "http.scheme": "HTTP",
                    "http.target": "/users/123",
                    "http.user_agent": "tests",
                    "name": "HTTP request",
                    "otel.kind": "server",
                    "request_id": "request-id",
                    "trace_id": ""
                }
            }),
        );

        assert_json_include!(
            actual: close,
            expected: json!({
                    "fields": {
                        "message": "close",
                    },
                    "level": "INFO",
                    "span": {
                        "http.client_ip": "",
                        "http.flavor": "1.1",
                        "http.host": "",
                        "http.method": "GET",
                        "http.route": "/users/:id",
                        "http.scheme": "HTTP",
                        "http.status_code": "500",
                        "http.target": "/users/123",
                        "http.user_agent": "tests",
                        "name": "HTTP request",
                        "otel.kind": "server",
                        "otel.status_code": "ERROR",
                        "request_id": "request-id",
                        "trace_id": ""
                    }
            }),
        );
    }

    // TODO(david): gRPC test

    fn duplex_writer() -> (DuplexWriter, Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::sync_channel(1024);
        (DuplexWriter { tx }, rx)
    }

    #[derive(Clone)]
    struct DuplexWriter {
        tx: SyncSender<Vec<u8>>,
    }

    impl<'a> MakeWriter<'a> for DuplexWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl std::io::Write for DuplexWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.tx.send(buf.to_vec()).unwrap();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
