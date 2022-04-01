use self::{
    classify::MakeHttpOrGrpcClassifier,
    opentelemetry::{OtelMakeSpan, OtelOnEos, OtelOnFailure, OtelOnResponse},
};
use tower_http::trace::TraceLayer;

pub(crate) mod classify;
pub(crate) mod opentelemetry;

pub(crate) fn layer() -> TraceLayer<
    MakeHttpOrGrpcClassifier,
    OtelMakeSpan,
    (), // on request
    OtelOnResponse,
    (), // on body chunk
    OtelOnEos,
    OtelOnFailure,
> {
    TraceLayer::new(MakeHttpOrGrpcClassifier)
        .make_span_with(OtelMakeSpan)
        .on_request(())
        .on_response(OtelOnResponse)
        .on_body_chunk(())
        .on_eos(OtelOnEos)
        .on_failure(OtelOnFailure)
}

#[cfg(test)]
mod tests {
    use crate::{config::Config, Server};
    use assert_json_diff::assert_json_include;
    use axum::{
        body::Body,
        routing::{get, post},
        Router,
    };
    use http::{header::HeaderName, HeaderMap, HeaderValue, Method, Request, StatusCode, Version};
    use http_body::Body as _;
    use serde_json::{json, Value};
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use tower::{Service, ServiceExt};
    use tracing_subscriber::{
        fmt::{format::FmtSpan, MakeWriter},
        util::SubscriberInitExt,
        EnvFilter,
    };

    #[tokio::test]
    async fn correct_fields_on_span_for_http() {
        let svc = Server::new(Config::default())
            .with(
                Router::new()
                    .route("/", get(|| async { StatusCode::OK }))
                    .route(
                        "/users/:id",
                        get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
                    ),
            )
            .into_service();

        let [(root_new, root_close), (users_id_new, users_id_close)] = spans_for_requests(
            svc,
            [
                Request::builder()
                    .header("x-request-id", "request-id")
                    .header("user-agent", "tests")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
                Request::builder()
                    .uri("/users/123")
                    .body(Body::empty())
                    .unwrap(),
            ],
        )
        .await;

        assert_json_include!(
            actual: root_new,
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
                    "http.route": "/",
                    "http.scheme": "HTTP",
                    "http.target": "/",
                    "http.user_agent": "tests",
                    "name": "HTTP request",
                    "otel.kind": "server",
                    "request_id": "request-id",
                    "trace_id": ""
                }
            }),
        );

        assert_json_include!(
            actual: root_close,
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
                    "http.route": "/",
                    "http.scheme": "HTTP",
                    "http.status_code": "200",
                    "http.target": "/",
                    "http.user_agent": "tests",
                    "name": "HTTP request",
                    "otel.kind": "server",
                    "otel.status_code": "OK",
                    "request_id": "request-id",
                    "trace_id": ""
                }
            }),
        );

        assert_json_include!(
            actual: users_id_new,
            expected: json!({
                "span": {
                    "http.route": "/users/:id",
                    "http.target": "/users/123",
                }
            }),
        );

        assert_json_include!(
            actual: users_id_close,
            expected: json!({
                "span": {
                    "http.status_code": "500",
                    "otel.status_code": "ERROR",
                }
            }),
        );
    }

    #[tokio::test]
    async fn correct_fields_on_span_for_grpc() {
        let svc = Server::new(Config::default())
            .with(
                Router::new()
                    .route(
                        "/package.service/Success",
                        post(|| async { send_code_in_trailers(0) }),
                    )
                    .route(
                        "/package.service/FailUnary",
                        post(|| async { ([("grpc-status", "13")], StatusCode::OK) }),
                    )
                    .route(
                        "/package.service/FailStream",
                        post(|| async { send_code_in_trailers(13) }),
                    ),
            )
            .into_service();

        let [(_, success), (_, fail_unary), (_, fail_stream)] = spans_for_requests(
            svc,
            [
                mock_grpc_request_to("/package.service/Success"),
                mock_grpc_request_to("/package.service/FailUnary"),
                mock_grpc_request_to("/package.service/FailStream"),
            ],
        )
        .await;

        assert_json_include!(
            actual: success,
            expected: json!({
                "span": {
                    "grpc.code": 0,
                    "http.flavor": "2.0",
                    "http.route": "/package.service/Success",
                    "http.status_code": "200",
                    "http.target": "/package.service/Success",
                    "otel.status_code": "OK",
                }
            }),
        );

        assert_json_include!(
            actual: fail_unary,
            expected: json!({
                "span": {
                    "grpc.code": 13,
                    "http.flavor": "2.0",
                    "http.status_code": "200",
                    "otel.status_code": "ERROR",
                }
            }),
        );

        assert_json_include!(
            actual: fail_stream,
            expected: json!({
                "span": {
                    "grpc.code": 13,
                    "http.flavor": "2.0",
                    "http.status_code": "200",
                    "otel.status_code": "ERROR",
                }
            }),
        );

        fn send_code_in_trailers(code: u16) -> impl axum::response::IntoResponse {
            let (mut tx, body) = hyper::Body::channel();

            tokio::spawn(async move {
                let mut headers = HeaderMap::new();
                headers.insert(
                    HeaderName::from_static("grpc-status"),
                    HeaderValue::from_str(&code.to_string()).unwrap(),
                );
                tx.send_trailers(headers).await.unwrap();
            });

            (StatusCode::OK, body.boxed())
        }

        fn mock_grpc_request_to(uri: &str) -> Request<Body> {
            Request::builder()
                .version(Version::HTTP_2)
                .header("content-type", "application/grpc")
                .method(Method::POST)
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        }
    }

    async fn spans_for_requests<const N: usize>(
        mut router: Router<Body>,
        reqs: [Request<Body>; N],
    ) -> [(Value, Value); N] {
        use http_body::Body as _;

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

        let mut spans = Vec::new();

        for req in reqs {
            let mut res = router.ready().await.unwrap().call(req).await.unwrap();

            while res.data().await.is_some() {}
            res.trailers().await.unwrap();
            drop(res);

            let logs = std::iter::from_fn(|| rx.try_recv().ok())
                .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
                .collect::<Vec<_>>();

            let [new, close]: [_; 2] = logs.try_into().unwrap();

            spans.push((new, close));
        }

        spans.try_into().unwrap()
    }

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
