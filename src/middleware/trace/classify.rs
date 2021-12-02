use http::HeaderMap;
use std::fmt;
use tower_http::classify::{ClassifiedResponse, ClassifyEos, ClassifyResponse, MakeClassifier};

/// A classified `HTTP` or `gRPC` response.
#[derive(Debug, Clone)]
pub(crate) enum HttpOrGrpcClassification {
    Http(http::StatusCode),
    Grpc(u16),
}

impl fmt::Display for HttpOrGrpcClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            HttpOrGrpcClassification::Http(inner) => inner.fmt(f),
            HttpOrGrpcClassification::Grpc(inner) => inner.fmt(f),
        }
    }
}

/// [`MakeClassifier`] that classifies responses as either `HTTP` or `gRPC` based on the
/// `content-type`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MakeHttpOrGrpcClassifier;

impl MakeClassifier for MakeHttpOrGrpcClassifier {
    type Classifier = HttpOrGrpcClassifier;
    type FailureClass = HttpOrGrpcClassification;
    type ClassifyEos = GrpcClassifyEos;

    fn make_classifier<B>(&self, req: &http::Request<B>) -> Self::Classifier {
        if is_grpc(req.headers()) {
            HttpOrGrpcClassifier::Grpc
        } else {
            HttpOrGrpcClassifier::Http
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum HttpOrGrpcClassifier {
    Grpc,
    Http,
}

impl ClassifyResponse for HttpOrGrpcClassifier {
    type FailureClass = HttpOrGrpcClassification;
    type ClassifyEos = GrpcClassifyEos;

    fn classify_response<B>(
        self,
        res: &http::Response<B>,
    ) -> ClassifiedResponse<Self::FailureClass, Self::ClassifyEos> {
        match self {
            HttpOrGrpcClassifier::Grpc => {
                if let Some(code) = grpc_code_from_headers(res.headers()) {
                    ClassifiedResponse::Ready(
                        classify_grpc_code(code).map_err(HttpOrGrpcClassification::Grpc),
                    )
                } else {
                    ClassifiedResponse::RequiresEos(GrpcClassifyEos)
                }
            }
            HttpOrGrpcClassifier::Http => {
                if res.status().is_server_error() {
                    ClassifiedResponse::Ready(Err(HttpOrGrpcClassification::Http(res.status())))
                } else {
                    ClassifiedResponse::Ready(Ok(()))
                }
            }
        }
    }

    fn classify_error<E>(self, error: &E) -> Self::FailureClass
    where
        E: fmt::Display + 'static,
    {
        unreachable!(
            "we handle all errors from middleware so this will never be called. error={}",
            error
        )
    }
}

pub(crate) struct GrpcClassifyEos;

impl ClassifyEos for GrpcClassifyEos {
    type FailureClass = HttpOrGrpcClassification;

    fn classify_eos(self, trailers: Option<&HeaderMap>) -> Result<(), Self::FailureClass> {
        let trailers = if let Some(trailers) = trailers {
            trailers
        } else {
            return Ok(());
        };

        let code = if let Some(code) = grpc_code_from_headers(trailers) {
            code
        } else {
            return Ok(());
        };

        classify_grpc_code(code).map_err(HttpOrGrpcClassification::Grpc)
    }

    fn classify_error<E>(self, error: &E) -> Self::FailureClass
    where
        E: fmt::Display + 'static,
    {
        unreachable!(
            "we handle all errors from middleware so this will never be called. error={}",
            error
        )
    }
}

const GRPC_CONTENT_TYPE: &str = "application/grpc";
const GRPC_STATUS_HEADER: &str = "grpc-status";

pub(super) fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map_or(false, |value| value.starts_with(GRPC_CONTENT_TYPE))
        || headers.contains_key(GRPC_STATUS_HEADER)
}

pub(super) fn grpc_code_from_headers(headers: &HeaderMap) -> Option<u16> {
    headers
        .get(GRPC_STATUS_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

pub(super) fn classify_grpc_code(code: u16) -> Result<(), u16> {
    const OK: u16 = 0;
    const INVALID_ARGUMENT: u16 = 3;
    const NOT_FOUND: u16 = 5;

    let is_success = code == OK || code == INVALID_ARGUMENT || code == NOT_FOUND;

    if is_success {
        Ok(())
    } else {
        Err(code)
    }
}
