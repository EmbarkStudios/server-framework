use axum::{middleware::Next, response::Response};
use http::Request;
use std::{
    task::{Context, Poll},
    time::Instant,
};
use tower::{Layer, Service};

pub(crate) mod metrics;
pub(crate) mod trace;

/// Combine two layers or services into one.
///
/// This differs from `tower::util::Either` in that it doesn't convert the error to `BoxError` but
/// requires the services to have the same error types.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Either<A, B> {
    A(A),
    B(B),
}

impl<S, A, B> Layer<S> for Either<A, B>
where
    A: Layer<S>,
    B: Layer<S>,
{
    type Service = Either<A::Service, B::Service>;

    fn layer(&self, inner: S) -> Self::Service {
        match self {
            Self::A(layer) => Either::A(layer.layer(inner)),
            Self::B(layer) => Either::B(layer.layer(inner)),
        }
    }
}

impl<A, B, R> Service<R> for Either<A, B>
where
    A: Service<R>,
    B: Service<R, Response = A::Response, Error = A::Error>,
{
    type Response = A::Response;
    type Error = A::Error;
    type Future = futures_util::future::Either<A::Future, B::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Either::A(svc) => svc.poll_ready(cx),
            Either::B(svc) => svc.poll_ready(cx),
        }
    }

    fn call(&mut self, req: R) -> Self::Future {
        match self {
            Either::A(svc) => futures_util::future::Either::Left(svc.call(req)),
            Either::B(svc) => futures_util::future::Either::Right(svc.call(req)),
        }
    }
}

pub(crate) async fn verbose_logging<B>(req: Request<B>, next: Next<B>) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    tracing::debug!("`{} {}` started", method, uri);
    let res = next.run(req).await;
    tracing::debug!(
        "`{} {}` completed with status {} and headers {:?} in {:?}",
        method,
        uri,
        res.status(),
        res.headers(),
        start.elapsed()
    );
    res
}
