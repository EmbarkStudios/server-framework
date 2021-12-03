use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::extract::MatchedPath;
use http::{Method, Request, Response};
use pin_project_lite::pin_project;
use tower::{layer::LayerFn, Service};

pub(crate) fn layer<S>() -> LayerFn<fn(S) -> RecordMetrics<S>> {
    tower::layer::layer_fn(|inner| RecordMetrics { inner })
}

#[derive(Clone)]
pub(crate) struct RecordMetrics<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RecordMetrics<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = Infallible>,
{
    type Response = S::Response;
    type Error = Infallible;
    type Future = RecordMetricsFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let start = Instant::now();

        let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
            matched_path.as_str().to_owned()
        } else {
            req.uri().path().to_owned()
        };

        let method = req.method().clone();

        RecordMetricsFuture {
            inner: self.inner.call(req),
            request_data: Some((method, path)),
            start,
        }
    }
}

pin_project! {
    pub(crate) struct RecordMetricsFuture<F> {
        #[pin]
        inner: F,
        request_data: Option<(Method, String)>,
        start: Instant,
    }
}

impl<F, B> Future for RecordMetricsFuture<F>
where
    F: Future<Output = Result<Response<B>, Infallible>>,
{
    type Output = Result<Response<B>, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.inner.poll(cx) {
            Poll::Ready(Ok(res)) => {
                let latency = this.start.elapsed().as_secs_f64();

                let status = res.status().as_u16().to_string();
                let (method, path) = this
                    .request_data
                    .take()
                    .expect("future polled after completion");

                let labels = [
                    ("method", method.to_string()),
                    ("path", path),
                    ("status", status),
                ];

                metrics::increment_counter!("http_requests_total", &labels);
                metrics::histogram!("http_requests_duration_seconds", latency, &labels);

                Poll::Ready(Ok(res))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}
