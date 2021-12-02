use crate::{
    error_handling::{default_error_handler, DefaultErrorHandler},
    middleware::metrics::RecordMetrics,
    request_id::MakeRequestUuid,
    Config,
};
use anyhow::Context as _;
use axum::{
    body::{self, BoxBody},
    error_handling::{HandleError, HandleErrorLayer},
    extract::Extension,
    routing::{get, Route},
    AddExtensionLayer, Router,
};
use axum_extra::routing::{HasRoutes, RouterExt};
use clap::Parser;
use http::{header::HeaderName, Request, Response};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::{convert::Infallible, fmt, net::SocketAddr, time::Duration};
use tower::{timeout::Timeout, Service, ServiceBuilder};
use tower_http::ServiceBuilderExt;

/// An HTTP server that runs [`Service`]s with a conventional stack of middleware.
pub struct Server<F> {
    config: Config,
    router: Router<BoxBody>,
    error_handler: F,
    metric_buckets: Option<Vec<(Matcher, Vec<f64>)>>,
}

impl Default for Server<DefaultErrorHandler> {
    fn default() -> Self {
        Self {
            config: Config::parse(),
            router: Default::default(),
            error_handler: default_error_handler,
            metric_buckets: None,
        }
    }
}

impl<F> fmt::Debug for Server<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("router", &self.router)
            .field("metric_buckets", &self.metric_buckets)
            .finish()
    }
}

impl Server<DefaultErrorHandler> {
    /// Create a new `Server` with the given config.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            router: Default::default(),
            error_handler: default_error_handler,
            metric_buckets: Default::default(),
        }
    }
}

impl<F> Server<F> {
    /// Add routes to the server.
    ///
    /// This supports anything that implements [`HasRoutes`] such as [`Router`]:
    ///
    /// ```rust
    /// use server_framework::Server;
    /// use axum::{Router, routing::get};
    ///
    /// let routes = Router::new().route("/", get(|| async { "Hello, World!" }));
    ///
    /// # async {
    /// Server::default()
    ///     .with(routes)
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    ///
    /// Or [`Resource`](axum_extra::routing::Resource):
    ///
    /// ```rust
    /// use server_framework::Server;
    /// use axum_extra::routing::Resource;
    /// use axum::{
    ///     Router,
    ///     async_trait,
    ///     extract::{Path, FromRequest, RequestParts},
    ///     routing::get,
    ///     body::BoxBody,
    /// };
    ///
    /// struct Users {
    ///     dependency: SomeDependency,
    /// }
    ///
    /// impl Users {
    ///     fn resource() -> Resource<BoxBody> {
    ///         Resource::named("users")
    ///             .index(Self::index)
    ///             .create(Self::create)
    ///             .show(Self::show)
    ///     }
    ///
    ///     async fn index(self) {}
    ///
    ///     async fn create(self) {}
    ///
    ///     async fn show(self, Path(user_id): Path<u64>) {}
    /// }
    ///
    /// #[async_trait]
    /// impl<B> FromRequest<B> for Users
    /// where
    ///     B: Send + 'static
    /// {
    ///     // ...
    ///     # type Rejection = std::convert::Infallible;
    ///     # async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
    ///     #     todo!()
    ///     # }
    /// }
    ///
    /// struct SomeDependency;
    ///
    /// # async {
    /// Server::default()
    ///     .with(Users::resource())
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    ///
    /// `with` can be called multiple times to add multiples sets of routes:
    ///
    /// ```rust
    /// use server_framework::Server;
    /// use axum::{Router, response::Json, routing::get};
    /// use serde_json::json;
    ///
    /// let routes = Router::new().route("/", get(|| async { "Hello, World!" }));
    ///
    /// let api_routes = Router::new().route("/api", get(|| async {
    ///     Json(json!({ "data": [1, 2, 3] }))
    /// }));
    ///
    /// # async {
    /// Server::default()
    ///     .with(routes)
    ///     .with(api_routes)
    ///     // our server now accepts `GET /` and `GET /api`
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    pub fn with<T>(mut self, router: T) -> Self
    where
        T: HasRoutes<BoxBody>,
    {
        self.router = self.router.with(router);
        self
    }

    /// Add a tonic service to the server.
    ///
    /// ```rust
    /// use axum::async_trait;
    /// use server_framework::Server;
    /// #
    /// # #[async_trait]
    /// # trait Greeter {}
    /// # #[derive(Clone)]
    /// # struct GreeterServer<T>(T);
    /// # impl<T> GreeterServer<T> {
    /// #     fn new(t: T) -> Self { Self(t) }
    /// # }
    /// # impl<T> tonic::transport::NamedService for GreeterServer<T> {
    /// #     const NAME: &'static str = "";
    /// # }
    /// # impl<T> tower::Service<http::Request<axum::body::BoxBody>> for GreeterServer<T> {
    /// #     type Response = http::Response<axum::body::BoxBody>;
    /// #     type Error = tonic::codegen::Never;
    /// #     type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
    /// #     fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
    /// #         todo!()
    /// #     }
    /// #     fn call(&mut self, _: http::Request<axum::body::BoxBody>) -> Self::Future {
    /// #         todo!()
    /// #     }
    /// # }
    ///
    /// #[derive(Clone)]
    /// struct MyGreeter;
    ///
    /// // implement server trait generated by tonic-build
    /// #[async_trait]
    /// impl Greeter for MyGreeter {
    ///     // ...
    /// }
    ///
    /// let service = GreeterServer::new(MyGreeter);
    ///
    /// # async {
    /// Server::default()
    ///     .with_tonic(service)
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    #[cfg(feature = "tonic")]
    pub fn with_tonic<S, B>(self, service: S) -> Self
    where
        S: Service<Request<BoxBody>, Response = Response<B>, Error = tonic::codegen::Never>
            + tonic::transport::NamedService
            + Clone
            + Send
            + 'static,
        S::Future: Send,
        B: http_body::Body<Data = axum::body::Bytes> + Send + 'static,
        B::Error: Into<axum::BoxError>,
    {
        self.with(router_from_tonic(service))
    }

    /// Add a fallback service.
    ///
    /// This service will be called if no routes matches the incoming request.
    ///
    /// ```rust
    /// use server_framework::Server;
    /// use axum::{
    ///     Router,
    ///     response::IntoResponse,
    ///     http::{StatusCode, Uri},
    ///     handler::Handler,
    /// };
    ///
    /// async fn fallback(uri: Uri) -> impl IntoResponse {
    ///     (StatusCode::NOT_FOUND, format!("No route for {}", uri))
    /// }
    ///
    /// # async {
    /// Server::default()
    ///     .fallback(fallback.into_service())
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    pub fn fallback<S, B>(mut self, svc: S) -> Self
    where
        S: Service<Request<BoxBody>, Response = Response<B>, Error = Infallible>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        B: http_body::Body<Data = axum::body::Bytes> + Send + 'static,
        B::Error: Into<axum::BoxError>,
    {
        let svc = ServiceBuilder::new()
            .map_response_body(body::boxed)
            .service(svc);
        self.router = self.router.fallback(svc);
        self
    }

    /// Change how errors from middleware are converted into responses.
    ///
    /// ```rust
    /// use server_framework::Server;
    /// use axum::{
    ///     Router,
    ///     Json,
    ///     BoxError,
    ///     response::IntoResponse,
    ///     http::StatusCode,
    /// };
    /// use serde_json::json;
    ///
    /// async fn handle_error(err: BoxError) -> impl IntoResponse {
    ///     (
    ///         StatusCode::INTERNAL_SERVER_ERROR,
    ///         Json(json!({
    ///             "error": {
    ///                 "status": 500,
    ///                 "message": "Something went wrong...",
    ///                 "details": err.to_string(),
    ///             },
    ///         }))
    ///     )
    /// }
    ///
    /// # async {
    /// Server::default()
    ///     .handle_error(handle_error)
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    ///
    /// Error handles can also run axum extractors:
    ///
    /// ```rust
    /// use server_framework::Server;
    /// use axum::{
    ///     Router,
    ///     BoxError,
    ///     response::IntoResponse,
    ///     http::{StatusCode, Method, Uri},
    /// };
    ///
    /// async fn handle_error(
    ///     // `Method` and `Uri` are extractors since they implement `axum::extract::FromRequest`
    ///     method: Method,
    ///     uri: Uri,
    ///     // the last argument must be the error
    ///     err: BoxError,
    /// ) -> impl IntoResponse {
    ///     // ...
    /// }
    ///
    /// # async {
    /// Server::default()
    ///     .handle_error(handle_error)
    ///     .serve()
    ///     .await
    ///     .unwrap();
    /// # };
    /// ```
    ///
    /// Note that "errors" means errors produced by a middleware, not the application itself. The
    /// service(s) that makes up the actual application is required to be infallible such that
    /// we're to always produce a response. An endpoint returning `500 Internal Server Error` is
    /// not considered an "error" and this method is not for handling such cases.
    pub fn handle_error<G, T>(self, error_handler: G) -> Server<G>
    where
        G: Clone + Send + 'static,
        T: 'static,
        HandleError<FallibleService, G, T>:
            Service<Request<BoxBody>, Response = Response<BoxBody>, Error = Infallible>,
        <HandleError<FallibleService, G, T> as Service<Request<BoxBody>>>::Future: Send,
    {
        Server {
            config: self.config,
            router: self.router,
            error_handler,
            metric_buckets: self.metric_buckets,
        }
    }

    /// Set additional metric buckets to define on the prometheus recorder.
    ///
    /// Calling this multiple times will append to the list of buckets.
    pub fn metric_buckets(mut self, buckets: Vec<(Matcher, Vec<f64>)>) -> Self {
        self.metric_buckets
            .get_or_insert(Default::default())
            .extend(buckets);
        self
    }

    /// Run the server.
    pub async fn serve<T>(self) -> anyhow::Result<()>
    where
        F: Clone + Send + 'static,
        T: 'static,
        HandleError<FallibleService, F, T>:
            Service<Request<BoxBody>, Response = Response<BoxBody>, Error = Infallible>,
        <HandleError<FallibleService, F, T> as Service<Request<BoxBody>>>::Future: Send,
    {
        tracing::debug!("server listening on {}", self.config.bind_address);

        let Config {
            bind_address,
            http2_only,
            timeout_sec,
            request_id_header,
            metrics_health_port,
        } = self.config;

        tokio::spawn(expose_metrics_and_health(
            metrics_health_port,
            self.metric_buckets,
        ));

        let request_id_header = HeaderName::from_bytes(request_id_header.as_bytes())
            .with_context(|| format!("Invalid request id: {:?}", request_id_header))?;

        let make_svc = self
            .router
            // these middleware are called for all routes
            .layer(
                ServiceBuilder::new()
                    .map_request_body(body::boxed)
                    .layer(HandleErrorLayer::new(self.error_handler))
                    .timeout(Duration::from_secs(timeout_sec)),
            )
            // these middleware are _only_ called for known routes
            .route_layer(
                ServiceBuilder::new()
                    .set_request_id(request_id_header.clone(), MakeRequestUuid)
                    // any potential trace layer must be added here, between these two layers
                    .propagate_request_id(request_id_header)
                    .layer(RecordMetrics::layer()),
            )
            .into_make_service_with_connect_info::<SocketAddr, _>();

        hyper::Server::bind(&bind_address)
            .http2_only(http2_only)
            .serve(make_svc)
            .with_graceful_shutdown(signal_listener())
            .await?;

        Ok(())
    }
}

/// The type of service that produces the errors `Server.error_handler` will receive
type FallibleService = Timeout<Route<BoxBody>>;

/// Run a second HTTP server that exposes metrics (and soon) health checks.
async fn expose_metrics_and_health(
    metrics_health_port: u16,
    metric_buckets: Option<Vec<(Matcher, Vec<f64>)>>,
) {
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    let mut recorder_builder = PrometheusBuilder::new().set_buckets_for_metric(
        Matcher::Full("http_requests_duration_seconds".to_string()),
        EXPONENTIAL_SECONDS,
    );

    for (matcher, values) in metric_buckets.into_iter().flatten().collect::<Vec<_>>() {
        recorder_builder = recorder_builder.set_buckets_for_metric(matcher, &values);
    }

    let recorder = recorder_builder.build();

    let recorder_handle = recorder.handle();

    ::metrics::set_boxed_recorder(Box::new(recorder)).expect("failed to set metrics recorder");

    let router =
        Router::new()
            .route(
                "/metrics",
                get(|recorder_handle: Extension<PrometheusHandle>| async move {
                    recorder_handle.render()
                }),
            )
            .layer(ServiceBuilder::new().layer(AddExtensionLayer::new(recorder_handle)));

    let bind_address = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, metrics_health_port));

    tracing::debug!("metrics and health server listening on {}", bind_address);

    hyper::Server::bind(&bind_address)
        .serve(router.into_make_service())
        .with_graceful_shutdown(signal_listener())
        .await
        .unwrap();
}

#[cfg(target_family = "unix")]
async fn signal_listener() {
    use tokio::signal::unix::SignalKind;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .expect("Failed to listen on SIGTERM signal");
    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, shutting down server");
        }
        _ = tokio::signal::ctrl_c() =>  {
            tracing::info!("Ctrl-c received, shutting down server");
        }
    }
}

#[cfg(not(target_family = "unix"))]
async fn signal_listener() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl-c signal");
    tracing::info!("Ctrl-c received, shutting down server");
}

/// Convert a [`tonic`] service into a [`Router`].
///
/// This can be useful for composing a number of services and adding middleware to them.
#[cfg(feature = "tonic")]
pub fn router_from_tonic<S, B>(service: S) -> Router<BoxBody>
where
    S: Service<Request<BoxBody>, Response = Response<B>, Error = tonic::codegen::Never>
        + tonic::transport::NamedService
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    B: http_body::Body<Data = axum::body::Bytes> + Send + 'static,
    B::Error: Into<axum::BoxError>,
{
    let svc = ServiceBuilder::new()
        .map_err(|err: tonic::codegen::Never| match err {})
        .map_response_body(body::boxed)
        .service(service);
    Router::new().route(&format!("/{}/*rest", S::NAME), svc)
}
