use crate::{
    error_handling::{default_error_handler, DefaultErrorHandler},
    health::{AlwaysLiveAndReady, HealthCheck, NoHealthCheckProvided},
    middleware::{metrics, trace},
    request_id::MakeRequestUuid,
    Config,
};
use axum::{
    body::{self, BoxBody},
    error_handling::{HandleError, HandleErrorLayer},
    extract::Extension,
    response::Response,
    routing::{get, Route},
    AddExtensionLayer, Router,
};
use axum_extra::routing::{HasRoutes, RouterExt};
use clap::Parser;
use http::{header::HeaderName, Request, StatusCode};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::{
    convert::Infallible,
    fmt::{self, Write},
    net::SocketAddr,
    time::Duration,
};
use tokio::net::TcpListener;
use tower::{timeout::Timeout, Service, ServiceBuilder};
use tower_http::ServiceBuilderExt;

/// An HTTP server that runs [`Service`]s with a conventional stack of middleware.
pub struct Server<F, H> {
    config: Config,
    router: Router<BoxBody>,
    error_handler: F,
    health_check: H,
    metric_buckets: Option<Vec<(Matcher, Vec<f64>)>>,
}

impl Default for Server<DefaultErrorHandler, NoHealthCheckProvided> {
    fn default() -> Self {
        Self {
            config: Config::parse(),
            router: Default::default(),
            error_handler: default_error_handler,
            health_check: NoHealthCheckProvided,
            metric_buckets: None,
        }
    }
}

impl<F, H> fmt::Debug for Server<F, H>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("router", &self.router)
            .field("health_check", &self.health_check)
            .field("metric_buckets", &self.metric_buckets)
            .finish()
    }
}

impl Server<DefaultErrorHandler, NoHealthCheckProvided> {
    /// Create a new `Server` with the given config.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            router: Default::default(),
            error_handler: default_error_handler,
            health_check: NoHealthCheckProvided,
            metric_buckets: Default::default(),
        }
    }
}

impl<F, H> Server<F, H> {
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
    ///     .always_live_and_ready()
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
    ///     .always_live_and_ready()
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
    ///     .always_live_and_ready()
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
    /// #     type Response = axum::response::Response;
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
    ///     .always_live_and_ready()
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
    ///     .always_live_and_ready()
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
    ///     .always_live_and_ready()
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
    ///     .always_live_and_ready()
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
    pub fn handle_error<G, T>(self, error_handler: G) -> Server<G, H>
    where
        G: Clone + Send + 'static,
        T: 'static,
        HandleError<FallibleService, G, T>:
            Service<Request<BoxBody>, Response = Response, Error = Infallible>,
        <HandleError<FallibleService, G, T> as Service<Request<BoxBody>>>::Future: Send,
    {
        Server {
            config: self.config,
            router: self.router,
            error_handler,
            health_check: self.health_check,
            metric_buckets: self.metric_buckets,
        }
    }

    /// Provide the health check the server should use.
    pub fn with_health_check<H2>(self, health_check: H2) -> Server<F, H2>
    where
        H2: HealthCheck + Clone,
    {
        Server {
            config: self.config,
            router: self.router,
            error_handler: self.error_handler,
            health_check,
            metric_buckets: self.metric_buckets,
        }
    }

    /// Mark this service as always being live and ready.
    pub fn always_live_and_ready(self) -> Server<F, AlwaysLiveAndReady> {
        self.with_health_check(AlwaysLiveAndReady)
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
            Service<Request<BoxBody>, Response = Response, Error = Infallible>,
        <HandleError<FallibleService, F, T> as Service<Request<BoxBody>>>::Future: Send,
        H: HealthCheck + Clone,
    {
        let listener = TcpListener::bind(&self.config.bind_address).await?;
        self.serve_with_listener(listener).await
    }

    /// Run the server with the given [`TcpListener`].
    ///
    /// Note this disregards `bind_address` of the config.
    pub async fn serve_with_listener<T>(mut self, listener: TcpListener) -> anyhow::Result<()>
    where
        F: Clone + Send + 'static,
        T: 'static,
        HandleError<FallibleService, F, T>:
            Service<Request<BoxBody>, Response = Response, Error = Infallible>,
        <HandleError<FallibleService, F, T> as Service<Request<BoxBody>>>::Future: Send,
        H: HealthCheck + Clone,
    {
        let listener = listener.into_std()?;

        if let Ok(addr) = listener.local_addr() {
            tracing::debug!("server listening on {}", addr);
        }

        let http2_only = self.config.http2_only;

        tokio::spawn(expose_metrics_and_health(
            self.config.metrics_health_port,
            self.metric_buckets.take(),
            self.health_check.clone(),
        ));

        let make_svc = self
            .into_service()
            .into_make_service_with_connect_info::<SocketAddr, _>();

        hyper::Server::from_tcp(listener)?
            .http2_only(http2_only)
            .serve(make_svc)
            .with_graceful_shutdown(signal_listener())
            .await?;

        Ok(())
    }

    /// Get the underlying service with middleware applied.
    pub fn into_service<T>(self) -> Router<axum::body::Body>
    where
        F: Clone + Send + 'static,
        T: 'static,
        HandleError<FallibleService, F, T>:
            Service<Request<BoxBody>, Response = Response, Error = Infallible>,
        <HandleError<FallibleService, F, T> as Service<Request<BoxBody>>>::Future: Send,
    {
        let request_id_header = HeaderName::from_bytes(self.config.request_id_header.as_bytes())
            .unwrap_or_else(|_| panic!("Invalid request id: {:?}", self.config.request_id_header));

        self.router
            // these middleware are called for all routes
            .layer(
                ServiceBuilder::new()
                    .map_request_body(body::boxed)
                    .layer(HandleErrorLayer::new(self.error_handler))
                    .timeout(Duration::from_secs(self.config.timeout_sec)),
            )
            // these middleware are _only_ called for known routes
            .route_layer(
                ServiceBuilder::new()
                    .set_request_id(request_id_header.clone(), MakeRequestUuid)
                    .layer(trace::layer())
                    .propagate_request_id(request_id_header)
                    .layer(metrics::layer()),
            )
    }
}

/// The type of service that produces the errors `Server.error_handler` will receive
type FallibleService = Timeout<Route<BoxBody>>;

/// Run a second HTTP server that exposes metrics and health checks.
async fn expose_metrics_and_health<H>(
    metrics_health_port: u16,
    metric_buckets: Option<Vec<(Matcher, Vec<f64>)>>,
    health_check: H,
) where
    H: HealthCheck + Clone,
{
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    let mut recorder_builder = PrometheusBuilder::new().set_buckets_for_metric(
        Matcher::Full("http_requests_duration_seconds".to_string()),
        EXPONENTIAL_SECONDS,
    );

    for (matcher, values) in metric_buckets.into_iter().flatten() {
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
            .route(
                "/health/live",
                get(|Extension(health_check): Extension<H>| async move {
                    if let Err(err) = health_check.is_live().await {
                        let err = error_display_chain(&err);
                        tracing::error!("readiness heath check failed: {}", err);
                        Err((StatusCode::SERVICE_UNAVAILABLE, err))
                    } else {
                        Ok(())
                    }
                }),
            )
            .route(
                "/health/ready",
                get(|Extension(health_check): Extension<H>| async move {
                    if let Err(err) = health_check.is_ready().await {
                        let err = error_display_chain(&err);
                        tracing::error!("liveness heath check failed: {}", err);
                        Err((StatusCode::SERVICE_UNAVAILABLE, err))
                    } else {
                        Ok(())
                    }
                }),
            )
            .layer(
                ServiceBuilder::new()
                    .layer(AddExtensionLayer::new(recorder_handle))
                    .layer(AddExtensionLayer::new(health_check)),
            );

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

fn error_display_chain(error: &anyhow::Error) -> String {
    let mut s = error.to_string();
    for source in error.chain() {
        s.push_str(" -> ");
        let _ = write!(s, "{}", source);
    }
    s
}
