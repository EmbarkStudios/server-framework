//! TODO: write some docs before publishing

// BEGIN - Embark standard lints v5 for Rust 1.55+
// do not change or add/remove here, but one can add exceptions after this section
// for more info see: <https://github.com/EmbarkStudios/rust-ecosystem/issues/59>
#![deny(unsafe_code)]
#![warn(
    clippy::all,
    clippy::await_holding_lock,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::disallowed_method,
    clippy::disallowed_type,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::expl_impl_clone_on_copy,
    clippy::explicit_deref_methods,
    clippy::explicit_into_iter_loop,
    clippy::fallible_impl_from,
    clippy::filter_map_next,
    clippy::flat_map_option,
    clippy::float_cmp_const,
    clippy::fn_params_excessive_bools,
    clippy::from_iter_instead_of_collect,
    clippy::if_let_mutex,
    clippy::implicit_clone,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::invalid_upcast_comparisons,
    clippy::large_digit_groups,
    clippy::large_stack_arrays,
    clippy::large_types_passed_by_value,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::manual_ok_or,
    clippy::map_err_ignore,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wild_err_arm,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::missing_enforced_import_renames,
    clippy::mut_mut,
    clippy::mutex_integer,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::needless_for_each,
    clippy::option_option,
    clippy::path_buf_push_overwrite,
    clippy::ptr_as_ptr,
    clippy::rc_mutex,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_functions_in_if_condition,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_lit_as_bytes,
    clippy::string_to_string,
    clippy::todo,
    clippy::trait_duplication_in_bounds,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::useless_transmute,
    clippy::verbose_file_reads,
    clippy::zero_sized_map_values,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]
// END - Embark standard lints v0.5 for Rust 1.55+
// crate-specific exceptions:
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs)]
#![deny(unreachable_pub, private_in_public)]
#![forbid(unsafe_code)]

use self::metrics::RecordMetrics;
use anyhow::Context as _;
use axum::{
    body::{self, BoxBody, HttpBody},
    error_handling::{HandleError, HandleErrorLayer},
    extract::Extension,
    routing::{get, Route},
    AddExtensionLayer, BoxError, Router,
};
use axum_extra::routing::{HasRoutes, RouterExt};
use http::{header::HeaderName, Method, Request, Response, StatusCode, Uri};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::{
    convert::Infallible,
    fmt,
    future::{ready, Ready},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tower::{timeout::Timeout, ServiceBuilder};
use tower_http::{request_id::RequestId, ServiceBuilderExt};
use uuid::Uuid;

pub use axum;
pub use clap::Parser;
pub use http;
pub use tower::{Layer, Service};

mod metrics;

/// Server configuration.
///
/// Supports being parsed from command line arguments (via clap):
///
/// ```rust
/// use server_framework::{Config, Parser};
///
/// let config = Config::parse();
/// ```
#[derive(Debug, Clone, clap::Parser)]
pub struct Config {
    #[clap(env = "ESF_BIND_ADDRESS", long, default_value = "0.0.0.0:3000")]
    bind_address: SocketAddr,

    #[clap(env = "ESF_METRICS_HEALTH_PORT", long, default_value = "8081")]
    metrics_health_port: u16,

    #[clap(env = "ESF_HTTP2_ONLY", long)]
    http2_only: bool,

    #[clap(env = "ESF_TIMEOUT", long, default_value = "30")]
    timeout_sec: u64,

    #[clap(
        env = "ESF_REQUEST_ID_HEADER",
        long,
        default_value = "x-esf-request-id"
    )]
    request_id_header: String,
}

/// A default batteries included HTTP server.
pub struct Server<F> {
    config: Config,
    router: Router<BoxBody>,
    error_handler: F,
}

impl Default for Server<DefaultErrorHandler> {
    fn default() -> Self {
        Self {
            config: Config::parse(),
            router: Default::default(),
            error_handler: default_error_handler,
        }
    }
}

impl<F> fmt::Debug for Server<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("router", &self.router)
            .finish()
    }
}

impl Server<DefaultErrorHandler> {
    /// Create a new `Server` with the given config.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            router: Router::new(),
            error_handler: default_error_handler,
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
    pub fn with_tonic<S, B>(self, svc: S) -> Self
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
            .service(svc);
        let route = Router::new().route(&format!("/{}", S::NAME), svc);
        self.with(route)
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
        }
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

        tokio::spawn(expose_metrics_and_health(self.config.clone()));

        let Config {
            bind_address,
            http2_only,
            timeout_sec,
            request_id_header,
            metrics_health_port: _,
        } = self.config;

        let request_id_header = HeaderName::from_bytes(request_id_header.as_bytes())
            .with_context(|| format!("Invalid request id: {:?}", request_id_header))?;

        let make_svc = self
            .router
            // these middleware are called for all routes
            .layer(
                ServiceBuilder::new()
                    .map_request_body(|body| WrappedBody { body })
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
            .with_graceful_shutdown(ctrl_c())
            .await?;

        Ok(())
    }
}

/// The type of service that produces the errors `Server.error_handler` will receive
type FallibleService = Timeout<Route<BoxBody>>;

/// Run a second HTTP server that exposes metrics (and soon) health checks.
async fn expose_metrics_and_health(config: Config) {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_requests_duration_seconds".to_string()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )
        .build();

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

    let bind_address = SocketAddr::from(([0, 0, 0, 0], config.metrics_health_port));

    hyper::Server::bind(&bind_address)
        .serve(router.into_make_service())
        .with_graceful_shutdown(ctrl_c())
        .await
        .unwrap();
}

async fn ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}

/// The default error handling type used by [`Server`].
pub type DefaultErrorHandler =
    fn(Method, Uri, Extension<RequestId>, BoxError) -> std::future::Ready<(StatusCode, String)>;

fn default_error_handler(
    method: Method,
    uri: Uri,
    Extension(request_id): Extension<RequestId>,
    err: BoxError,
) -> Ready<(StatusCode, String)> {
    tracing::error!(
        %err,
        %method,
        %uri,
        request_id = %request_id.header_value().to_str().unwrap(),
        "error from middleware",
    );

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

// this type wont be present when we publish
// using it here to ensure we support middleware that modify the request body type
// which is something our internal version doesn't support well
struct WrappedBody<B> {
    body: B,
}

impl<B> HttpBody for WrappedBody<B>
where
    B: HttpBody + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        Pin::new(&mut self.body).poll_data(cx)
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        Pin::new(&mut self.body).poll_trailers(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[derive(Clone, Copy)]
struct MakeRequestUuid;

impl tower_http::request_id::MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _: &Request<B>) -> Option<RequestId> {
        let request_id = Uuid::new_v4().to_string().parse().unwrap();
        Some(RequestId::new(request_id))
    }
}
