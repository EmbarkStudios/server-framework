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
#![deny(
    unreachable_pub,
    private_in_public,
    // TODO(david): enable these before publishing
    // missing_debug_implementations,
    // missing_docs,
)]
#![forbid(unsafe_code)]

use axum::{
    body::{self, BoxBody, HttpBody},
    Router,
};
use axum_extra::routing::{HasRoutes, RouterExt};
use http::{Request, Response};
use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tower::ServiceBuilder;
use tower_http::ServiceBuilderExt as _;

pub use axum;
pub use clap::Parser;
pub use http;
pub use tower::{Layer, Service};

#[derive(Debug, clap::Parser)]
pub struct Config {
    #[clap(env = "ESF_BIND_ADDRESS", long, default_value = "0.0.0.0:3000")]
    bind_address: SocketAddr,

    #[clap(env = "ESF_HTTP2_ONLY", long)]
    http2_only: bool,
}

// TODO(david): metrics middleware
// TODO(david): internal metrics service

pub struct Server {
    config: Config,
    router: Router<BoxBody>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            router: Router::new(),
        }
    }

    pub fn with<T>(mut self, router: T) -> Self
    where
        T: HasRoutes<BoxBody>,
    {
        self.router = self.router.with(router);
        self
    }

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

    pub async fn serve(self) -> anyhow::Result<()> {
        tracing::debug!("server listening on {}", self.config.bind_address);

        let Config {
            bind_address,
            http2_only,
        } = self.config;

        let make_svc = self
            .router
            .layer(
                ServiceBuilder::new()
                    .map_request_body(|body| WrappedBody { body })
                    .map_request_body(body::boxed),
            )
            .into_make_service_with_connect_info::<SocketAddr, _>();

        hyper::Server::bind(&bind_address)
            .http2_only(http2_only)
            .serve(make_svc)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;

        Ok(())
    }
}

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
