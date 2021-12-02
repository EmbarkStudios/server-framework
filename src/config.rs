use clap::Parser;
use std::net::SocketAddr;

/// Server configuration.
///
/// Supports being parsed from command line arguments (via clap):
///
/// ```rust
/// use server_framework::Config;
///
/// let config = Config::from_args();
/// ```
///
/// You can use `#[clap(flatten)]` to combine this with your apps remaining configuration:
///
/// ```rust
/// use server_framework::{Config, Server};
/// use clap::Parser;
///
/// #[derive(clap::Parser)]
/// struct MyAppConfig {
///     #[clap(flatten)]
///     server_config: Config,
/// }
///
/// let config = MyAppConfig::parse();
///
/// # async {
/// Server::new(config.server_config)
///     .serve()
///     .await
///     .unwrap();
/// # };
/// ```
#[derive(Debug, Clone, clap::Parser)]
#[non_exhaustive]
pub struct Config {
    /// The socket address the server will bind to.
    ///
    /// Defaults to `0.0.0.0:8080`.
    ///
    /// Can also be set through the `ESF_BIND_ADDRESS` environment variable.
    #[clap(env = "ESF_BIND_ADDRESS", long, default_value = "0.0.0.0:8080")]
    pub bind_address: SocketAddr,

    /// The port the metrics and health server will bind to.
    ///
    /// Defaults to `8081`.
    ///
    /// Can also be set through the `ESF_METRICS_HEALTH_PORT` environment variable.
    #[clap(env = "ESF_METRICS_HEALTH_PORT", long, default_value = "8081")]
    pub metrics_health_port: u16,

    /// Whether or not to only accept http2 traffic.
    ///
    /// Defaults to `false`.
    ///
    /// Can also be set through the `ESF_HTTP2_ONLY` environment variable.
    #[clap(env = "ESF_HTTP2_ONLY", long)]
    pub http2_only: bool,

    /// The request timeout in seconds.
    ///
    /// Defaults to 30.
    ///
    /// Can also be set through the `ESF_TIMEOUT` environment variable.
    #[clap(env = "ESF_TIMEOUT", long, default_value = "30")]
    pub timeout_sec: u64,

    /// The rqeuest id headers.
    ///
    /// Defaults to `x-request-id`.
    ///
    /// Can also be set through the `ESF_REQUEST_ID_HEADER` environment variable.
    #[clap(env = "ESF_REQUEST_ID_HEADER", long, default_value = "x-request-id")]
    pub request_id_header: String,
}

impl Config {
    /// Get the config from command line arguments.
    pub fn from_args() -> Self {
        let config = Self::parse();
        tracing::debug!(?config);
        config
    }
}

#[cfg(test)]
pub(crate) fn test() -> Config {
    Config {
        bind_address: "0.0.0.0:8080".parse().unwrap(),
        metrics_health_port: 8081,
        http2_only: false,
        timeout_sec: 30,
        request_id_header: "x-request-id".to_owned(),
    }
}
