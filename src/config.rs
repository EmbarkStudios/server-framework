use std::net::SocketAddr;

/// Server configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// The socket address the server will bind to.
    ///
    /// Defaults to `0.0.0.0:8080`.
    pub bind_address: SocketAddr,

    /// The port the metrics and health server will bind to.
    ///
    /// Defaults to `8081`.
    pub metrics_health_port: u16,

    /// Whether or not to only accept http2 traffic.
    ///
    /// Defaults to `false`.
    pub http2_only: bool,

    /// The request timeout in seconds.
    ///
    /// Defaults to 30.
    pub timeout_sec: u64,

    /// The rqeuest id headers.
    ///
    /// Defaults to `x-request-id`.
    pub request_id_header: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 8080)),
            metrics_health_port: 8081,
            http2_only: false,
            timeout_sec: 30,
            request_id_header: "x-request-id".to_owned(),
        }
    }
}
