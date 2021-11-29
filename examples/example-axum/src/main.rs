use server_framework::{Config, Server, Parser as _};

#[tokio::main]
async fn main() {
    init_tracing();

    let config = Config::parse();
    tracing::debug!(?config);
    Server::new(config);
}

fn init_tracing() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "example_axum=debug")
    }
    tracing_subscriber::fmt::init();
}
