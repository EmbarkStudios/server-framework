use server_framework::{
    axum::{response::IntoResponse, routing::get, Router},
    Config, Server,
};

#[tokio::main]
async fn main() {
    init_tracing();

    let config = Config::from_args();

    let routes = Router::new().route("/", get(root));

    Server::new(config)
        .with(routes)
        .serve()
        .await
        .expect("server failed to start");
}

fn init_tracing() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "example_axum=debug,server_framework=debug")
    }
    tracing_subscriber::fmt::init();
}

async fn root() -> impl IntoResponse {
    "Hello, World!"
}
