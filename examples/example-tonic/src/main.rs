use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use server_framework::{Config, Server};

mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() {
    init_tracing();

    let config = Config::from_args();

    let service = GreeterServer::new(MyGreeter);

    Server::new(config)
        .with_tonic(service)
        .always_live_and_ready()
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

#[derive(Clone)]
pub struct MyGreeter;

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: tonic::Request<HelloRequest>,
    ) -> Result<tonic::Response<HelloReply>, tonic::Status> {
        tracing::debug!(?request);

        let reply = hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };

        Ok(tonic::Response::new(reply))
    }
}
