use crate::hello_world::{
    greeter_client::GreeterClient,
    greeter_server::{Greeter, GreeterServer},
    HelloReply, HelloRequest,
};
use server_framework::{axum::routing::get, Config, Router, Server};
use tokio::net::TcpSocket;
use tonic::{transport::Channel, Status};

#[derive(Clone)]
pub struct MyGreeter;

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: tonic::Request<HelloRequest>,
    ) -> Result<tonic::Response<HelloReply>, tonic::Status> {
        let reply = crate::hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };

        // Sleep to trigger the server side timeout
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        Ok(tonic::Response::new(reply))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_timeout_response() {
    let mut config = Config::default();
    config.timeout_sec = 1;
    config.bind_address = "0.0.0.0:8080".parse().unwrap();

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(config.bind_address).unwrap();
    socket.set_reuseport(true).unwrap();
    socket.set_reuseaddr(true).unwrap();

    let bind_address = config.bind_address;

    let task = tokio::spawn(async move {
        Server::new(config)
            .with_tonic(GreeterServer::new(MyGreeter))
            .always_live_and_ready()
            .serve_with_listener(socket.listen(1024).unwrap())
            .await
            .expect("server failed to start");
    });

    let channel = Channel::builder(format!("http://{}", bind_address).parse().unwrap())
        .connect()
        .await
        .unwrap();

    let mut client = GreeterClient::new(channel);

    let request = tonic::Request::new(HelloRequest {
        name: "test".into(),
    });

    // Will timeout
    let status = client.say_hello(request).await.unwrap_err();

    let expected = Status::deadline_exceeded("request timed out");

    assert_eq!(status.code(), expected.code());
    assert_eq!(status.message(), expected.message());

    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn http_timeout_response() {
    let mut config = Config::default();
    config.timeout_sec = 1;

    config.bind_address = "0.0.0.0:8082".parse().unwrap();

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(config.bind_address).unwrap();
    socket.set_reuseport(true).unwrap();
    socket.set_reuseaddr(true).unwrap();

    let bind_address = config.bind_address;

    let routes = Router::new().route(
        "/",
        get(|| async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            "Hello, World!"
        }),
    );

    let task = tokio::spawn(async move {
        Server::new(config)
            .with(routes)
            .always_live_and_ready()
            .serve_with_listener(socket.listen(1024).unwrap())
            .await
            .expect("server failed to start");
    });

    // Will timeout
    let response = reqwest::get(format!("http://{}", bind_address))
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::REQUEST_TIMEOUT);

    assert_eq!(
        response.text().await.unwrap(),
        "request timed out".to_string()
    );

    task.abort();
}
