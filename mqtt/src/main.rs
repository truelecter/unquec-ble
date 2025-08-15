#[tokio::main(flavor = "current_thread")]
async fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .with_colors(true)
        .init()
        .unwrap();

    let scx = rmqtt::context::ServerContext::new().build().await;

    log::info!("Starting MQTT server");

    rmqtt::server::MqttServer::new(scx)
        .listener(
            rmqtt::net::Builder::new()
                .name("external/tcp")
                .laddr(([0, 0, 0, 0], 1337).into())
                .bind()
                .unwrap()
                .tcp()
                .unwrap(),
        )
        .build()
        .run()
        .await;
}