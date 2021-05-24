mod gatekeeper;
mod web;

use actix_web::{web::Data, App, HttpServer};
use gatekeeper::KubeGatekeeperClient;
use kube::Client;
use log::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info,kube=info,actix_web=info");
    env_logger::init();

    let client = Client::try_default().await.unwrap();
    let v = client.apiserver_version().await.unwrap();
    info!("api version: {:?}", v);

    HttpServer::new(move || {
        let gatekeeper_client = KubeGatekeeperClient::new(client.clone());

        let client = Data::new(gatekeeper_client);
        App::new()
            .app_data(client)
            .service(web::index)
            .service(web::constraint_template)
            .service(web::constraint)
            .service(web::config)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
