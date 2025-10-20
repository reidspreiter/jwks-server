mod error;
mod keys;

use actix_web::{App, HttpResponse, HttpServer, Responder, Result as ActixResult, web};
use keys::KeyGen;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

async fn get_jwks(keygen: web::Data<Arc<KeyGen>>) -> ActixResult<impl Responder> {
    let result = web::block(move || {
        keygen.get_jwks()
    }).await;

    match result {
        Ok(Ok(jwks)) => Ok(HttpResponse::Ok().json(jwks)),
        Ok(Err(e)) => {
            error!("Error generating jwks: {e}");
            Ok(HttpResponse::InternalServerError().json("Error generating jwks"))
        },
        Err(e) => {
            error!("Blocking error: {e}");
            Ok(HttpResponse::InternalServerError().json("Error generating jwks"))
        }
    }
}

#[derive(Deserialize)]
struct AuthQueryParams {
    expired: Option<String>,
}

#[derive(Serialize)]
struct AuthResponse {
    jwt: String,
}

async fn auth(
    keygen: web::Data<Arc<KeyGen>>,
    query: web::Query<AuthQueryParams>,
) -> ActixResult<impl Responder> {
    let result = web::block(move || {
        keygen.generate_jwt(query.expired == Some(String::from("true")))
    }).await;

    match result {
        Ok(Ok(jwt)) => Ok(HttpResponse::Ok().json(AuthResponse { jwt })),
        Ok(Err(e)) => {
            error!("Error generating jwt: {e}");
            Ok(HttpResponse::InternalServerError().json("Error generating jwt"))
        }
        Err(e) => {
            error!("Blocking error: {e}");
            Ok(HttpResponse::InternalServerError().json("Error generating jwt"))
        }
    }
}

fn configure_app(cfg: &mut web::ServiceConfig, keygen: Arc<KeyGen>) {
    cfg.app_data(web::Data::new(keygen))
        .service(web::resource("/auth").route(web::post().to(auth)))
        .service(web::resource("/.well-known/jwks.json").route(web::get().to(get_jwks)));
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .init();

    let keygen = Arc::new(KeyGen::new(true).unwrap());

    info!("Starting jwks server...");
    HttpServer::new(move || {
        App::new().configure(|cfg| configure_app(cfg, keygen.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[cfg(test)]
#[path = "tests/test_main.rs"]
mod test_main;
