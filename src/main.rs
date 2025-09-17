mod error;
mod keys;

use actix_web::{App, HttpResponse, HttpServer, Responder, Result as ActixResult, web};
use keys::KeyGen;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

async fn get_jwks(keygen: web::Data<Arc<KeyGen>>) -> ActixResult<impl Responder> {
    info!("JWKS");
    let jwks = keygen.get_jwks();
    Ok(HttpResponse::Ok().json(jwks))
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
    info!("Auth");
    match keygen.generate_jwt(Some(query.expired == Some(String::from("true")))) {
        Ok(jwt) => Ok(HttpResponse::Ok().json(AuthResponse { jwt })),
        Err(e) => {
            error!("Error generating jwt: {e}");
            Ok(HttpResponse::InternalServerError().json("Error generating jwt"))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .init();

    let keygen = Arc::new(KeyGen::new()?);
    info!("Starting jwks server...");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(keygen.clone()))
            .service(web::resource("/auth").route(web::post().to(auth)))
            .service(web::resource("/.well-known/jwks.json").route(web::get().to(get_jwks)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
