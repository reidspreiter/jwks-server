use super::*;
use actix_web::{http::StatusCode, test as web_test};

#[actix_web::test]
async fn test_jwks_endpoint_err_codes() {
    let app = web_test::init_service(App::new().configure(configure_app)).await;
    let uri = "/.well-known/jwks.json";
    let req = web_test::TestRequest::get().uri(uri).to_request();

    let resp = web_test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Failed to get jwks");

    let methods: [fn() -> web_test::TestRequest; 4] = [
        web_test::TestRequest::delete,
        web_test::TestRequest::patch,
        web_test::TestRequest::post,
        web_test::TestRequest::put,
    ];

    for method in &methods {
        let req = method().uri(uri).to_request();

        let resp = web_test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "Got incorrect response status: {}",
            resp.status()
        );
    }
}

#[actix_web::test]
async fn test_auth_endpoint_err_codes() {
    let app = web_test::init_service(App::new().configure(configure_app)).await;
    let uri = "/auth";
    let req = web_test::TestRequest::post().uri(uri).to_request();

    let resp = web_test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Failed to get jwt");

    let methods: [fn() -> web_test::TestRequest; 4] = [
        web_test::TestRequest::delete,
        web_test::TestRequest::patch,
        web_test::TestRequest::get,
        web_test::TestRequest::put,
    ];

    for method in &methods {
        let req = method().uri(uri).to_request();

        let resp = web_test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "Got incorrect response status: {}",
            resp.status()
        );
    }
}
