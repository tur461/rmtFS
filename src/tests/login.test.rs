use crate::apis_mock::setup_test_app;

#[actix_rt::test]
async fn test_login() {
    let (app, pool) = setup_test_app().await;

    let new_user = json!({
        "username": "testuser",
        "password": "password123",
        "allocated_space": 100,
    });

    let req = test::TestRequest::post()
        .uri("/api/register")
        .set_json(&new_user)
        .to_request();
    
    test::call_service(&app, req).await;

    let login_creds = json!({
        "username": "testuser",
        "password": "password123",
    });

    let req = test::TestRequest::post()
        .uri("/api/login")
        .set_json(&login_creds)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
