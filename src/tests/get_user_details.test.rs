use crate::apis_mock::setup_test_app;


#[actix_rt::test]
async fn test_get_user_details() {
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

    let user = sqlx::query!("SELECT * FROM users WHERE username = ?", "testuser")
        .fetch_one(&pool)
        .await
        .unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/user/{}", user.id))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
