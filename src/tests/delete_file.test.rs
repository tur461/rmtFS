use crate::apis_mock::setup_test_app;

#[actix_rt::test]
async fn test_delete_file() {
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

    let file = json!({
        "filename": "testfile.txt",
        "content": "Hello, World!",
        "user_id": user.id,
    });

    let req = test::TestRequest::post()
        .uri(&format!("/api/files/cre_by_uid/{}", user.id))
        .set_payload(file)
        .to_request();
    
    test::call_service(&app, req).await;

    let file = sqlx::query!("SELECT * FROM files WHERE user_id = ?", user.id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!("/api/files/del_by_fid/{}", file.id))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
