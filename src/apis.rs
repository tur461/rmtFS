use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use bcrypt::{hash, verify, DEFAULT_COST};
use crate::jwt::create_jwt;
use crate::models::{
    User,
    create_user, 
    get_user_by_id, 
    update_user_space, 
    get_user_by_username, 
};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::fs;
use log::error;

const PATH_TO_FILES: &str = "./src/files/";


#[derive(Deserialize)]
pub struct UserLogin {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
    allocated_space: usize, // Space in MB
}


#[derive(Deserialize)]
struct FileUpload {
    filename: String,
    size: usize, // File size in MB
}


#[derive(Serialize, Deserialize, Clone, Default)]
pub struct File {
    pub id: String,
    pub user_id: String,
    pub filename: String,
    pub filepath: String,
    pub size: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileReq {
    pub filename: String,
    pub content: String,
    // optional
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub filepath: String,
    #[serde(default)]
    pub size: usize,
}

pub async fn register(
    user_data: web::Json<RegisterRequest>,
    pool: web::Data<SqlitePool>
) -> impl Responder {
    log::info!("called");
    let password_hash = hash(&user_data.password, DEFAULT_COST).unwrap();

    let new_user = User {
        id: Uuid::new_v4().to_string(),
        username: user_data.username.clone(),
        password_hash,
        allocated_space: user_data.allocated_space,
        used_space: 0,
    };

    match create_user(pool.get_ref(), &new_user).await {
        Ok(_) => HttpResponse::Ok().json("User registered"),
        Err(_) => HttpResponse::BadRequest().json("User already exists"),
    }
}

pub async fn login(
    creds: web::Json<UserLogin>, 
    pool: web::Data<SqlitePool>,
    secret: web::Data<String>
) -> impl Responder {
    match get_user_by_username(&pool, &creds.username).await {
        Ok(user) => {
            if verify(&creds.password, &user.password_hash).unwrap() {
                let token = create_jwt(user.id, &secret).unwrap();
                HttpResponse::Ok().json(token)
            } else {
                HttpResponse::Unauthorized().body("Invalid password")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid username"),
    }
}

pub async fn get_user_details( 
    pool: web::Data<SqlitePool>,
    user_id: web::Path<String>
) -> impl Responder {
    let user = get_user_by_id(&pool, &user_id).await;
    if user.is_err() {
        return HttpResponse::InternalServerError().body("user not found!.");
    }
    let user = user.unwrap();
    
    HttpResponse::Ok().json(user)
}


pub async fn get_files(
    pool: web::Data<SqlitePool>,
    user_id: web::Path<String>
) -> impl Responder {
    let rows = sqlx::query("SELECT id, user_id, filename, filepath, size FROM files WHERE user_id = ?")
        .bind(user_id.to_string())
        .fetch_all(pool.get_ref())
        .await;

    match rows {
        Ok(files) => {
            let files: Vec<File> = files.into_iter().map(|row| {
                File {
                    id: row.try_get("id").unwrap(),
                    user_id: row.try_get("user_id").unwrap(),
                    filename: row.try_get("filename").unwrap(),
                    filepath: row.try_get("filepath").unwrap(),
                    size: row.get::<i32, _>("size") as usize,
                }
            }).collect();

            HttpResponse::Ok().json(files)
        },
        Err(e) => {
            error!("Error Fetching Files: {}", e);
            HttpResponse::InternalServerError().body("Error fetching files")
        },
    }
}

pub async fn get_file_by_id(
    pool: web::Data<SqlitePool>, 
    id: web::Path<String>
) -> impl Responder {
    let file = sqlx::query("SELECT id, filename, filepath, size FROM files WHERE id = ?")
        .bind(id.into_inner())
        .fetch_optional(pool.get_ref())
        .await;

    match file {
        Ok(Some(file)) => {
            let filepath: String = file.try_get("filepath").unwrap();
            match fs::read(&filepath) {
                Ok(content) => HttpResponse::Ok().body(content),
                Err(_) => HttpResponse::InternalServerError().body("Error reading file from disk"),
            }
        }
        Ok(None) => HttpResponse::NotFound().body("File not found"),
        Err(_) => HttpResponse::InternalServerError().body("Error fetching file"),
    }
}

pub async fn create_file(
    pool: web::Data<SqlitePool>, 
    file_data: web::Json<FileReq>, 
    user_id: web::Path<String>
) -> impl Responder {
    let user = get_user_by_id(&pool, &user_id).await;
    if user.is_err() {
        return HttpResponse::InternalServerError().body("user not found!.");
    }
    let user = user.unwrap();
    let (allocated_space, used_space) = (user.allocated_space, user.used_space);
    
    let size = file_data.content.len();    
    let file_size = size;
    if used_space + file_size > allocated_space {
        return HttpResponse::BadRequest().body("Not enough space allocated");
    }

    let new_file = file_data.into_inner();

    // here check if there is a directory under PATH_TO_FILE with name user_id
    // if not create it
    let uid = ""; // for now it is empty, else it'll be user_id

    let filepath = format!("{}{}{}", PATH_TO_FILES, uid, new_file.filename); // Adjust this path
    let file_id = Uuid::new_v4().to_string();
    
    match fs::write(&filepath, "default content") { // Replace with actual file content
        Ok(_) => (),
        Err(e) => {
            error!("FS ERROR: {}", e);
            return HttpResponse::InternalServerError().body("Error saving file to disk")
        },
    }

    let result = sqlx::query("INSERT INTO files (id, user_id, filename, filepath, size) VALUES (?, ?, ?, ?, ?)")
        .bind(&file_id)
        .bind(user_id.to_string())
        .bind(&new_file.filename)
        .bind(&filepath)
        .bind(file_size.to_string())
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => {
            let new_used_space = used_space + file_size;
            if let Err(_) = update_user_space(pool.get_ref(), &user_id, new_used_space).await {
                return HttpResponse::InternalServerError().body("Error updating user space");
            }

            HttpResponse::Created().json("File created successfully")
        }
        Err(_) => HttpResponse::InternalServerError().body("Error saving file metadata"),
    }
}

pub async fn update_file(
    pool: web::Data<SqlitePool>, 
    id: web::Path<String>, 
    updated_file: web::Json<File>
) -> impl Responder {
    let file_id = id.into_inner();
    let filepath = format!("/path/to/files/{}", updated_file.filename);  // Adjust path

    match fs::write(&filepath, "new file content") {  // Replace with actual new content
        Ok(_) => (),
        Err(_) => return HttpResponse::InternalServerError().body("Error updating file on disk"),
    }

    let result = sqlx::query("UPDATE files SET filename = ?, filepath = ?, size = ? WHERE id = ?")
        .bind(&updated_file.filename)
        .bind(&filepath)
        .bind(updated_file.size.to_string())
        .bind(file_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("File updated successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error updating file metadata"),
    }
}

pub async fn delete_file(
    pool: web::Data<SqlitePool>, 
    id: web::Path<String>,
    user_id: web::Path<String> 
) -> impl Responder {
    let user = get_user_by_username(&pool, &user_id).await;
    if user.is_err() {
        return HttpResponse::InternalServerError().body("user not found!.");
    }
    let user = user.unwrap();

    let file_id = id.into_inner();

    let file_row = sqlx::query("SELECT filepath, size FROM files WHERE id = ?")
        .bind(&file_id)
        .fetch_optional(pool.get_ref())
        .await;

    match file_row {
        Ok(Some(file)) => {
            let filepath: String = file.try_get("filepath").unwrap();
            let file_size: usize = file.get::<i32, _>("size") as usize;

            if let Err(_) = fs::remove_file(&filepath) {
                return HttpResponse::InternalServerError().body("Error deleting file from disk");
            }

            let result = sqlx::query("DELETE FROM files WHERE id = ?")
                .bind(&file_id)
                .execute(pool.get_ref())
                .await;

            match result {
                Ok(_) => {
                    let used_space = user.used_space;
                    let new_used_space = used_space - file_size;
                    if let Err(_) = update_user_space(pool.get_ref(), &user_id, new_used_space).await {
                        return HttpResponse::InternalServerError().body("Error updating user space");
                    }

                    HttpResponse::Ok().body("File deleted successfully")
                }
                Err(_) => HttpResponse::InternalServerError().body("Error deleting file metadata"),
            }
        }
        Ok(None) => HttpResponse::NotFound().body("File not found"),
        Err(_) => HttpResponse::InternalServerError().body("Error fetching file"),
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, web};
    use serde_json::json;
    use sqlx::SqlitePool;
    use crate::{register, login, get_files, get_file_by_id, create_file, update_file, delete_file};
    
    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
    
        sqlx::query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                allocated_space INTEGER,
                used_space INTEGER
            );"
        ).execute(&pool).await.unwrap();
    
        sqlx::query(
            "CREATE TABLE files (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                filename TEXT,
                filepath TEXT,
                size INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );"
        ).execute(&pool).await.unwrap();
    
        pool
    }
    
    fn get_mock_token(user_id: &str) -> String {
        format!("Bearer mocktoken_{}", user_id)
    }
    
    #[actix_rt::test]
    async fn test_register() {
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(web::resource("/register").route(web::post().to(register)))
        ).await;
    
        let payload = json!({
            "username": "testuser",
            "password": "password123",
            "allocated_space": 100
        });
    
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&payload)
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    
        let user_exists: bool = sqlx::query_scalar("SELECT COUNT(*) > 0 FROM users WHERE username = ?")
            .bind("testuser")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(user_exists);
    }
    
    #[actix_rt::test]
    async fn test_login() {
        let jwt_secret = "test_secret".to_string();
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(jwt_secret.clone()))
                .service(web::resource("/login").route(web::post().to(login)))
        ).await;
    
        // First, insert a user into the database.
        let password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("user_1")
        .bind("testuser")
        .bind(password_hash)
        .bind(100)
        .bind(0)
        .execute(&pool).await.unwrap();
    
        let payload = json!({
            "username": "testuser",
            "password": "password123"
        });
    
        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&payload)
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
    
    #[actix_rt::test]
    async fn test_upload_file_success() {
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(web::resource("/upload").route(web::post().to(upload_file)))
        ).await;
    
        // Insert user into the database
        let password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("user_1")
        .bind("testuser")
        .bind(password_hash)
        .bind(100)
        .bind(0)
        .execute(&pool).await.unwrap();
    
        // Mock file upload payload
        let payload = json!({
            "filename": "testfile.txt",
            "size": 10 // Size in MB
        });
    
        let req = test::TestRequest::post()
            .uri("/upload")
            .set_json(&payload)
            .insert_header(("Authorization", get_mock_token("user_1")))
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
    
    #[actix_rt::test]
    async fn test_upload_file_insufficient_space() {
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(web::resource("/upload").route(web::post().to(upload_file)))
        ).await;
    
        // Insert user with low allocated space
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("user_2")
        .bind("testuser2")
        .bind(bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap())
        .bind(5) // Only 5 MB of space allocated
        .bind(0)
        .execute(&pool).await.unwrap();
    
        let payload = json!({
            "filename": "testfile_large.txt",
            "size": 10 // Exceeds allocated space
        });
    
        let req = test::TestRequest::post()
            .uri("/upload")
            .set_json(&payload)
            .insert_header(("Authorization", get_mock_token("user_2")))
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Not enough space
    }
    
    #[actix_rt::test]
    async fn test_get_files_success() {
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(web::resource("/files").route(web::get().to(get_files)))
        ).await;
    
        // Insert user and a file
        let password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("user_1")
        .bind("testuser")
        .bind(password_hash)
        .bind(100)
        .bind(0)
        .execute(&pool).await.unwrap();
    
        sqlx::query(
            "INSERT INTO files (id, user_id, filename, filepath, size)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("file_1")
        .bind("user_1")
        .bind("testfile.txt")
        .bind("/path/to/testfile.txt")
        .bind(10)
        .execute(&pool).await.unwrap();
    
        let req = test::TestRequest::get()
            .uri("/files")
            .insert_header(("Authorization", get_mock_token("user_1")))
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
    
    #[actix_rt::test]
    async fn test_get_file_by_id_success() {
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(web::resource("/file/{id}").route(web::get().to(get_file_by_id)))
        ).await;
    
        // Insert user and file into the database
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("user_1")
        .bind("testuser")
        .bind(bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap())
        .bind(100)
        .bind(0)
        .execute(&pool).await.unwrap();
    
        sqlx::query(
            "INSERT INTO files (id, user_id, filename, filepath, size)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("file_1")
        .bind("user_1")
        .bind("testfile.txt")
        .bind("/path/to/testfile.txt")
        .bind(10)
        .execute(&pool).await.unwrap();
    
        let req = test::TestRequest::get()
            .uri("/file/file_1")
            .insert_header(("Authorization", get_mock_token("user_1")))
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
    
    #[actix_rt::test]
    async fn test_delete_file_success() {
        let pool = setup_test_db().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(web::resource("/file/{id}").route(web::delete().to(delete_file)))
        ).await;
    
        // Insert user and file into the database
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("user_1")
        .bind("testuser")
        .bind(bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap())
        .bind(100)
        .bind(0)
        .execute(&pool).await.unwrap();
    
        sqlx::query(
            "INSERT INTO files (id, user_id, filename, filepath, size)
            VALUES (?, ?, ?, ?, ?)"
        ).bind("file_1")
        .bind("user_1")
        .bind("testfile.txt")
        .bind("/path/to/testfile.txt")
        .bind(10)
        .execute(&pool).await.unwrap();
    
        let req = test::TestRequest::delete()
            .uri("/file/file_1")
            .insert_header(("Authorization", get_mock_token("user_1")))
            .to_request();
    
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
}

