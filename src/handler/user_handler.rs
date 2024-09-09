// src/handlers/user_handler.rs

use actix_web::{web, HttpResponse, Responder};
use crate::repo::UserRepo;
use crate::model::{User, RegisterRequest, UserLogin};
use sqlx::sqlite::SqlitePool;
use bcrypt::{hash, verify, DEFAULT_COST};
use crate::jwt::JWT;
use sysinfo::Disks;


pub struct UserHandler;

impl UserHandler {
        pub async fn register(
            user_data: web::Json<RegisterRequest>,
            pool: web::Data<SqlitePool>
        ) -> impl Responder {
            log::info!("called");
            let disks = Disks::new_with_refreshed_list();
            log::info!("### DISK INFO ###");
            let cur_dir = std::env::current_dir().unwrap();
            log::info!("Cur folder: {}", cur_dir.display());
            let cur_disk = disks.iter().find(|disk| cur_dir.starts_with(disk.mount_point()));
            let mut av_space = 0;
            match cur_disk {
                Some(disk) => {
                    av_space = disk.available_space();
                    log::info!("Disk mount point: {}", disk.mount_point().display());
                    log::info!("Available space: {} bytes", av_space);
                    log::info!("Total space: {} bytes", disk.total_space());
        
                }
                None => {
                    log::info!("No disk found for the current directory.");
                    return HttpResponse::InternalServerError().json("Space issue.");
                }
            }
        
            let space_needed = user_data.allocated_space;
        
            if space_needed > av_space {
                // handle this scenario etiher by:
                // 1. returning error
                // 2. connecting to another instance runing somewhere else, sending user details
                return HttpResponse::InsufficientStorage().json("Not enough storage available on server.");
            }
        
            let user_repo = UserRepo::new(pool.get_ref());
        
            let password_hash = hash(&user_data.password, DEFAULT_COST).unwrap();
        
            let new_user = User {
                id: uuid::Uuid::new_v4().to_string(),
                username: user_data.username.clone(),
                password_hash,
                allocated_space: user_data.allocated_space,
                used_space: 0,
            };
        
            match user_repo.create_user(&new_user).await {
                Ok(_) => HttpResponse::Ok().json("User registered"),
                Err(_) => HttpResponse::BadRequest().json("User already exists"),
            }
        }
        
        pub async fn login(
            creds: web::Json<UserLogin>,
            pool: web::Data<SqlitePool>,
            secret: web::Data<String>
        ) -> impl Responder {
            let user_repo = UserRepo::new(pool.get_ref());
        
            match user_repo.get_user_by_username(&creds.username).await {
                Ok(user) => {
                    if verify(&creds.password, &user.password_hash).unwrap() {
                        let token = JWT::create_jwt(user.id, &secret).unwrap();
                        HttpResponse::Ok().json(token)
                    } else {
                        HttpResponse::Unauthorized().body("Invalid username or password")
                    }
                }
                Err(_) => HttpResponse::Unauthorized().body("Invalid username or password"),
            }
        }

        pub async fn get_user_details(
            pool: web::Data<SqlitePool>,
            user_id: web::Path<String>
        ) -> impl Responder {
            let user_repo = UserRepo::new(&pool.as_ref());
            match user_repo.get_user_by_id(&user_id).await {
                Ok(user) => HttpResponse::Ok().json(user),
                Err(_) => HttpResponse::NotFound().json(format!("User with id {} not found.", user_id))
            }
        }
    
}
