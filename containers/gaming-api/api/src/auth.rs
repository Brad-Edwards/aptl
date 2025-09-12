use axum::{
    extract::{State, ConnectInfo},
    http::StatusCode,
    response::Json,
};
use axum_extra::{TypedHeader, headers::UserAgent};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use std::{collections::HashMap, net::SocketAddr};
use crate::{models::User, AppState};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user_id: Option<i64>,
    pub session_id: Option<String>,
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub session_id: String,
}

pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(user_agent): TypedHeader<UserAgent>,
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    
    let client_ip = addr.ip().to_string();
    let user_agent_string = user_agent.as_str();
    
    // Log authentication attempt for Wazuh (PAM format)
    println!(
        "{} game-server gaming-api(pam_unix)[{}]: authentication attempt; rhost={} user={}",
        chrono::Utc::now().format("%b %d %H:%M:%S"),
        std::process::id(),
        client_ip,
        request.username
    );

    // Check credentials against database  
    let user_result: Result<User, sqlx::Error> = sqlx::query_as(
        "SELECT id, username, password_text, email, created_at, account_status_id, first_name, last_name, last_ip_address 
         FROM users WHERE username = ?"
    )
    .bind(&request.username)
    .fetch_one(&state.db)
    .await;

    match user_result {
        Ok(user) => {
            if user.password_text == request.password {
                // Successful login
                let session_id = Uuid::new_v4().to_string();
                
                // Log successful authentication (PAM format)
                println!(
                    "{} game-server gaming-api(pam_unix)[{}]: session opened for user {}; rhost={}",
                    chrono::Utc::now().format("%b %d %H:%M:%S"),
                    std::process::id(),
                    user.username,
                    client_ip
                );

                Ok(Json(LoginResponse {
                    success: true,
                    message: "Login successful".to_string(),
                    user_id: Some(user.id),
                    session_id: Some(session_id),
                }))
            } else {
                // Failed login - wrong password (PAM format)  
                println!(
                    "{} game-server gaming-api(pam_unix)[{}]: authentication failure; logname= rhost={} user={}",
                    chrono::Utc::now().format("%b %d %H:%M:%S"),
                    std::process::id(),
                    client_ip,
                    request.username
                );

                Ok(Json(LoginResponse {
                    success: false,
                    message: "Invalid credentials".to_string(),
                    user_id: None,
                    session_id: None,
                }))
            }
        }
        Err(_) => {
            // Failed login - user not found (PAM format)
            println!(
                "{} game-server gaming-api(pam_unix)[{}]: authentication failure; logname= rhost={} user={}",
                chrono::Utc::now().format("%b %d %H:%M:%S"),
                std::process::id(),
                client_ip,
                request.username
            );

            Ok(Json(LoginResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                user_id: None,
                session_id: None,
            }))
        }
    }
}

pub async fn logout(
    State(_state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> Result<Json<HashMap<&'static str, &'static str>>, StatusCode> {
    
    // Log logout event
    println!(
        "{{\"timestamp\":\"{}\",\"event_type\":\"logout\",\"session_id\":\"{}\"}}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        request.session_id
    );

    let mut response = HashMap::new();
    response.insert("status", "logged_out");
    Ok(Json(response))
}