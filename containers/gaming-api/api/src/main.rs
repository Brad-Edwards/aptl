use axum::{
    extract::{Path, State, ConnectInfo},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{collections::HashMap, net::SocketAddr};
use tower::ServiceBuilder;

mod database;
mod models;
mod auth;
mod game;

use database::get_database_pool;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize database connection
    let db_pool = get_database_pool().await?;
    let state = AppState { db: db_pool };

    // Build API routes
    let app = Router::new()
        // Authentication endpoints (cred stuffing targets)
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        
        // Game server endpoints (blue team investigates via normal APIs)
        .route("/users/{user_id}/characters", get(game::get_user_characters))
        .route("/characters/{character_id}/inventory", get(game::get_character_inventory))
        .route("/characters/{character_id}/stats", get(game::get_character_stats))
        .route("/users/{user_id}/sessions", get(game::get_user_sessions))
        .route("/users/{user_id}/transactions", get(game::get_user_transactions))
        .route("/marketplace/listings", get(game::get_marketplace_listings))
        .route("/sessions/{session_id}/activity", get(game::get_session_activity))
        .route("/users/{user_id}/settings-history", get(game::get_user_settings_history))
        
        // Health check
        .route("/health", get(health_check))
        .with_state(state);

    // Start server with ConnectInfo enabled
    println!("🎮 Gaming API Server starting on http://0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    
    Ok(())
}

async fn health_check() -> Json<HashMap<&'static str, &'static str>> {
    let mut response = HashMap::new();
    response.insert("status", "healthy");
    response.insert("service", "gaming-api");
    Json(response)
}
