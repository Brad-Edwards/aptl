use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_text: String,
    pub email: String,
    pub created_at: Option<String>,
    pub account_status_id: i64,
    pub first_name: String,
    pub last_name: String,
    pub last_ip_address: String,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Character {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub level: i64,
    pub class_id: i64,
    pub created_at: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub ip_address: String,
    pub login_time: Option<String>,
    pub logout_time: Option<String>,
    pub success: bool,
    pub geo_location: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct PlayerMovement {
    pub id: i64,
    pub user_id: i64,
    pub session_id: i64,
    pub location_id: i64,
    pub timestamp: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub id: i64,
    pub from_character_id: Option<i64>,
    pub to_character_id: Option<i64>,
    pub item_id: i64,
    pub quantity: i64,
    pub timestamp: Option<String>,
    pub transaction_type: String,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct CharacterInventory {
    pub id: i64,
    pub character_id: i64,
    pub item_id: i64,
    pub quantity: i64,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: i64,
    pub name: String,
    pub rarity: String,
    pub gold_value: i64,
}