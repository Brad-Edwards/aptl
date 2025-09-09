use sqlx::FromRow;
use serde::{Deserialize, Serialize};

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub email: String,
    pub created_at: Option<String>,
    pub account_value: i64,
    pub account_status_id: i64,
    pub email_last_changed: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Character {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub level: i64,
    pub class: String,
    pub created_at: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: i64,
    pub name: String,
    pub gold_value: i64,
    pub item_type: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct GameLocation {
    pub id: i64,
    pub name: String,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct LoginHistory {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub ip_address: String,
    pub login_time: Option<String>,
    pub success: bool,
    pub geo_location: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub login_time: Option<String>,
    pub logout_time: Option<String>,
    pub ip_address: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct PlayerMovement {
    pub id: i64,
    pub user_id: i64,
    pub character_id: Option<i64>,
    pub session_id: String,
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
pub struct MarketplaceActivity {
    pub id: i64,
    pub user_id: i64,
    pub character_id: i64,
    pub session_id: String,
    pub action_type: String,
    pub item_id: Option<i64>,
    pub transaction_id: Option<i64>,
    pub timestamp: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct CharacterInventory {
    pub id: i64,
    pub character_id: i64,
    pub item_id: i64,
    pub quantity: i64,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct AccountStatus {
    pub id: i64,
    pub status: String,
    pub description: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: i64,
    pub from_user_id: i64,
    pub to_user_id: i64,
    pub content: String,
    pub timestamp: Option<String>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct SettingsChange {
    pub id: i64,
    pub user_id: i64,
    pub session_id: i64,
    pub change_type: String,
    pub timestamp: Option<String>,
}