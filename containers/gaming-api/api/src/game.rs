use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use crate::{models::*, AppState};

#[derive(Serialize)]
pub struct UserDetailsResponse {
    pub user: User,
    pub characters: Vec<Character>,
    pub account_status: String,
}

#[derive(Serialize)]
pub struct UserSessionsResponse {
    pub sessions: Vec<Session>,
    pub total_count: i64,
    pub failed_logins: i64,
}

#[derive(Serialize)]
pub struct SessionMovementsResponse {
    pub movements: Vec<MovementWithLocation>,
    pub session_info: Session,
}

#[derive(Serialize)]
pub struct MovementWithLocation {
    pub movement: PlayerMovement,
    pub location_name: String,
}

#[derive(Serialize)]
pub struct UserTransactionsResponse {
    pub transactions: Vec<TransactionDetail>,
    pub total_count: i64,
}

#[derive(Serialize)]
pub struct TransactionDetail {
    pub transaction: Transaction,
    pub from_character_name: Option<String>,
    pub to_character_name: Option<String>,
    pub item_name: String,
}

#[derive(Serialize)]
pub struct CharacterInventoryResponse {
    pub character: Character,
    pub inventory: Vec<InventoryItem>,
    pub total_value: i64,
}

#[derive(Serialize)]
pub struct InventoryItem {
    pub item: Item,
    pub quantity: i64,
}

pub async fn get_user_characters(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<UserDetailsResponse>, StatusCode> {
    
    // Get user details
    let user: User = sqlx::query_as(
        "SELECT id, username, password_text, email, created_at, account_status_id, first_name, last_name, last_ip_address 
         FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    // Get user's characters
    let characters: Vec<Character> = sqlx::query_as(
        "SELECT id, user_id, name, level, class_id, created_at FROM characters WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get account status
    let (account_status,): (String,) = sqlx::query_as(
        "SELECT status FROM account_status WHERE id = ?"
    )
    .bind(user.account_status_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserDetailsResponse {
        user,
        characters,
        account_status,
    }))
}

pub async fn get_user_sessions(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<UserSessionsResponse>, StatusCode> {
    
    // Get all sessions for user
    let sessions: Vec<Session> = sqlx::query_as(
        "SELECT id, user_id, username, ip_address, login_time, logout_time, success, geo_location 
         FROM sessions WHERE user_id = ? ORDER BY login_time DESC"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_count = sessions.len() as i64;
    let failed_logins = sessions.iter().filter(|s| !s.success).count() as i64;

    Ok(Json(UserSessionsResponse {
        sessions,
        total_count,
        failed_logins,
    }))
}

pub async fn get_session_activity(
    Path(session_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<SessionMovementsResponse>, StatusCode> {
    
    // Get session info
    let session: Session = sqlx::query_as(
        "SELECT id, user_id, username, ip_address, login_time, logout_time, success, geo_location 
         FROM sessions WHERE id = ?"
    )
    .bind(session_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    // Get movements for this session with location names
    let movement_rows = sqlx::query(
        "SELECT pm.id, pm.user_id, pm.session_id, pm.location_id, pm.timestamp, gl.name as location_name
         FROM player_movement pm 
         JOIN game_locations gl ON pm.location_id = gl.id 
         WHERE pm.session_id = ? ORDER BY pm.timestamp"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let movements: Vec<(PlayerMovement, String)> = movement_rows
        .into_iter()
        .map(|row| (
            PlayerMovement {
                id: row.get("id"),
                user_id: row.get("user_id"),
                session_id: row.get("session_id"),
                location_id: row.get("location_id"),
                timestamp: row.get("timestamp"),
            },
            row.get("location_name")
        ))
        .collect();

    let movements_with_location: Vec<MovementWithLocation> = movements
        .into_iter()
        .map(|(movement, location_name)| MovementWithLocation {
            movement,
            location_name,
        })
        .collect();

    Ok(Json(SessionMovementsResponse {
        movements: movements_with_location,
        session_info: session,
    }))
}

pub async fn get_user_transactions(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<UserTransactionsResponse>, StatusCode> {
    
    // Get all transactions involving user's characters
    let transaction_rows = sqlx::query(
        "SELECT t.id, t.from_character_id, t.to_character_id, t.item_id, t.quantity, t.timestamp, t.transaction_type,
                c1.name as from_character_name, c2.name as to_character_name, i.name as item_name
         FROM transactions t
         LEFT JOIN characters c1 ON t.from_character_id = c1.id
         LEFT JOIN characters c2 ON t.to_character_id = c2.id  
         JOIN items i ON t.item_id = i.id
         WHERE c1.user_id = ? OR c2.user_id = ?
         ORDER BY t.timestamp DESC"
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let transaction_details: Vec<(Transaction, Option<String>, Option<String>, String)> = transaction_rows
        .into_iter()
        .map(|row| (
            Transaction {
                id: row.get("id"),
                from_character_id: row.get("from_character_id"),
                to_character_id: row.get("to_character_id"),
                item_id: row.get("item_id"),
                quantity: row.get("quantity"),
                timestamp: row.get("timestamp"),
                transaction_type: row.get("transaction_type"),
            },
            row.get("from_character_name"),
            row.get("to_character_name"),
            row.get("item_name")
        ))
        .collect();

    let total_count = transaction_details.len() as i64;
    
    let transactions: Vec<TransactionDetail> = transaction_details
        .into_iter()
        .map(|(transaction, from_name, to_name, item_name)| TransactionDetail {
            transaction,
            from_character_name: from_name,
            to_character_name: to_name,
            item_name,
        })
        .collect();

    Ok(Json(UserTransactionsResponse {
        transactions,
        total_count,
    }))
}

pub async fn get_character_inventory(
    Path(character_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<CharacterInventoryResponse>, StatusCode> {
    
    // Get character details
    let character: Character = sqlx::query_as(
        "SELECT id, user_id, name, level, class_id, created_at FROM characters WHERE id = ?"
    )
    .bind(character_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    // Get character inventory with item details
    let inventory_rows = sqlx::query(
        "SELECT i.id, i.name, i.rarity, i.gold_value, ci.quantity
         FROM character_inventory ci
         JOIN items i ON ci.item_id = i.id  
         WHERE ci.character_id = ?
         ORDER BY i.gold_value DESC"
    )
    .bind(character_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let inventory_items: Vec<(Item, i64)> = inventory_rows
        .into_iter()
        .map(|row| (
            Item {
                id: row.get("id"),
                name: row.get("name"),
                rarity: row.get("rarity"),
                gold_value: row.get("gold_value"),
            },
            row.get("quantity")
        ))
        .collect();

    let total_value = inventory_items
        .iter()
        .map(|(item, quantity)| item.gold_value * quantity)
        .sum();

    let inventory: Vec<InventoryItem> = inventory_items
        .into_iter()
        .map(|(item, quantity)| InventoryItem { item, quantity })
        .collect();

    Ok(Json(CharacterInventoryResponse {
        character,
        inventory,
        total_value,
    }))
}

#[derive(Serialize)]
pub struct MarketplaceListingsResponse {
    pub listings: Vec<MarketplaceListing>,
    pub total_count: i64,
}

#[derive(Serialize)]
pub struct MarketplaceListing {
    pub item_name: String,
    pub quantity: i64,
    pub price: i64,
    pub seller_character: String,
}

#[derive(Serialize)]
pub struct CharacterStatsResponse {
    pub character: Character,
    pub class_name: String,
    pub total_inventory_value: i64,
    pub last_activity: Option<String>,
}

pub async fn get_marketplace_listings(
    State(state): State<AppState>,
) -> Result<Json<MarketplaceListingsResponse>, StatusCode> {
    
    // Get sample marketplace listings (simulate active marketplace)
    let listing_rows = sqlx::query(
        "SELECT i.name as item_name, ci.quantity, i.gold_value as price, c.name as seller_character
         FROM character_inventory ci
         JOIN items i ON ci.item_id = i.id
         JOIN characters c ON ci.character_id = c.id
         WHERE i.name != 'Gold' AND ci.quantity > 0
         ORDER BY i.gold_value DESC
         LIMIT 20"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let listings: Vec<MarketplaceListing> = listing_rows
        .into_iter()
        .map(|row| MarketplaceListing {
            item_name: row.get("item_name"),
            quantity: row.get("quantity"),
            price: row.get("price"),
            seller_character: row.get("seller_character"),
        })
        .collect();

    Ok(Json(MarketplaceListingsResponse {
        total_count: listings.len() as i64,
        listings,
    }))
}

pub async fn get_character_stats(
    Path(character_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<CharacterStatsResponse>, StatusCode> {
    
    // Get character with class name
    let character_row = sqlx::query(
        "SELECT c.id, c.user_id, c.name, c.level, c.class_id, c.created_at, cc.class_name
         FROM characters c 
         JOIN character_class cc ON c.class_id = cc.id
         WHERE c.id = ?"
    )
    .bind(character_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    let character = Character {
        id: character_row.get("id"),
        user_id: character_row.get("user_id"),
        name: character_row.get("name"),
        level: character_row.get("level"),
        class_id: character_row.get("class_id"),
        created_at: character_row.get("created_at"),
    };
    let class_name: String = character_row.get("class_name");

    // Get inventory value
    let total_value: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(i.gold_value * ci.quantity) 
         FROM character_inventory ci 
         JOIN items i ON ci.item_id = i.id 
         WHERE ci.character_id = ?"
    )
    .bind(character_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .flatten();

    // Get last activity
    let last_activity: Option<String> = sqlx::query_scalar(
        "SELECT MAX(timestamp) FROM player_movement WHERE user_id = 
         (SELECT user_id FROM characters WHERE id = ?)"
    )
    .bind(character_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .flatten();

    Ok(Json(CharacterStatsResponse {
        character,
        class_name,
        total_inventory_value: total_value.unwrap_or(0),
        last_activity,
    }))
}

#[derive(Serialize)]
pub struct UserSettingsHistoryResponse {
    pub settings_changes: Vec<SettingsChangeDetail>,
    pub total_count: i64,
}

#[derive(Serialize)]
pub struct SettingsChangeDetail {
    pub change_type: String,
    pub timestamp: String,
    pub session_id: i64,
}

pub async fn get_user_settings_history(
    Path(user_id): Path<i64>,
    State(state): State<AppState>,
) -> Result<Json<UserSettingsHistoryResponse>, StatusCode> {
    
    let settings_rows = sqlx::query(
        "SELECT change_type, timestamp, session_id
         FROM settings_changes 
         WHERE user_id = ? 
         ORDER BY timestamp DESC"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let settings_changes: Vec<SettingsChangeDetail> = settings_rows
        .into_iter()
        .map(|row| SettingsChangeDetail {
            change_type: row.get("change_type"),
            timestamp: row.get("timestamp"),
            session_id: row.get("session_id"),
        })
        .collect();

    Ok(Json(UserSettingsHistoryResponse {
        total_count: settings_changes.len() as i64,
        settings_changes,
    }))
}