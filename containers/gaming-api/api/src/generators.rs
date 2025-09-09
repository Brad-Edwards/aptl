pub mod account_status;
pub mod character_class;
pub mod character_inventory;
pub mod characters;
pub mod game_locations;
pub mod items;
pub mod sessions;
pub mod static_data;
pub mod users;

use sqlx::SqlitePool;
use crate::Result;
use account_status::AccountStatusGenerator;
use character_class::CharacterClassGenerator;
use character_inventory::CharacterInventoryGenerator;
use characters::CharactersGenerator;
use game_locations::GameLocationsGenerator;
use items::ItemsGenerator;
use sessions::SessionsGenerator;
use users::UserGenerator;
use static_data::StaticDataLoader;

pub async fn generate_account_status(pool: &SqlitePool) -> Result<()> {
    let loader = StaticDataLoader::new()?;
    let account_status_data = loader.get_account_status()?;
    AccountStatusGenerator::new(pool.clone()).generate(&account_status_data).await
}

pub async fn generate_game_locations(pool: &SqlitePool) -> Result<()> {
    let loader = StaticDataLoader::new()?;
    let game_locations_data = loader.get_game_locations()?;
    GameLocationsGenerator::new(pool.clone()).generate(&game_locations_data).await
}

pub async fn generate_items(pool: &SqlitePool) -> Result<()> {
    let loader = StaticDataLoader::new()?;
    let items_data = loader.get_items()?;
    ItemsGenerator::new(pool.clone()).generate(&items_data).await
}

pub async fn generate_users(pool: &SqlitePool) -> Result<()> {
    let loader = StaticDataLoader::new()?;
    let users_data = loader.get_users()?;
    UserGenerator::new(pool.clone()).generate(&users_data).await
}

pub async fn generate_character_classes(pool: &SqlitePool) -> Result<()> {
    let loader = StaticDataLoader::new()?;
    let character_class_data = loader.get_character_classes()?;
    CharacterClassGenerator::new(pool.clone()).generate(&character_class_data).await
}

pub async fn generate_characters(pool: &SqlitePool) -> Result<()> {
    let generator = CharactersGenerator::new(pool.clone());
    generator.generate().await
}

pub async fn generate_character_inventory(pool: &SqlitePool) -> Result<()> {
    let generator = CharacterInventoryGenerator::new(pool.clone());
    generator.generate().await
}

pub async fn generate_sessions(pool: &SqlitePool) -> Result<()> {
    let generator = SessionsGenerator::new(pool.clone());
    generator.generate().await
}

pub async fn generate_all(pool: &SqlitePool) -> Result<()> {
    generate_account_status(pool).await?;
    generate_character_classes(pool).await?;
    generate_game_locations(pool).await?;
    generate_items(pool).await?;
    generate_users(pool).await?;
    generate_characters(pool).await?;
    generate_character_inventory(pool).await?;
    generate_sessions(pool).await?;
    Ok(())
}
