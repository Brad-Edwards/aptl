pub mod account_status;
pub mod game_locations;
pub mod items;
pub mod static_data;

use sqlx::SqlitePool;
use crate::Result;
use account_status::AccountStatusGenerator;
use game_locations::GameLocationsGenerator;
use items::ItemsGenerator;
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

pub async fn generate_all(pool: &SqlitePool) -> Result<()> {
    generate_account_status(pool).await?;
    generate_game_locations(pool).await?;
    generate_items(pool).await?;
    Ok(())
}
