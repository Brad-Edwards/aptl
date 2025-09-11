use sqlx::SqlitePool;
use crate::Result;
use super::static_data::StaticGameLocation;

pub struct GameLocationsGenerator {
    pool: SqlitePool,
}

impl GameLocationsGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self, data: &[StaticGameLocation]) -> Result<()> {
        for location in data {
            sqlx::query("INSERT INTO game_locations (name) VALUES (?)")
                .bind(&location.name)
                .execute(&self.pool)
                .await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM game_locations")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} game locations", count.0);
        Ok(())
    }
}