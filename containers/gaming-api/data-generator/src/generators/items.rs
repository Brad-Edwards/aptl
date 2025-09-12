use sqlx::SqlitePool;
use crate::Result;
use super::static_data::StaticItem;

pub struct ItemsGenerator {
    pool: SqlitePool,
}

impl ItemsGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self, data: &[StaticItem]) -> Result<()> {
        for item in data {
            sqlx::query("INSERT INTO items (name, rarity, gold_value) VALUES (?, ?, ?)")
                .bind(&item.name)
                .bind(&item.rarity)
                .bind(&item.gold_value)
                .execute(&self.pool)
                .await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM items")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} items", count.0);
        Ok(())
    }
}