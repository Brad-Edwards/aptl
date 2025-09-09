use sqlx::SqlitePool;
use crate::Result;
use rand::Rng;

pub struct CharacterInventoryGenerator {
    pool: SqlitePool,
}

impl CharacterInventoryGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self) -> Result<()> {
        // Get gold item ID
        let (gold_item_id,): (i64,) = sqlx::query_as("SELECT id FROM items WHERE name = 'Gold'")
            .fetch_one(&self.pool)
            .await?;

        // Get all characters with their levels
        let characters: Vec<(i64, i64)> = sqlx::query_as("SELECT id, level FROM characters")
            .fetch_all(&self.pool)
            .await?;

        // Get all non-gold items
        let items: Vec<(i64,)> = sqlx::query_as("SELECT id FROM items WHERE name != 'Gold'")
            .fetch_all(&self.pool)
            .await?;
        let item_ids: Vec<i64> = items.into_iter().map(|(id,)| id).collect();

        for (character_id, level) in characters {
            // Give gold (scaled by level)
            let gold_amount = rand::rng().random_range(10..=500) * (level / 10 + 1);
            
            sqlx::query("INSERT INTO character_inventory (character_id, item_id, quantity) VALUES (?, ?, ?)")
                .bind(character_id)
                .bind(gold_item_id)
                .bind(gold_amount)
                .execute(&self.pool)
                .await?;

            // Give random items (0-4 different item types, more for higher levels)
            let max_items = std::cmp::min(4, level / 25 + 1);
            let item_count = rand::rng().random_range(0..=max_items);

            let mut selected_items = Vec::new();
            for _ in 0..item_count {
                // Pick a random item not already selected
                let mut attempts = 0;
                loop {
                    let item_id = item_ids[rand::rng().random_range(0..item_ids.len())];
                    if !selected_items.contains(&item_id) || attempts > 10 {
                        selected_items.push(item_id);
                        let quantity = rand::rng().random_range(1..=5);

                        sqlx::query("INSERT INTO character_inventory (character_id, item_id, quantity) VALUES (?, ?, ?)")
                            .bind(character_id)
                            .bind(item_id)
                            .bind(quantity)
                            .execute(&self.pool)
                            .await?;
                        break;
                    }
                    attempts += 1;
                }
            }
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM character_inventory")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} inventory entries", count.0);
        Ok(())
    }
}