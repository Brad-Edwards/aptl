use sqlx::SqlitePool;
use crate::Result;
use rand::Rng;

pub struct TransactionsGenerator {
    pool: SqlitePool,
}

impl TransactionsGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn get_transaction_type(&self, types: &[String]) -> String {
        types[rand::rng().random_range(0..types.len())].clone()
    }

    fn random_transaction_time(&self) -> String {
        let start_date = chrono::NaiveDate::from_ymd_opt(2025, 8, 9).unwrap();
        let end_date = chrono::NaiveDate::from_ymd_opt(2025, 9, 8).unwrap();
        
        let days_range = (end_date - start_date).num_days();
        let random_day = start_date + chrono::Duration::days(rand::rng().random_range(0..=days_range));
        
        let hour = rand::rng().random_range(6..=23);
        let minute = rand::rng().random_range(0..=59);
        let second = rand::rng().random_range(0..=59);
        
        format!("{} {:02}:{:02}:{:02}", random_day.format("%Y-%m-%d"), hour, minute, second)
    }

    async fn create_transaction(&self, from_char: i64, to_char: i64, item_id: i64, quantity: i64, transaction_type: &str) -> Result<()> {
        let timestamp = self.random_transaction_time();
        
        sqlx::query("INSERT INTO transactions (from_character_id, to_character_id, item_id, quantity, timestamp, transaction_type) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(from_char)
            .bind(to_char)
            .bind(item_id)
            .bind(quantity)
            .bind(timestamp)
            .bind(transaction_type)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }

    pub async fn generate(&self) -> Result<()> {
        // Load transaction types from JSON
        let loader = crate::generators::static_data::StaticDataLoader::new()?;
        let transaction_types = loader.get_transaction_types()?;
        
        // Get all characters
        let characters: Vec<(i64,)> = sqlx::query_as("SELECT id FROM characters")
            .fetch_all(&self.pool)
            .await?;
        let character_ids: Vec<i64> = characters.into_iter().map(|(id,)| id).collect();

        // Get all items
        let items: Vec<(i64,)> = sqlx::query_as("SELECT id FROM items")
            .fetch_all(&self.pool)
            .await?;
        let item_ids: Vec<i64> = items.into_iter().map(|(id,)| id).collect();

        // Generate transactions for 5% of characters
        let transaction_count = character_ids.len() / 20; // ~5% participation
        
        for _ in 0..transaction_count {
            let from_char = character_ids[rand::rng().random_range(0..character_ids.len())];
            let to_char = character_ids[rand::rng().random_range(0..character_ids.len())];
            
            if from_char != to_char {
                let item_id = item_ids[rand::rng().random_range(0..item_ids.len())];
                let quantity = rand::rng().random_range(1..=5);
                let transaction_type = self.get_transaction_type(&transaction_types);
                
                self.create_transaction(from_char, to_char, item_id, quantity, &transaction_type).await?;
            }
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transactions")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} transactions", count.0);
        Ok(())
    }
}