use sqlx::SqlitePool;
use crate::Result;
use super::static_data::StaticDataLoader;
use rand::Rng;

pub struct CharactersGenerator {
    pool: SqlitePool,
}

impl CharactersGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self) -> Result<()> {
        let loader = StaticDataLoader::new()?;
        let char_names = loader.get_char_names()?;
        let mut name_index = 0;
        
        // Get all users
        let users: Vec<(i64, String)> = sqlx::query_as("SELECT id, created_at FROM users")
            .fetch_all(&self.pool)
            .await?;
            
        // Get character class count for random selection
        let (class_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM character_class")
            .fetch_one(&self.pool)
            .await?;

        for (user_id, user_created_at) in users {
            let char_count = rand::rng().random_range(1..=3);
            
            for i in 0..char_count {
                let name = &char_names[name_index % char_names.len()];
                name_index += 1;
                
                let level = rand::rng().random_range(1..=100);
                let class_id = rand::rng().random_range(1..=class_count);
                
                let created_at = if i == 0 {
                    user_created_at.clone()
                } else {
                    self.random_date_between(&user_created_at, "2025-09-08 00:00:00")
                };
                
                sqlx::query("INSERT INTO characters (user_id, name, level, class_id, created_at) VALUES (?, ?, ?, ?, ?)")
                    .bind(user_id)
                    .bind(name)
                    .bind(level)
                    .bind(class_id)
                    .bind(created_at)
                    .execute(&self.pool)
                    .await?;
            }
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM characters")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} characters", count.0);
        Ok(())
    }

    fn random_date_between(&self, start: &str, end: &str) -> String {
        if let (Ok(start_dt), Ok(end_dt)) = (
            chrono::NaiveDateTime::parse_from_str(start, "%Y-%m-%d %H:%M:%S"),
            chrono::NaiveDateTime::parse_from_str(end, "%Y-%m-%d %H:%M:%S")
        ) {
            let duration = end_dt - start_dt;
            let random_seconds = rand::rng().random_range(0..=duration.num_seconds());
            let random_dt = start_dt + chrono::Duration::seconds(random_seconds);
            random_dt.format("%Y-%m-%d %H:%M:%S").to_string()
        } else {
            start.to_string()
        }
    }
}