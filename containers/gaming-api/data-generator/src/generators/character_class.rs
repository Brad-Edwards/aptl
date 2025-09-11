use sqlx::SqlitePool;
use crate::Result;
use super::static_data::StaticCharacterClass;

pub struct CharacterClassGenerator {
    pool: SqlitePool,
}

impl CharacterClassGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self, data: &[StaticCharacterClass]) -> Result<()> {
        for class in data {
            sqlx::query("INSERT INTO character_class (class_name) VALUES (?)")
                .bind(&class.class_name)
                .execute(&self.pool)
                .await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM character_class")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} character classes", count.0);
        Ok(())
    }
}