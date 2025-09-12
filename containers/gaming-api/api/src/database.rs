use sqlx::SqlitePool;

const DATABASE_URL: &str = "sqlite:./data/gaming.db";

pub async fn get_database_pool() -> Result<SqlitePool, sqlx::Error> {
    SqlitePool::connect(DATABASE_URL).await
}