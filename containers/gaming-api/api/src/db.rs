use sqlx::{SqlitePool, migrate};
use crate::Result;

const DATABASE_URL: &str = "sqlite:./data/gaming.db";

/// Get database connection pool
pub async fn get_pool() -> Result<SqlitePool> {
    let pool = SqlitePool::connect(DATABASE_URL).await?;
    Ok(pool)
}

/// Initialize database and run migrations
pub async fn init() -> Result<()> {
    use std::{fs, process::Command};
    
    // Create data directory if it doesn't exist
    fs::create_dir_all("./data")?;
    
    // Remove existing database file if it exists
    if std::path::Path::new("./data/gaming.db").exists() {
        fs::remove_file("./data/gaming.db")?;
        println!("Removed existing database");
    }
    
    // Create empty database file
    Command::new("touch")
        .arg("./data/gaming.db")
        .output()?;
    
    let pool = get_pool().await?;
    
    // Run migrations
    migrate!("./migrations").run(&pool).await?;
    
    // Verify connection by checking table count
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        .fetch_one(&pool)
        .await?;
    
    println!("Database initialized with {} tables", count.0);
    Ok(())
}
