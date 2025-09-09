use clap::Parser;
use crate::Result;

/// Gaming API CLI - Mock MMO server for security demonstrations
#[derive(Parser)]
#[command(name = "gaming-api")]
#[command(about = "A mock gaming API for account takeover simulations")]
pub struct Cli;

impl Cli {
    pub async fn run(self) -> Result<()> {
        println!("Initializing database and seeding data...");
        crate::db::init().await?;
        let pool = crate::db::get_pool().await?;
        crate::generators::generate_all(&pool).await?;
        println!("Complete!");
        Ok(())
    }
}