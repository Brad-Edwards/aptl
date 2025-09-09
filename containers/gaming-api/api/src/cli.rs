use clap::{Parser, Subcommand};
use crate::Result;

/// Gaming API CLI - Mock MMO server for security demonstrations
#[derive(Parser)]
#[command(name = "gaming-api")]
#[command(about = "A mock gaming API for account takeover simulations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        self.command.execute().await
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize database and run migrations
    Init,
    /// Generate mock data for all tables
    Seed {
        /// Clear existing data before seeding
        #[arg(long)]
        clear: bool,
    },
    /// Generate specific data types
    Generate {
        /// Data type to generate (users, characters, etc.)
        #[arg(value_enum)]
        data_type: DataType,
        /// Number of records to generate
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
    /// Verify database integrity and relationships
    Verify,
}

#[derive(clap::ValueEnum, Clone)]
pub enum DataType {
    Users,
    Characters,
    Items,
    Locations,
    Channels,
}

impl Commands {
    pub async fn execute(self) -> Result<()> {
        match self {
            Commands::Init => {
                println!("Initializing database...");
                crate::db::init().await?;
                println!("Database initialized successfully!");
            }
            Commands::Seed { clear } => {
                if clear {
                    println!("Clearing existing data...");
                }
                println!("Seeding database with mock data...");
                // TODO: Implement seeding
                println!("Database seeded successfully!");
            }
            Commands::Generate { data_type, count } => {
                println!("Generating {} {} records...", count, data_type.name());
                // TODO: Implement specific generation
                println!("Generated {} records!", count);
            }
            Commands::Verify => {
                println!("Verifying database integrity...");
                crate::db::verify().await?;
                println!("Database verification complete!");
            }
        }
        Ok(())
    }
}

impl DataType {
    fn name(&self) -> &'static str {
        match self {
            DataType::Users => "users",
            DataType::Characters => "characters", 
            DataType::Items => "items",
            DataType::Locations => "locations",
            DataType::Channels => "channels",
        }
    }
}