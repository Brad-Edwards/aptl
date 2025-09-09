pub mod account_status;
pub mod static_data;
pub mod users;

use sqlx::SqlitePool;
use crate::Result;
use account_status::AccountStatusGenerator;
use static_data::StaticDataLoader;
use users::UsersGenerator;

pub async fn generate_account_status(pool: &SqlitePool) -> Result<()> {
    let loader = StaticDataLoader::new()?;
    let account_status_data = loader.get_account_status()?;
    AccountStatusGenerator::new(pool.clone()).generate(&account_status_data).await
}
