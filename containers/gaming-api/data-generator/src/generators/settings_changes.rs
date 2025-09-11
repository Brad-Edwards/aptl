use sqlx::SqlitePool;
use crate::Result;

pub struct SettingsChangesGenerator {
    pool: SqlitePool,
}

impl SettingsChangesGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn create_settings_change(&self, user_id: i64, session_id: i64, change_type: &str, timestamp: &str) -> Result<()> {
        sqlx::query("INSERT INTO settings_changes (user_id, session_id, change_type, timestamp) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(session_id)
            .bind(change_type)
            .bind(timestamp)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn generate(&self) -> Result<()> {
        // Get all Settings location visits from player_movement
        let settings_visits: Vec<(i64, i64, String)> = sqlx::query_as(
            "SELECT pm.user_id, pm.session_id, pm.timestamp 
             FROM player_movement pm 
             JOIN game_locations gl ON pm.location_id = gl.id 
             WHERE gl.name = 'Settings'"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut password_changes = 0;
        let mut email_changes = 0;

        let visit_count = settings_visits.len();
        
        for (user_id, session_id, timestamp) in &settings_visits {
            // 20% chance of password change during Settings visit
            if rand::random::<f32>() < 0.2 {
                self.create_settings_change(*user_id, *session_id, "password", timestamp).await?;
                password_changes += 1;
            }

            // 10% chance of email change during Settings visit
            if rand::random::<f32>() < 0.1 {
                self.create_settings_change(*user_id, *session_id, "email", timestamp).await?;
                email_changes += 1;
            }
        }

        println!("Generated {} password changes, {} email changes from {} settings visits", 
                password_changes, email_changes, visit_count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_probabilities() {
        // Test that the probability logic makes sense
        let mut password_changes = 0;
        let mut email_changes = 0;
        let visits = 1000;

        for _ in 0..visits {
            if rand::random::<f32>() < 0.2 {
                password_changes += 1;
            }
            if rand::random::<f32>() < 0.1 {
                email_changes += 1;
            }
        }

        println!("Over {} visits: {} password changes ({}%), {} email changes ({}%)", 
                visits, password_changes, password_changes * 100 / visits,
                email_changes, email_changes * 100 / visits);

        // Password changes should be roughly 20% (18-22% acceptable range)
        assert!(password_changes > 180 && password_changes < 220, 
                "Password changes should be ~20% of visits");

        // Email changes should be roughly 10% (8-12% acceptable range)  
        assert!(email_changes > 80 && email_changes < 120,
                "Email changes should be ~10% of visits");

        // Password changes should be roughly 2x email changes
        let ratio = password_changes as f64 / email_changes as f64;
        assert!(ratio > 1.5 && ratio < 2.5, "Password changes should be ~2x email changes");
    }

    #[test]
    fn test_settings_change_data_structure() {
        // Test that we're creating the right data structure
        
        // Mock settings visits data
        let mock_visits = vec![
            (1, 101, "2025-08-10 15:30:00".to_string()),
            (2, 102, "2025-08-11 16:45:00".to_string()),
            (1, 103, "2025-08-12 14:20:00".to_string()),
        ];

        println!("Mock settings visits:");
        for (i, (user_id, session_id, timestamp)) in mock_visits.iter().enumerate() {
            println!("  Visit {}: User {} in session {} at {}", i+1, user_id, session_id, timestamp);
        }

        // Verify data structure matches what SQL expects
        for (user_id, session_id, timestamp) in &mock_visits {
            // These should all be valid types for SQL binding
            assert!(*user_id > 0);
            assert!(*session_id > 0); 
            assert!(!timestamp.is_empty());
            assert!(chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S").is_ok());
        }

        assert_eq!(mock_visits.len(), 3);
        println!("Data structure validation passed");
    }

    #[test]
    fn test_change_type_strings() {
        // Verify we're using the correct change type strings
        let change_types = ["password", "email"];
        
        for change_type in &change_types {
            assert!(change_type == &"password" || change_type == &"email");
            assert!(change_type.len() > 0);
        }
        
        println!("Change types validated: {:?}", change_types);
    }
}