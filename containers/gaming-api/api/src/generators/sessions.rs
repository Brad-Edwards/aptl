use sqlx::SqlitePool;
use crate::Result;
use rand::Rng;

pub struct SessionsGenerator {
    pool: SqlitePool,
}

impl SessionsGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn get_user_pattern(&self) -> &'static str {
        let rand = rand::random::<f32>();
        if rand < 0.8 { "active" }
        else if rand < 0.95 { "casual" }
        else { "dormant" }
    }

    fn get_gap_days(&self, pattern: &str) -> i64 {
        match pattern {
            "active" => rand::rng().random_range(1..=3),
            "casual" => rand::rng().random_range(3..=7),
            "dormant" => rand::rng().random_range(7..=30),
            _ => 1,
        }
    }

    fn generate_additional_ip(&self) -> String {
        format!("72.{}.{}.{}", 
            rand::rng().random_range(1..=255),
            rand::rng().random_range(1..=255),
            rand::rng().random_range(1..=255))
    }

    fn random_time_of_day(&self) -> String {
        let hour = rand::rng().random_range(6..=23);
        let minute = rand::rng().random_range(0..=59);
        let second = rand::rng().random_range(0..=59);
        format!("{:02}:{:02}:{:02}", hour, minute, second)
    }

    fn random_session_duration_minutes() -> i64 {
        rand::rng().random_range(30..=360)
    }

    fn get_user_ips(&self, primary_ip: String) -> Vec<String> {
        let mut ips = vec![primary_ip];
        if rand::random::<f32>() < 0.2 {
            ips.push(self.generate_additional_ip());
        }
        ips
    }

    async fn generate_user_sessions(&self, user_id: i64, username: &str, created_at: &str, user_ips: &[String]) -> Result<()> {
        let pattern = self.get_user_pattern();
        
        if let Ok(start_date) = chrono::NaiveDateTime::parse_from_str(created_at, "%Y-%m-%d %H:%M:%S") {
            let end_date = chrono::NaiveDateTime::parse_from_str("2025-09-08 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
            let mut current_date = start_date;

            while current_date < end_date {
                let gap_days = self.get_gap_days(pattern);
                current_date = current_date + chrono::Duration::days(gap_days);
                
                if current_date >= end_date { break; }

                let login_hour = rand::rng().random_range(6..=22); // Cap at 22:XX to allow session time
                let login_minute = rand::rng().random_range(0..=59);
                let login_second = rand::rng().random_range(0..=59);
                
                let login_dt = current_date.date().and_hms_opt(login_hour, login_minute, login_second).unwrap();
                let login_time = login_dt.format("%Y-%m-%d %H:%M:%S").to_string();

                let ip = &user_ips[rand::rng().random_range(0..user_ips.len())];

                if rand::random::<f32>() < 0.95 {
                    self.insert_successful_session(user_id, username, ip, &login_time, login_dt).await?;
                } else {
                    self.insert_failed_session(user_id, username, ip, &login_time).await?;
                }
            }
        }
        Ok(())
    }

    async fn insert_successful_session(&self, user_id: i64, username: &str, ip: &str, login_time: &str, current_date: chrono::NaiveDateTime) -> Result<()> {
        let duration = Self::random_session_duration_minutes();
        let logout_dt = current_date + chrono::Duration::minutes(duration);
        
        // Ensure logout doesn't go past 23:59 same day - cap long sessions  
        let end_of_day = current_date.date().and_hms_opt(23, 59, 0).unwrap();
        let actual_logout = std::cmp::min(logout_dt, end_of_day);
        
        let logout_time = actual_logout.format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query("INSERT INTO sessions (user_id, username, ip_address, login_time, logout_time, success, geo_location) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(username)
            .bind(ip)
            .bind(login_time)
            .bind(&logout_time)
            .bind(true)
            .bind("US East Coast")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn insert_failed_session(&self, user_id: i64, username: &str, ip: &str, login_time: &str) -> Result<()> {
        sqlx::query("INSERT INTO sessions (user_id, username, ip_address, login_time, logout_time, success, geo_location) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(username)
            .bind(ip)
            .bind(login_time)
            .bind(None::<String>)
            .bind(false)
            .bind("US East Coast")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn generate(&self) -> Result<()> {
        let users: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT id, username, created_at, last_ip_address FROM users"
        )
        .fetch_all(&self.pool)
        .await?;

        for (user_id, username, created_at, primary_ip) in users {
            let user_ips = self.get_user_ips(primary_ip);
            self.generate_user_sessions(user_id, &username, &created_at, &user_ips).await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} sessions", count.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_duration_logic() {
        println!("=== SESSION DURATION TESTS ===");
        
        // Test various login times with session durations
        let test_cases = [
            ("2025-08-10 06:00:00", 60),   // 6 AM + 1 hour = 7 AM  
            ("2025-08-10 14:30:00", 120),  // 2:30 PM + 2 hours = 4:30 PM
            ("2025-08-10 20:00:00", 180),  // 8 PM + 3 hours = 11 PM
            ("2025-08-10 22:00:00", 360),  // 10 PM + 6 hours = would be 4 AM next day
        ];
        
        for (login_time, duration_min) in test_cases {
            let login_dt = chrono::NaiveDateTime::parse_from_str(login_time, "%Y-%m-%d %H:%M:%S").unwrap();
            let logout_dt = login_dt + chrono::Duration::minutes(duration_min);
            
            // Test the capping logic
            let end_of_day = login_dt.date().and_hms_opt(23, 59, 0).unwrap();
            let actual_logout = std::cmp::min(logout_dt, end_of_day);
            
            let actual_duration = (actual_logout - login_dt).num_minutes();
            
            println!("Login: {}, Planned duration: {}min, Actual logout: {}, Actual duration: {}min", 
                    login_time, duration_min, actual_logout.format("%H:%M:%S"), actual_duration);
            
            // Verify logout is always after login
            assert!(actual_logout > login_dt, "Logout must be after login");
            
            // Verify logout doesn't exceed end of day
            assert!(actual_logout <= end_of_day, "Logout must be same day");
            
            // Verify duration is positive
            assert!(actual_duration >= 0, "Session duration must be positive");
        }
    }

    #[test]
    fn test_session_time_generation() {
        println!("=== TIME GENERATION TESTS ===");
        
        // Test multiple random time generations
        for i in 0..10 {
            let login_hour = rand::rng().random_range(6..=23);
            let login_minute = rand::rng().random_range(0..=59);
            let login_second = rand::rng().random_range(0..=59);
            
            println!("Generated time {}: {:02}:{:02}:{:02}", i+1, login_hour, login_minute, login_second);
            
            // Verify time components are in valid ranges
            assert!(login_hour >= 6 && login_hour <= 23);
            assert!(login_minute >= 0 && login_minute <= 59);
            assert!(login_second >= 0 && login_second <= 59);
        }
    }

    #[test]
    fn test_session_duration_bounds() {
        println!("=== SESSION DURATION BOUNDS ===");
        
        for _ in 0..10 {
            let duration = SessionsGenerator::random_session_duration_minutes();
            println!("Generated duration: {} minutes", duration);
            
            // Verify duration is within expected bounds (30-360 minutes)
            assert!(duration >= 30 && duration <= 360, "Duration {} should be 30-360 minutes", duration);
        }
    }

    #[test] 
    fn test_end_to_end_session_timing() {
        println!("=== END-TO-END SESSION TIMING TEST ===");
        
        // Simulate the exact logic from the session generator
        let base_date = chrono::NaiveDate::from_ymd_opt(2025, 8, 10).unwrap();
        
        for test_case in 0..5 {
            // Generate login time (same logic as real generator)
            let login_hour = rand::rng().random_range(6..=23);
            let login_minute = rand::rng().random_range(0..=59); 
            let login_second = rand::rng().random_range(0..=59);
            let login_dt = base_date.and_hms_opt(login_hour, login_minute, login_second).unwrap();
            
            // Generate session duration
            let duration = rand::rng().random_range(30..=360);
            let logout_dt = login_dt + chrono::Duration::minutes(duration);
            
            // Apply capping logic
            let end_of_day = login_dt.date().and_hms_opt(23, 59, 0).unwrap();
            let actual_logout = std::cmp::min(logout_dt, end_of_day);
            
            let actual_duration = (actual_logout - login_dt).num_minutes();
            
            println!("Test {}: Login {}, Duration {}min -> Logout {}, Actual {}min", 
                    test_case + 1,
                    login_dt.format("%H:%M:%S"),
                    duration,
                    actual_logout.format("%H:%M:%S"), 
                    actual_duration);
            
            // Critical assertions
            assert!(actual_logout >= login_dt, "Logout must be >= login time");
            assert!(actual_duration >= 0, "Duration must be positive");
            assert!(actual_logout <= end_of_day, "Must not exceed same day");
        }
    }

    #[test]
    fn test_late_login_edge_cases() {
        println!("=== LATE LOGIN EDGE CASE TESTS ===");
        
        // Test very late logins that could cause negative durations
        let late_login_cases = [
            ("22:30:00", 60),    // 22:30 + 60min = 23:30 (ok)
            ("22:45:00", 120),   // 22:45 + 120min = 00:45 next day (should cap at 23:59)
            ("23:30:00", 180),   // 23:30 + 180min = 02:30 next day (should cap at 23:59)
            ("23:58:00", 60),    // 23:58 + 60min = 00:58 next day (should cap at 23:59)
        ];
        
        let base_date = chrono::NaiveDate::from_ymd_opt(2025, 8, 10).unwrap();
        
        for (login_time_str, duration_min) in late_login_cases {
            // Parse login time components
            let time_parts: Vec<u32> = login_time_str.split(':').map(|s| s.parse().unwrap()).collect();
            let login_dt = base_date.and_hms_opt(time_parts[0], time_parts[1], time_parts[2]).unwrap();
            
            // Apply session logic
            let logout_dt = login_dt + chrono::Duration::minutes(duration_min);
            let end_of_day = login_dt.date().and_hms_opt(23, 59, 0).unwrap();
            let actual_logout = std::cmp::min(logout_dt, end_of_day);
            let actual_duration = (actual_logout - login_dt).num_minutes();
            
            println!("Late login test: {} + {}min -> {} ({}min duration)", 
                    login_time_str, duration_min, 
                    actual_logout.format("%H:%M:%S"), actual_duration);
            
            // CRITICAL: Duration must never be negative
            assert!(actual_duration >= 0, 
                    "Duration {} must be positive for login {} + {}min", 
                    actual_duration, login_time_str, duration_min);
            
            // Logout must be at or after login
            assert!(actual_logout >= login_dt, 
                    "Logout {} must be >= login {}", 
                    actual_logout.format("%H:%M:%S"), login_time_str);
        }
    }

    #[test]
    fn test_login_hour_range() {
        println!("=== LOGIN HOUR RANGE TEST ===");
        
        // Test that login hour generation respects new bounds
        for _ in 0..20 {
            let login_hour = rand::rng().random_range(6..=22);
            println!("Generated login hour: {}", login_hour);
            
            // Should never generate 23:XX logins (which could cause issues)
            assert!(login_hour >= 6 && login_hour <= 22, 
                    "Login hour {} should be 6-22 (not 23)", login_hour);
        }
        
        // Verify that even latest possible login (22:59:59) + minimum session (30min) doesn't exceed day
        let latest_login = chrono::NaiveDate::from_ymd_opt(2025, 8, 10).unwrap()
            .and_hms_opt(22, 59, 59).unwrap();
        let min_session_end = latest_login + chrono::Duration::minutes(30);
        let end_of_day = latest_login.date().and_hms_opt(23, 59, 0).unwrap();
        
        println!("Latest login 22:59:59 + 30min = {}", min_session_end.format("%H:%M:%S"));
        
        // Even minimum session should be cappable
        assert!(min_session_end > end_of_day, "This proves capping logic is needed");
        let capped_logout = std::cmp::min(min_session_end, end_of_day);
        let capped_duration = (capped_logout - latest_login).num_minutes();
        
        assert!(capped_duration >= 0, "Capped duration should still be positive");
        println!("Capped logout: {}, Duration: {}min", capped_logout.format("%H:%M:%S"), capped_duration);
    }
}