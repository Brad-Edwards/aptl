use sqlx::SqlitePool;
use crate::Result;
use rand::Rng;
use std::collections::HashMap;


pub struct PlayerMovementGenerator {
    pool: SqlitePool,
}

#[derive(Debug)]
struct LocationBudget {
    total_minutes: i64,
    used_minutes: i64,
}

impl LocationBudget {
    fn remaining_minutes(&self) -> i64 {
        self.total_minutes - self.used_minutes
    }
    
    fn has_time_remaining(&self) -> bool {
        self.remaining_minutes() > 5 // Need at least 5 minutes to make a visit worthwhile
    }
}

impl PlayerMovementGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Initialize total time budgets for each location for the entire session
    fn initialize_session_budgets(session_duration_minutes: i64) -> HashMap<i64, LocationBudget> {
        let mut budgets = HashMap::new();
        
        // Game: gets 80% of session time when visited (location_id = 2)
        let game_time = (session_duration_minutes as f64 * 0.8) as i64;
        budgets.insert(2, LocationBudget { total_minutes: game_time, used_minutes: 0 });
        
        // Marketplace: gets 15% of session time when visited (location_id = 4)
        let marketplace_time = (session_duration_minutes as f64 * 0.15) as i64;
        budgets.insert(4, LocationBudget { total_minutes: marketplace_time, used_minutes: 0 });
        
        // Chat: gets 10% of session time when visited (location_id = 3)
        let chat_time = (session_duration_minutes as f64 * 0.10) as i64;
        budgets.insert(3, LocationBudget { total_minutes: chat_time, used_minutes: 0 });
        
        // Settings: gets 5% of session time when visited (location_id = 5)
        let settings_time = (session_duration_minutes as f64 * 0.05) as i64;
        budgets.insert(5, LocationBudget { total_minutes: settings_time, used_minutes: 0 });
        
        budgets
    }

    // Roll for next location selection with weighted probabilities
    fn roll_next_location() -> i64 {
        let rand = rand::random::<f32>();
        if rand < 0.8 { 2 }        // Game: 80% chance (location_id = 2)
        else if rand < 0.95 { 4 }  // Marketplace: 15% chance (location_id = 4)
        else if rand < 0.98 { 3 }  // Chat: 3% chance (location_id = 3)
        else { 5 }                 // Settings: 2% chance (location_id = 5)
    }

    // Calculate time to spend on this visit (30-40% of location's total budget, or remaining budget)
    fn calculate_visit_time(location_id: i64, budget: &LocationBudget, session_duration: i64) -> i64 {
        let visit_percentage = match location_id {
            2 => rand::rng().random_range(30..=40) as f64 / 100.0, // Game: 30-40%
            4 => rand::rng().random_range(3..=8) as f64 / 100.0,   // Marketplace: 3-8%  
            3 => rand::rng().random_range(2..=5) as f64 / 100.0,   // Chat: 2-5%
            5 => rand::rng().random_range(1..=3) as f64 / 100.0,   // Settings: 1-3%
            _ => 0.02,
        };
        
        let ideal_time = (session_duration as f64 * visit_percentage) as i64;
        std::cmp::min(ideal_time, budget.remaining_minutes())
    }

    // Calculate Landing transition time (brief navigation)
    fn landing_time(session_duration: i64) -> i64 {
        let percentage = rand::rng().random_range(1..=2) as f64 / 100.0; // 1-2%
        std::cmp::max(1, (session_duration as f64 * percentage) as i64)
    }

    fn collect_session_movements(&self, session_id: i64, user_id: i64, login_time: &str, logout_time: &str, movements: &mut Vec<(i64, i64, i64, String)>) -> Result<()> {
        if let (Ok(login_dt), Ok(logout_dt)) = (
            chrono::NaiveDateTime::parse_from_str(login_time, "%Y-%m-%d %H:%M:%S"),
            chrono::NaiveDateTime::parse_from_str(logout_time, "%Y-%m-%d %H:%M:%S")
        ) {
            let session_duration = (logout_dt - login_dt).num_minutes();
            
            // Always start at Landing (location_id = 1)
            let mut current_time = login_dt;
            movements.push((user_id, session_id, 1, current_time.format("%Y-%m-%d %H:%M:%S").to_string()));
            
            // Initialize location budgets for the entire session
            let mut budgets = Self::initialize_session_budgets(session_duration);
            
            // Debug output for session planning
            if session_duration > 60 {
                println!("Session {}: {}min duration, budgets: {:?}", session_id, session_duration, budgets);
            }
            
            let mut location_visits: HashMap<i64, i64> = HashMap::new();
            
            // Generate movement sequence with rolling location selection
            while current_time < logout_dt - chrono::Duration::minutes(5) {
                
                // Spend time at Landing (1-2% of session)
                let landing_duration = Self::landing_time(session_duration);
                current_time = current_time + chrono::Duration::minutes(landing_duration);
                
                // Check if we have time for another destination
                if current_time >= logout_dt - chrono::Duration::minutes(5) {
                    break; // Time to logout from Landing
                }
                
                // Roll for next location selection
                let selected_location = Self::roll_next_location();
                
                // Check if this location has remaining budget
                if let Some(budget) = budgets.get(&selected_location) {
                    if !budget.has_time_remaining() {
                        // Location budget exhausted, try again (or break if all exhausted)
                        continue;
                    }
                    
                    // Calculate visit time for this location
                    let visit_time = Self::calculate_visit_time(selected_location, budget, session_duration);
                    
                    if visit_time < 5 {
                        continue; // Not worth a visit
                    }
                    
                    // Move to selected location
                    movements.push((user_id, session_id, selected_location, current_time.format("%Y-%m-%d %H:%M:%S").to_string()));
                    
                    // Track time spent at location for verification
                    *location_visits.entry(selected_location).or_insert(0) += visit_time;
                    
                    // Update budget usage
                    if let Some(budget) = budgets.get_mut(&selected_location) {
                        budget.used_minutes += visit_time;
                    }
                    
                    // Stay at location for calculated time
                    current_time = current_time + chrono::Duration::minutes(visit_time);
                    
                    // Check if location budget is exhausted
                    if let Some(budget) = budgets.get(&selected_location) {
                        if !budget.has_time_remaining() {
                            // Budget exhausted - user might logout from here
                            if rand::random::<f32>() < 0.3 {
                                if session_duration > 60 {
                                    println!("Session {}: User logout from location {} after exhausting budget", session_id, selected_location);
                                }
                                break; // Logout from this location
                            }
                        }
                    }
                    
                    // Return to Landing for next selection
                    if current_time < logout_dt - chrono::Duration::minutes(5) {
                        movements.push((user_id, session_id, 1, current_time.format("%Y-%m-%d %H:%M:%S").to_string()));
                    }
                }
            }
            
            // Debug output for verification
            if session_duration > 60 {
                println!("Session {}: Final time usage: {:?}", session_id, location_visits);
                let total_accounted = location_visits.values().sum::<i64>();
                println!("Session {}: {}min total, {}min accounted, {} movements", 
                        session_id, session_duration, total_accounted, movements.len());
            }
        }
        Ok(())
    }

    pub async fn generate(&self) -> Result<()> {
        // Get successful sessions from last 30 days only
        let sessions: Vec<(i64, i64, String, String, String)> = sqlx::query_as(
            "SELECT id, user_id, username, login_time, logout_time FROM sessions 
             WHERE success = 1 AND logout_time IS NOT NULL AND login_time >= '2025-08-09'"
        )
        .fetch_all(&self.pool)
        .await?;

        if sessions.is_empty() {
            println!("Generated 0 player movements (no sessions in last 30 days)");
            return Ok(());
        }

        // Group sessions by user_id for batching
        let mut user_sessions: std::collections::HashMap<i64, Vec<_>> = std::collections::HashMap::new();
        for session in sessions {
            user_sessions.entry(session.1).or_insert_with(Vec::new).push(session);
        }

        let mut total_movements = 0;
        
        for (_user_id, user_session_list) in user_sessions {
            let mut movements_batch = Vec::new();
            
            for (session_id, user_id, _username, login_time, logout_time) in user_session_list {
                self.collect_session_movements(session_id, user_id, &login_time, &logout_time, &mut movements_batch)?;
            }
            
            // Bulk insert movements for this user
            for (user_id, session_id, location_id, timestamp) in &movements_batch {
                sqlx::query("INSERT INTO player_movement (user_id, session_id, location_id, timestamp) VALUES (?, ?, ?, ?)")
                    .bind(user_id)
                    .bind(session_id)
                    .bind(location_id)
                    .bind(timestamp)
                    .execute(&self.pool)
                    .await?;
            }
            total_movements += movements_batch.len();
        }

        println!("Generated {} player movements", total_movements);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_budget_logic() {
        let budget = LocationBudget {
            total_minutes: 60,
            used_minutes: 20,
        };
        
        assert_eq!(budget.remaining_minutes(), 40);
        assert!(budget.has_time_remaining());
        
        let exhausted_budget = LocationBudget {
            total_minutes: 10,
            used_minutes: 8,
        };
        
        assert!(!exhausted_budget.has_time_remaining()); // Less than 5 minutes
    }

    #[test] 
    fn test_time_allocation_logic() {
        // Test budget calculation logic without database
        
        // Mock a generator instance (we'll test the logic without the pool)
        let budgets_180 = {
            let mut budgets = HashMap::new();
            let max_time = (180.0 * 0.4) as i64; // 72 minutes max per location
            
            // Simulate Game: 60% likelihood gets allocated
            let game_time = std::cmp::min(max_time, (180.0 * 0.6) as i64); // 108 -> capped at 72
            budgets.insert(3, LocationBudget { total_minutes: game_time, used_minutes: 0 });
            
            budgets
        };
        
        // Game should get the max allocation (72 minutes) due to 40% cap
        assert_eq!(budgets_180.get(&3).unwrap().total_minutes, 72);
        
        // Test shorter session
        let budgets_30 = {
            let mut budgets = HashMap::new();
            let max_time = (30.0 * 0.4) as i64; // 12 minutes max per location
            
            let game_time = std::cmp::min(max_time, (30.0 * 0.6) as i64); // 18 -> capped at 12
            budgets.insert(3, LocationBudget { total_minutes: game_time, used_minutes: 0 });
            
            budgets
        };
        
        // Shorter session should respect the 40% cap
        assert_eq!(budgets_30.get(&3).unwrap().total_minutes, 12);
    }

    #[test]
    fn test_destination_choice_logic() {
        let mut budgets = HashMap::new();
        budgets.insert(3, LocationBudget { total_minutes: 30, used_minutes: 0 });
        budgets.insert(4, LocationBudget { total_minutes: 10, used_minutes: 8 }); // 2 minutes left
        
        let available: Vec<i64> = budgets.iter()
            .filter(|(_, budget)| budget.has_time_remaining())
            .map(|(&id, _)| id)
            .collect();
            
        // Should only include location 3 (has >5 minutes remaining)
        assert_eq!(available.len(), 1);
        assert_eq!(available[0], 3);
        
        // Exhaust all budgets
        budgets.get_mut(&3).unwrap().used_minutes = 28; // Only 2 minutes left
        
        let no_available: Vec<i64> = budgets.iter()
            .filter(|(_, budget)| budget.has_time_remaining())
            .map(|(&id, _)| id)
            .collect();
            
        assert_eq!(no_available.len(), 0);
    }

    #[test]
    fn test_session_movement_generation() {
        // Mock generator without database
        let generator = PlayerMovementGenerator {
            pool: unsafe { std::mem::zeroed() } // Hack for testing - won't use pool
        };
        
        let mut movements = Vec::new();
        
        // Test a 120-minute session
        let result = generator.collect_session_movements(
            1, // session_id
            1, // user_id
            "2025-08-10 10:00:00", // login
            "2025-08-10 12:00:00", // logout (120 minutes)
            &mut movements
        );
        
        assert!(result.is_ok());
        assert!(!movements.is_empty());
        
        // First movement should always be Landing
        assert_eq!(movements[0].2, 1); // location_id = 1 (Landing)
        assert_eq!(movements[0].3, "2025-08-10 10:00:00"); // login time
        
        // Verify Landing-hub pattern: every odd index should be Landing return
        let mut has_non_landing = false;
        for (i, movement) in movements.iter().enumerate() {
            if i > 0 && movement.2 != 1 {
                has_non_landing = true;
                // Previous movement should have been Landing (hub pattern)
                assert_eq!(movements[i-1].2, 1, "Movement to location {} not preceded by Landing", movement.2);
            }
        }
        
        assert!(has_non_landing, "Should have visited at least one non-Landing location");
    }

    #[test]  
    fn test_short_session_pattern() {
        let generator = PlayerMovementGenerator {
            pool: unsafe { std::mem::zeroed() }
        };
        
        let mut movements = Vec::new();
        
        // Test a 30-minute session
        let _ = generator.collect_session_movements(
            2, 2,
            "2025-08-10 14:00:00",
            "2025-08-10 14:30:00", 
            &mut movements
        );
        
        // Short sessions should have fewer movements
        assert!(movements.len() <= 6); // Landing + destination + maybe one more hop
        
        // Still should start at Landing
        assert_eq!(movements[0].2, 1);
    }

    #[test]
    fn test_movement_timing() {
        let generator = PlayerMovementGenerator {
            pool: unsafe { std::mem::zeroed() }
        };
        
        let mut movements = Vec::new();
        
        let _ = generator.collect_session_movements(
            3, 3,
            "2025-08-10 09:00:00",
            "2025-08-10 11:00:00",
            &mut movements
        );
        
        // Verify timestamps are in chronological order
        for i in 1..movements.len() {
            let prev_time = chrono::NaiveDateTime::parse_from_str(&movements[i-1].3, "%Y-%m-%d %H:%M:%S").unwrap();
            let curr_time = chrono::NaiveDateTime::parse_from_str(&movements[i].3, "%Y-%m-%d %H:%M:%S").unwrap();
            
            assert!(curr_time > prev_time, "Movements should be chronologically ordered");
        }
        
        // Last movement should be before logout time
        if let Some(last_movement) = movements.last() {
            let last_time = chrono::NaiveDateTime::parse_from_str(&last_movement.3, "%Y-%m-%d %H:%M:%S").unwrap();
            let logout_time = chrono::NaiveDateTime::parse_from_str("2025-08-10 11:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
            
            assert!(last_time <= logout_time, "Movements should not exceed session logout time");
        }
    }

    #[test]
    fn test_budget_utilization_statistical() {
        // Test multiple sessions to check statistical patterns
        let mut total_game_time = 0;
        let mut total_marketplace_time = 0;
        let mut session_count = 0;
        
        for session_duration in [60, 120, 180, 240, 300] {
            for _ in 0..10 { // Test 10 sessions of each duration
                let budgets = PlayerMovementGenerator::initialize_session_budgets(session_duration);
                
                if let Some(game_budget) = budgets.get(&3) {
                    total_game_time += game_budget.total_minutes;
                }
                if let Some(marketplace_budget) = budgets.get(&4) {
                    total_marketplace_time += marketplace_budget.total_minutes;
                }
                session_count += 1;
            }
        }
        
        // Game should get significantly more time than Marketplace (60% vs 20% likelihood)
        println!("Statistical test: Game={}min, Marketplace={}min over {} sessions", 
                total_game_time, total_marketplace_time, session_count);
        
        if total_game_time > 0 && total_marketplace_time > 0 {
            let ratio = total_game_time as f64 / total_marketplace_time as f64;
            assert!(ratio > 2.0, "Game should get significantly more time than Marketplace");
        }
    }

    #[test]
    fn test_budget_initialization() {
        let budgets = PlayerMovementGenerator::initialize_session_budgets(180);
        
        println!("Budget allocation for 180min session:");
        for (location_id, budget) in &budgets {
            println!("  Location {}: {} minutes", location_id, budget.total_minutes);
        }
        
        // Game should get 80% = 144 minutes
        assert_eq!(budgets.get(&3).unwrap().total_minutes, 144);
        // Marketplace should get 15% = 27 minutes  
        assert_eq!(budgets.get(&4).unwrap().total_minutes, 27);
        // Chat should get 10% = 18 minutes
        assert_eq!(budgets.get(&5).unwrap().total_minutes, 18);
        // Settings should get 5% = 9 minutes
        assert_eq!(budgets.get(&2).unwrap().total_minutes, 9);
    }

    #[test]
    fn test_rolling_location_selection_distribution() {
        // Test location selection probabilities over many rolls
        let mut location_counts = HashMap::new();
        
        for _ in 0..1000 {
            let location = PlayerMovementGenerator::roll_next_location();
            *location_counts.entry(location).or_insert(0) += 1;
        }
        
        println!("Location selection distribution over 1000 rolls:");
        for (location_id, count) in &location_counts {
            let percentage = *count as f64 / 1000.0 * 100.0;
            println!("  Location {}: {} times ({}%)", location_id, count, percentage);
        }
        
        // Game (location 2) should be ~80% of selections
        let game_percentage = *location_counts.get(&2).unwrap_or(&0) as f64 / 1000.0;
        assert!(game_percentage > 0.75 && game_percentage < 0.85, "Game should be selected ~80% of the time");
    }

    #[test]
    fn test_visit_time_calculations() {
        let game_budget = LocationBudget { total_minutes: 144, used_minutes: 0 };
        let marketplace_budget = LocationBudget { total_minutes: 27, used_minutes: 0 };
        
        // Test Game visit time (30-40% of 180min session = 54-72 minutes)
        let game_visit_time = PlayerMovementGenerator::calculate_visit_time(2, &game_budget, 180);
        println!("Game visit time: {} minutes (should be 54-72)", game_visit_time);
        assert!(game_visit_time >= 54 && game_visit_time <= 72);
        
        // Test Marketplace visit time (3-8% of 180min session = 5-14 minutes)  
        let marketplace_visit_time = PlayerMovementGenerator::calculate_visit_time(4, &marketplace_budget, 180);
        println!("Marketplace visit time: {} minutes (should be 5-14)", marketplace_visit_time);
        assert!(marketplace_visit_time >= 5 && marketplace_visit_time <= 14);
    }

    #[tokio::test]
    async fn test_session_generation_sanity_check() {
        println!("\n=== SESSION GENERATION SANITY CHECK ===");
        
        // Create a mock generator for testing movement logic
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        let generator = PlayerMovementGenerator::new(pool);
        
        // Test several different session lengths
        for (session_name, login_time, logout_time) in [
            ("Short 1hr session", "2025-08-10 10:00:00", "2025-08-10 11:00:00"),
            ("Medium 3hr session", "2025-08-10 14:00:00", "2025-08-10 17:00:00"), 
            ("Long 5hr session", "2025-08-10 09:00:00", "2025-08-10 14:00:00"),
        ] {
            println!("\n--- {} ---", session_name);
            
            let mut movements: Vec<(i64, i64, i64, String)> = Vec::new();
            
            let result = generator.collect_session_movements(
                1, 1, login_time, logout_time, &mut movements
            );
            
            assert!(result.is_ok());
            
            // Print detailed movement breakdown
            println!("Generated {} movements:", movements.len());
            for (i, (user_id, session_id, location_id, timestamp)) in movements.iter().enumerate() {
                let location_name = match location_id {
                    1 => "Landing",
                    2 => "Game", 
                    3 => "Chat",
                    4 => "Marketplace",
                    5 => "Settings",
                    _ => "Unknown"
                };
                println!("  {}: {} at {}", i+1, location_name, timestamp);
            }
            
            // Verify basic patterns
            assert_eq!(movements[0].2, 1, "Should start at Landing");
            
            // Count location visits
            let mut location_counts = HashMap::new();
            for movement in &movements {
                *location_counts.entry(movement.2).or_insert(0) += 1;
            }
            
            println!("Location visit counts:");
            for (location_id, count) in &location_counts {
                let location_name = match location_id {
                    1 => "Landing", 2 => "Game", 3 => "Chat", 
                    4 => "Marketplace", 5 => "Settings", _ => "Unknown"
                };
                println!("  {}: {} visits", location_name, count);
            }
        }
    }
}