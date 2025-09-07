const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'data/gaming.db');
const db = new sqlite3.Database(dbPath);

async function createTestUser() {
  const hashedPassword = await bcrypt.hash('password123', 10);
  
  db.run(
    'INSERT INTO users (username, password_hash, email, account_value, is_premium) VALUES (?, ?, ?, ?, ?)',
    ['testuser', hashedPassword, 'test@example.com', 1500, 1],
    function(err) {
      if (err) {
        console.error('Error creating test user:', err.message);
      } else {
        console.log('Test user created successfully with ID:', this.lastID);
      }
      db.close();
    }
  );
}

createTestUser();