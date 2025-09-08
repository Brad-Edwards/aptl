const sqlite3 = require('sqlite3').verbose();
const path = require('path');

/**
 * Connect to the SQLite database
 * @returns {Promise<sqlite3.Database>} Database connection
 */
function connectToDatabase() {
  return new Promise((resolve, reject) => {
    const dbPath = path.join(__dirname, '../data/gaming.db');
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        reject(new Error(`Failed to connect to database: ${err.message}`));
      } else {
        resolve(db);
      }
    });
  });
}

/**
 * Clear all data from the database
 * @param {sqlite3.Database} db - Database connection
 * @returns {Promise<void>}
 */
function clearDatabase(db) {
  return new Promise((resolve, reject) => {
    const tables = ['auth_events', 'transactions', 'items', 'users'];
    
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      tables.forEach(table => {
        db.run(`DELETE FROM ${table}`);
      });
      
      db.run('COMMIT', (err) => {
        if (err) {
          reject(new Error(`Failed to clear database: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  });
}

/**
 * Insert users into the database
 * @param {sqlite3.Database} db - Database connection
 * @param {Array} users - Array of user objects
 * @returns {Promise<void>}
 */
function insertUsers(db, users) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      INSERT INTO users (
        username, password_hash, email, created_at, last_login,
        character_level, total_playtime_hours, account_value,
        is_premium, last_ip, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      users.forEach(user => {
        stmt.run([
          user.username,
          user.password_hash,
          user.email,
          user.created_at,
          user.last_login,
          user.character_level,
          user.total_playtime_hours,
          user.account_value,
          user.is_premium ? 1 : 0,
          user.last_ip,
          user.user_agent
        ]);
      });
      
      db.run('COMMIT', (err) => {
        stmt.finalize();
        if (err) {
          reject(new Error(`Failed to insert users: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  });
}

/**
 * Insert items into the database
 * @param {sqlite3.Database} db - Database connection
 * @param {Array} items - Array of item objects
 * @returns {Promise<void>}
 */
function insertItems(db, items) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      INSERT INTO items (name, gold_value)
      VALUES (?, ?)
    `);

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      items.forEach(item => {
        stmt.run([item.name, item.value]);
      });
      
      db.run('COMMIT', (err) => {
        stmt.finalize();
        if (err) {
          reject(new Error(`Failed to insert items: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  });
}

/**
 * Insert transactions into the database
 * @param {sqlite3.Database} db - Database connection
 * @param {Array} transactions - Array of transaction objects
 * @returns {Promise<void>}
 */
function insertTransactions(db, transactions) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      INSERT INTO transactions (
        from_username, to_username, item_name, gold_value, timestamp
      ) VALUES (?, ?, ?, ?, ?)
    `);

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      transactions.forEach(transaction => {
        stmt.run([
          transaction.from_username,
          transaction.to_username,
          transaction.item_name,
          transaction.gold_value,
          transaction.timestamp
        ]);
      });
      
      db.run('COMMIT', (err) => {
        stmt.finalize();
        if (err) {
          reject(new Error(`Failed to insert transactions: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  });
}

/**
 * Insert authentication events into the database
 * @param {sqlite3.Database} db - Database connection
 * @param {Array} authEvents - Array of auth event objects
 * @returns {Promise<void>}
 */
function insertAuthEvents(db, authEvents) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      INSERT INTO auth_events (
        username, ip_address, user_agent, success, timestamp
      ) VALUES (?, ?, ?, ?, ?)
    `);

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      authEvents.forEach(event => {
        stmt.run([
          event.username,
          event.ip_address,
          event.user_agent,
          event.success ? 1 : 0,
          event.timestamp
        ]);
      });
      
      db.run('COMMIT', (err) => {
        stmt.finalize();
        if (err) {
          reject(new Error(`Failed to insert auth events: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  });
}

/**
 * Close database connection
 * @param {sqlite3.Database} db - Database connection
 * @returns {Promise<void>}
 */
function closeDatabase(db) {
  return new Promise((resolve, reject) => {
    db.close((err) => {
      if (err) {
        reject(new Error(`Failed to close database: ${err.message}`));
      } else {
        resolve();
      }
    });
  });
}

module.exports = {
  connectToDatabase,
  clearDatabase,
  insertUsers,
  insertItems,
  insertTransactions,
  insertAuthEvents,
  closeDatabase
};