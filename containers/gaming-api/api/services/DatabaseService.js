const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

class DatabaseService {
  constructor(logger, dataDir = path.join(__dirname, '../data')) {
    this.logger = logger;
    this.dataDir = dataDir;
    this.dbPath = path.join(this.dataDir, 'gaming.db');
    this.db = null;
  }

  async connect() {
    this._ensureDataDir();
    
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          this.logger.error('Database connection failed', { error: err.message });
          reject(err);
        } else {
          this.logger.info('Connected to SQLite database');
          resolve();
        }
      });
    });
  }

  async initializeSchema() {
    if (!this.db) throw new Error('Database not connected');
    
    const schema = fs.readFileSync(path.join(__dirname, '../sql/schema.sql'), 'utf8');
    
    return new Promise((resolve, reject) => {
      this.db.exec(schema, (err) => {
        if (err) {
          this.logger.error('Failed to initialize database schema', { error: err.message });
          reject(err);
        } else {
          this.logger.info('Database schema initialized successfully');
          resolve();
        }
      });
    });
  }

  // Generic query methods
  async get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  async run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID, changes: this.changes });
      });
    });
  }

  async close() {
    if (!this.db) return;
    
    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) {
          this.logger.error('Error closing database', { error: err.message });
          reject(err);
        } else {
          this.logger.info('Database connection closed');
          resolve();
        }
      });
    });
  }

  _ensureDataDir() {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
  }
}

module.exports = DatabaseService;