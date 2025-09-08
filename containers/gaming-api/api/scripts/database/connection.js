const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
  constructor() {
    this.db = null;
    this.dbPath = path.join(__dirname, '../../database.sqlite');
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          reject(new Error(`Failed to connect to database: ${err.message}`));
        } else {
          console.log('Connected to SQLite database');
          resolve();
        }
      });
    });
  }

  async disconnect() {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            reject(new Error(`Failed to disconnect from database: ${err.message}`));
          } else {
            console.log('Disconnected from SQLite database');
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }

  async run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) {
          reject(new Error(`Failed to run query: ${err.message}`));
        } else {
          resolve({ lastID: this.lastID, changes: this.changes });
        }
      });
    });
  }

  async get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) {
          reject(new Error(`Failed to get row: ${err.message}`));
        } else {
          resolve(row);
        }
      });
    });
  }

  async all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(new Error(`Failed to get rows: ${err.message}`));
        } else {
          resolve(rows);
        }
      });
    });
  }

  async beginTransaction() {
    await this.run('BEGIN TRANSACTION');
  }

  async commit() {
    await this.run('COMMIT');
  }

  async rollback() {
    await this.run('ROLLBACK');
  }

  async bulkInsert(table, columns, data) {
    if (!data || data.length === 0) {
      throw new Error('No data provided for bulk insert');
    }

    const placeholders = columns.map(() => '?').join(', ');
    const sql = `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`;
    
    await this.beginTransaction();
    
    try {
      const stmt = this.db.prepare(sql);
      
      for (const row of data) {
        await new Promise((resolve, reject) => {
          stmt.run(row, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      }
      
      await new Promise((resolve, reject) => {
        stmt.finalize((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      await this.commit();
      return data.length;
      
    } catch (error) {
      await this.rollback();
      throw new Error(`Bulk insert failed: ${error.message}`);
    }
  }

  async tableExists(tableName) {
    const result = await this.get(
      "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
      [tableName]
    );
    return !!result;
  }

  async getTableSchema(tableName) {
    return await this.all(`PRAGMA table_info(${tableName})`);
  }

  async getRowCount(tableName) {
    const result = await this.get(`SELECT COUNT(*) as count FROM ${tableName}`);
    return result.count;
  }
}

module.exports = Database;