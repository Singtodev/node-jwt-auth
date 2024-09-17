import sqlite3 from "sqlite3";
sqlite3.verbose();

const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.error("Error opening database", err.message);
  } else {
    db.serialize(() => {
      // Create users table
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        password TEXT NOT NULL,
        role INT DEFAULT 1
      )`);

      // Create refresh_tokens table
      db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        status TEXT DEFAULT 'active', -- 'active', 'revoked'
        FOREIGN KEY (user_id) REFERENCES users(id)
      );`);
    });

    console.log("Connected to the SQLite database.");
  }
});

export default db;
