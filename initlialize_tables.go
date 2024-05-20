package main

import (
	"database/sql"
	"log"
)

func initializeSQLiteTables(db *sql.DB) {
	var err error

	// Foreign keys needs to enabled in SQLite database
	var isForeignKeysEnabled int
	err = db.QueryRow("PRAGMA foreign_keys;").Scan(&isForeignKeysEnabled)
	if err != nil {
		log.Fatal(err)
	}

	if isForeignKeysEnabled != 1 {
		_, err = db.Exec("PRAGMA foreign_keys = ON;")
		if err != nil {
			log.Fatal(err)
		}
	}

	// Initializing table for users if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		date_created TIMESTAMP NOT NULL,
        password BLOB NOT NULL
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Initializing table for posts if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
		users_id INTEGER,
		title TEXT NOT NULL UNIQUE,
        content TEXT NOT NULL,
        category TEXT NOT NULL,
		date TIMESTAMP NOT NULL,
		FOREIGN KEY (users_id) REFERENCES users (id)
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Initializing table for comments if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        posts_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		date TIMESTAMP NOT NULL,
		users_id INTEGER NOT NULL,
		FOREIGN KEY (users_id) REFERENCES users (id),
		FOREIGN KEY (posts_id) REFERENCES posts (id)
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Initializing table for comments_likes if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS comments_likes (
		users_id INTEGER NOT NULL,
		comments_id INTEGER NOT NULL,
        posts_id INTEGER NOT NULL,
		is_dislike INTEGER NOT NULL,
		PRIMARY KEY (users_id, comments_id, posts_id)
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Initializing table for posts_likes if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS posts_likes (
		users_id INTEGER NOT NULL,
		posts_id INTEGER NOT NULL,
		is_dislike INTEGER NOT NULL,
		PRIMARY KEY (users_id, posts_id)
    );`)
	if err != nil {
		log.Fatal(err)
	}
}
