package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"literary-lions/internal/cookies"

	"database/sql"

	// underscore is used when no package's exported identifiers (functions, types, variables) are used in your code.
	_ "github.com/mattn/go-sqlite3"
)

var secret []byte

type User struct {
	Name     string
	Password string
}

var tmpl *template.Template

func init() {

	var err error
	tmpl, err = template.ParseFiles("static/index.html")
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}

	initializeSQLiteTables(db)

	defer db.Close()
}

func main() {

	for _, driver := range sql.Drivers() {
		fmt.Println(driver)
	}

	gob.Register(&User{})

	secret, err := hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(secret)

	mux := http.NewServeMux()
	mux.HandleFunc("/set", setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)
	mux.HandleFunc("/", indexHandler)

	log.Print("Listening...")
	err = http.ListenAndServe(":3000", mux)
	if err != nil {
		log.Fatal(err)
	}
}

func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	// Initialize a User struct containing the data that we want to store in the
	// cookie.
	user := User{Name: "Alice", Password: "BadPassword"}

	// Initialize a buffer to hold the gob-encoded data.
	var buf bytes.Buffer

	// Gob-encode the user data, storing the encoded output in the buffer.
	err := gob.NewEncoder(&buf).Encode(&user)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Call buf.String() to get the gob-encoded value as a string and set it as
	// the cookie value.
	cookie := http.Cookie{
		Name:     "exampleCookie",
		Value:    buf.String(),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Write an encrypted cookie containing the gob-encoded data as normal.
	err = cookies.WriteEncrypted(w, cookie, secret)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	// Read the gob-encoded value from the encrypted cookie, handling any errors
	// as necessary.
	gobEncodedValue, err := cookies.ReadEncrypted(r, "exampleCookie", secret)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "invalid cookie", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	// Create a new instance of a User type.
	var user User

	// Create an strings.Reader containing the gob-encoded value.
	reader := strings.NewReader(gobEncodedValue)

	// Decode it into the User type. Notice that we need to pass a *pointer* to
	// the Decode() target here?
	if err := gob.NewDecoder(reader).Decode(&user); err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Print the user information in the response.
	fmt.Fprintf(w, "Name: %q\n", user.Name)
	fmt.Fprintf(w, "Password: %q\n", user.Password)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {

	data := struct {
	}{}

	err := tmpl.Execute(w, data)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

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
        password TEXT NOT NULL,
		date_created TIMESTAMP NOT NULL
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Initializing table for posts if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
		users_id INTEGER,
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
        id INTEGER PRIMARY KEY,
		users_id INTEGER NOT NULL,
		comments_id INTEGER NOT NULL,
        posts_id INTEGER NOT NULL,
		is_dislike INTEGER NOT NULL
		FOREIGN KEY (users_id) REFERENCES users (id),
		FOREIGN KEY (posts_id) REFERENCES posts (id),
		FOREIGN KEY (comments_id) REFERENCES comments (id)
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Initializing table for posts_likes if it doesn't exist yet
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS posts_likes (
        id INTEGER PRIMARY KEY,
		users_id INTEGER NOT NULL,
		comments_id INTEGER NOT NULL,
		is_dislike INTEGER NOT NULL
		FOREIGN KEY (users_id) REFERENCES users (id),
		FOREIGN KEY (comments_id) REFERENCES comments (id)
    );`)
	if err != nil {
		log.Fatal(err)
	}
}
