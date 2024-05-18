package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"database/sql"

	// underscore is used when no package's exported identifiers (functions, types, variables) are used in your code.
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string
	Password string
}

type Session struct {
	UserID   int
	Username string
}

var sessions map[string]Session

var tmpl *template.Template
var db *sql.DB

func init() {

	var err error
	tmpl, err = template.ParseFiles("static/index.html")
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}

	initializeSQLiteTables(db)

}

func main() {
	sessions = make(map[string]Session)

	gob.Register(&User{})

	var err error

	mux := http.NewServeMux()
	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/create_post", sessionMiddleware(createPostHandler))

	// Protected routes
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/protected", protectedHandler)

	// Wrap the protectedMux with session middleware
	// http.Handle("/protected", sessionMiddleware(protectedMux))

	// Use the standard mux for other routes
	http.Handle("/", mux)

	log.Print("Listening...")
	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data from request context
	session := r.Context().Value("session").(Session)

	// You can now use session data as needed
	username := session.Username
	userID := session.UserID

	// Example response
	fmt.Fprintf(w, "Protected route accessed by user: %s (ID: %d)", username, userID)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	searchInput := r.Form.Get("search")
	rows, err := db.Query("SELECT * FROM posts WHERE title LIKE '%' || ? || '%' OR content LIKE '%' || ? || '%';", searchInput, searchInput)

	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	Posts := []Post{}
	var user_id int
	var id int
	var date string
	for rows.Next() {
		tmp := Post{}
		err = rows.Scan(&id, &user_id, &tmp.Title, &tmp.Content, &tmp.Category, &date)
		if err != nil {
			log.Fatal(err)
		}

		//TODO: Reformat date

		db.QueryRow("SELECT username FROM users WHERE id = ?;", user_id).Scan(&tmp.Username)
		tmp.Date = date[:len(date)-10]
		Posts = append(Posts, tmp)

		// fmt.Printf("%d, %s, %s, %s, %s, %s\n", id, tmp.Username, tmp.Title, tmp.Content, tmp.Category, tmp.Date)
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	content := PageContent{Posts: Posts}

	err = tmpl.Execute(w, content)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

type PageContent struct {
	Posts         []Post
	Authenticated bool
}

type Post struct {
	User_id  int
	Title    string
	Content  string
	Category string
	Date     string
	Username string
}

func indexHandler(w http.ResponseWriter, r *http.Request) {

	//FIXME: Move to new function also for search

	// Check if the session cookie exists
	_, err := r.Cookie("session_id")
	isAuthenticated := err == nil // isAuthenticated is true if there is no error in retrieving the cookie

	// Pulling posts from DB
	rows, err := db.Query("SELECT * FROM posts;")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	Posts := []Post{}
	var user_id int
	var id int
	var date string
	for rows.Next() {
		tmp := Post{}
		err = rows.Scan(&id, &user_id, &tmp.Title, &tmp.Content, &tmp.Category, &date)
		if err != nil {
			log.Fatal(err)
		}

		//TODO: Reformat date

		db.QueryRow("SELECT username FROM users WHERE id = ?;", user_id).Scan(&tmp.Username)
		tmp.Date = date[:len(date)-10]
		Posts = append(Posts, tmp)

		// fmt.Printf("%d, %s, %s, %s, %s, %s\n", id, tmp.Username, tmp.Title, tmp.Content, tmp.Category, tmp.Date)
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	// Pass authentication status along with posts when rendering the template
	content := PageContent{
		Posts:         Posts,
		Authenticated: isAuthenticated,
	}

	err = tmpl.Execute(w, content)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
func registerHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		renderTemplate(w, "register", "")

	} else if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse register form", http.StatusInternalServerError)
			return
		}

		email := r.Form.Get("email")
		username := r.Form.Get("username")
		password := r.Form.Get("password")

		err = checkForValidInput(w, username, password, email)
		if err != nil {
			return
		}

		stmtForCheck, err := db.Prepare("SELECT username FROM users WHERE username = ?;")
		if err != nil {
			log.Fatal(err)
		}
		defer stmtForCheck.Close()

		var userExists string
		var emailExists string
		err = stmtForCheck.QueryRow(username).Scan(&userExists)
		if err != nil && err != sql.ErrNoRows {
			log.Fatal(err)
		}
		err = stmtForCheck.QueryRow(password).Scan(&emailExists)
		if err != nil && err != sql.ErrNoRows {
			log.Fatal(err)
		}

		// TODO: Have to differentiate errorMessages and usual Messages

		if userExists != "" || emailExists != "" {
			renderTemplate(w, "register", "Username or email is already taken")
			return
		}

		// Password encrypted for security
		blob, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		stmtForAddUser, err := db.Prepare("INSERT INTO users (username, email, date_created, password) VALUES (?,?,?,?);")
		if err != nil {
			log.Fatal(err)
		}

		defer stmtForAddUser.Close()
		timestamp := time.Now().Format(time.DateTime)
		_, err = stmtForAddUser.Exec(username, email, timestamp, blob)
		if err != nil {
			log.Fatal(err)
		}

		renderTemplate(w, "login", fmt.Sprintf("New user %s created", strings.ToUpper(username)))
		return

	} else {
		err := errors.New("incorrect HTTP request received")
		log.Fatal(err)
	}
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract post data from the form
	title := r.FormValue("title")
	content := r.FormValue("content")
	category := r.FormValue("category")

	// Validate post data
	if title == "" || content == "" || category == "" {
		http.Error(w, "Title, content, and category are required fields", http.StatusBadRequest)
		return
	}

	// Let's assume the user is already authenticated and we have their user ID in the session
	session := r.Context().Value("session").(Session)
	userID := session.UserID

	// Insert the post into the database
	stmt, err := db.Prepare("INSERT INTO posts (users_id, title, content, category, date) VALUES (?, ?, ?, ?, ?);")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error preparing SQL statement:", err)
		return
	}
	defer stmt.Close()

	timestamp := time.Now().Format(time.RFC3339)
	_, err = stmt.Exec(userID, title, content, category, timestamp)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error executing SQL statement:", err)
		return
	}

	// Redirect the user to the home page or display a success message
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "login", "")
	} else if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse login form", http.StatusInternalServerError)
			return
		}
		usernameOrEmail := r.Form.Get("username")
		passwordFromForm := r.Form.Get("password")

		if usernameOrEmail == "" && passwordFromForm == "" {
			renderTemplate(w, "login", "You have to enter a username and password")
			return
		}

		if usernameOrEmail == "" {
			renderTemplate(w, "login", "Username field was empty")
			return
		}
		if passwordFromForm == "" {
			renderTemplate(w, "login", "Password field was empty")
			return
		}

		stmtForCheck, err := db.Prepare("SELECT id, username, password FROM users WHERE username = ? OR email = ?;")
		if err != nil {
			log.Fatal(err)
		}
		defer stmtForCheck.Close()

		var userID int
		var username string
		var password []byte

		err = stmtForCheck.QueryRow(usernameOrEmail, usernameOrEmail).Scan(&userID, &username, &password)
		if err != nil {
			if err == sql.ErrNoRows {
				renderTemplate(w, "login", "User does not exist")
				return
			} else {
				log.Fatal(err)
			}
		}

		err = bcrypt.CompareHashAndPassword(password, []byte(passwordFromForm))
		if err != nil {
			renderTemplate(w, "login", "Wrong password entered")
			return
		}

		// Create a session
		sessionID := generateSessionID()
		sessions[sessionID] = Session{UserID: userID, Username: username}

		// Set the session ID in a cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
		})

		renderTemplate(w, "login", "Login was successful")
		return
	} else {
		err := errors.New("incorrect HTTP request received")
		log.Fatal(err)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Delete the session cookie by setting an expired cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Set to true if using HTTPS
		MaxAge:   -1,
	})

	// Redirect the user to the login page or any other appropriate page after logout
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func sessionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		sessionID := cookie.Value
		session, ok := sessions[sessionID]
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Set session data in request context
		ctx := context.WithValue(r.Context(), "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

type Message struct {
	Message string
}

func renderTemplate(w http.ResponseWriter, title, message string) {

	data := Message{
		Message: message,
	}

	tmpl := template.Must(template.ParseFiles(fmt.Sprintf("static/%s.html", title)))
	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func checkForValidInput(w http.ResponseWriter, username, password, email string) error {
	if len(password) < 8 {
		renderTemplate(w, "register", "Password has to be at least 8 characters")
		return errors.New("")
	}

	if !isValidEmail(email) {
		renderTemplate(w, "register", "Please enter a correct email")
		return errors.New("")
	}

	if email == "" || username == "" || password == "" {
		renderTemplate(w, "register", "Please fill in all the fields to register successfully")
		return errors.New("")
	}
	return nil
}

func isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	regex := regexp.MustCompile(pattern)

	return regex.MatchString(email)
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
