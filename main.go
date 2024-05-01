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
	"regexp"
	"strings"
	"time"

	"literary-lions/internal/cookies"

	"database/sql"

	// underscore is used when no package's exported identifiers (functions, types, variables) are used in your code.
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var secret []byte

type User struct {
	Name     string
	Password string
}

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

	gob.Register(&User{})

	_, err := hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	mux.HandleFunc("/set", setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)

	log.Print("Listening...")
	err = http.ListenAndServe(":3000", mux)
	if err != nil {
		log.Fatal(err)
	}
}

type PageContent struct {
	Posts []Post
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

	//FIXME: Move to new function

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

	content := PageContent{Posts: Posts}

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

		stmtForCheck, err := db.Prepare("SELECT username, password FROM users WHERE username = ? OR email = ?;")
		if err != nil {
			log.Fatal(err)
		}
		defer stmtForCheck.Close()

		var username string
		var password []byte

		err = stmtForCheck.QueryRow(usernameOrEmail, usernameOrEmail).Scan(&username, &password)
		if err != nil {
			if err == sql.ErrNoRows {
				renderTemplate(w, "login", "User does not exist")
				return
			} else {
				log.Fatal(err)
			}
		}

		err = bcrypt.CompareHashAndPassword(password, []byte(passwordFromForm))
		// if error nil then correct password
		if err != nil {
			fmt.Println(err.Error())
			renderTemplate(w, "login", "Wrong password entered")
			return
		}

		renderTemplate(w, "login", "Login was successful")
		return

	} else {
		err := errors.New("incorrect HTTP request received")
		log.Fatal(err)
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

// FIXME: Could show all the errors at once with {{range}}
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
