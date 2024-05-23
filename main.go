package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"

	"database/sql"

	// underscore is used when no package's exported identifiers (functions, types, variables) are used in your code.
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Name     string
	Password string
}

type Session struct {
	UserID   int
	Username string
}

type PageContent struct {
	Posts           []Post
	IsAuthenticated bool
}

type Post struct {
	ID       int
	User_id  int
	Title    string
	Content  string
	Category string
	Date     string
	Username string
	Likes    int
	Dislikes int
}

var sessions map[string]Session

var tmpl *template.Template
var db *sql.DB

func init() {

	var err error
	tmpl, err = template.ParseGlob("static/**/*.html")
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
	mux.HandleFunc("/profile", authenticate(profileHandler))
	mux.HandleFunc("/create_post", authenticate(createPostHandler))
	mux.HandleFunc("/like_post", authenticate(likePostHandler))

	http.Handle("/", mux)

	log.Print("Listening...")
	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// middleware
func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		sessionID := cookie.Value
		_, ok := sessions[sessionID]
		if !ok {
			// FIXME: FOR DEVELOPMENT

			sessions[sessionID] = Session{UserID: 2}
			// Set the session ID in a cookie
			http.SetCookie(w, cookie)
			// http.Redirect(w, r, "/login", http.StatusSeeOther)
			// return
		}

		// Set session data in request context
		next.ServeHTTP(w, r)
	}
}

func renderTemplate(w http.ResponseWriter, title string, data any) {

	err := tmpl.ExecuteTemplate(w, fmt.Sprintf("%s.html", title), data)
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
