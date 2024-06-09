package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"time"

	"database/sql"

	// underscore is used when no package's exported identifiers (functions, types, variables) are used in your code.
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Name     string
	Password string
	Bio      string
}

type Session struct {
	UserID   int
	Username string
}

type PageContent struct {
	Posts            []Post
	Categories       []string
	SelectedCategory string
	IsAuthenticated  bool
}

type Post struct {
	ID       int
	User_id  int
	Title    string
	Content  string
	Category string
	Date     time.Time
	Username string
	Likes    int
	Dislikes int
	Comments []Comment
}

type Comment struct {
	ID       int
	PostID   int
	Content  string
	Date     time.Time
	UserID   int
	Username string
	Likes    int
	Dislikes int
}

type ProfileData struct {
	Username     string
	Bio          string
	CreatedPosts []Post
	LikedPosts   []Post
}

var sessions map[string]Session

var tmpl *template.Template
var db *sql.DB

func init() {

	var err error
	funcmap := template.FuncMap{
		"formatDate": formatDate,
	}
	tmpl, err = template.New("all").Funcs(funcmap).ParseGlob("static/**/*.html")
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

	port := "5000"
	var err error

	mux := http.NewServeMux()
	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/profile", authenticate(profileHandler))
	mux.HandleFunc("/profile/", profileViewHandler)
	mux.HandleFunc("/post/", viewPostHandler)
	mux.HandleFunc("/create_post", authenticate(createPostHandler))
	mux.HandleFunc("/like_post", authenticate(likePostHandler))
	mux.HandleFunc("/comment", authenticate(submitCommentHandler))
	mux.HandleFunc("/like_comment", authenticate(likeCommentHandler))
	mux.HandleFunc("/updatebio", authenticate(updateBioHandler))
	mux.HandleFunc("/categories", categoriesHandler)

	http.Handle("/", mux)

	log.Printf("Listening on port %s", port)
	err = http.ListenAndServe(":"+port, nil)
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
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Set session data in request context
		next.ServeHTTP(w, r)
	}
}
func renderTemplate(w http.ResponseWriter, title string, data any, statusCode int) {
	w.WriteHeader(statusCode)
	err := tmpl.ExecuteTemplate(w, fmt.Sprintf("%s.html", title), data)
	if err != nil {
		serverError(w, err)
		return
	}
}

func checkForValidInput(w http.ResponseWriter, username, password, email string) map[string]string {
	errors := make(map[string]string)

	if len(password) < 8 {
		errors["password"] = "Password has to be at keast 8 characters"
	}
	if !isValidEmail(email) {
		errors["email"] = "Please enter a correct email"
	}
	if email == "" {
		errors["email"] = "Email field required"
	}
	if username == "" {
		errors["username"] = "Username field required"
	}
	if password == "" {
		errors["password"] = "Password field required"
	}

	stmtForCheck, err := db.Prepare("SELECT username FROM users WHERE username = ?;")
	if err != nil {
		serverError(w, err)
		return nil
	}
	defer stmtForCheck.Close()

	var userExists string
	var emailExists string
	err = stmtForCheck.QueryRow(username).Scan(&userExists)
	if err != nil && err != sql.ErrNoRows {
		serverError(w, err)
		return nil
	}
	err = stmtForCheck.QueryRow(password).Scan(&emailExists)
	if err != nil && err != sql.ErrNoRows {
		serverError(w, err)
		return nil
	}

	if userExists != "" {
		errors["username"] = "Username is already taken"
	}

	if emailExists != "" {
		errors["email"] = "Email is already taken"
	}

	return errors
}

func isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	regex := regexp.MustCompile(pattern)

	return regex.MatchString(email)
}

func formatDate(t time.Time) string {
	result := t.Format(time.DateTime)
	return result[:len(result)-3]
}
