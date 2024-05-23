package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func profileHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session_id")
	if err != nil {
		log.Fatal(err)
	}

	session, ok := sessions[cookie.Value]
	if !ok {
		log.Fatal(err)
	}

	userID := session.UserID

	stmtForCheck, err := db.Prepare("SELECT username FROM users WHERE id = ?;")
	if err != nil {
		log.Fatal(err)
	}
	defer stmtForCheck.Close()

	var user string
	err = stmtForCheck.QueryRow(userID).Scan(&user)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	data := struct {
		Username string
	}{
		Username: user,
	}

	err = tmpl.ExecuteTemplate(w, "profile.html", data)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {

	// user authentication needs to be checked for the right index page
	_, err := r.Cookie("session_id")
	isAuthenticated := err == nil

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

	if isAuthenticated {
		err = tmpl.ExecuteTemplate(w, "protected.html", content)
	} else {
		err = tmpl.ExecuteTemplate(w, "index.html", content)
	}

	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is authenticated
	isAuthenticated := false
	if _, err := r.Cookie("session_id"); err == nil {
		isAuthenticated = true
	}

	// Query to get posts with like and dislike counts
	rows, err := db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date,
                           u.username,
                           COALESCE(SUM(CASE WHEN pl.is_dislike = 0 THEN 1 ELSE 0 END), 0) as likes,
                           COALESCE(SUM(CASE WHEN pl.is_dislike = 1 THEN 1 ELSE 0 END), 0) as dislikes
                           FROM posts p
                           JOIN users u ON p.users_id = u.id
                           LEFT JOIN posts_likes pl ON p.id = pl.posts_id
                           GROUP BY p.id, p.users_id, p.title, p.content, p.category, p.date, u.username;`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	Posts := []Post{}
	for rows.Next() {
		tmp := Post{}
		err = rows.Scan(&tmp.ID, &tmp.User_id, &tmp.Title, &tmp.Content, &tmp.Category, &tmp.Date, &tmp.Username, &tmp.Likes, &tmp.Dislikes)
		if err != nil {
			log.Fatal(err)
		}
		Posts = append(Posts, tmp)
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	// Pass authentication status along with posts when rendering the template
	content := PageContent{
		Posts:           Posts,
		IsAuthenticated: isAuthenticated,
	}

	if isAuthenticated {
		err = tmpl.ExecuteTemplate(w, "protected.html", content)
	} else {
		err = tmpl.ExecuteTemplate(w, "index.html", content)
	}

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
	if r.Method == http.MethodGet {
		err := tmpl.ExecuteTemplate(w, "create_post.html", "")
		if err != nil {
			log.Println(err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	} else if r.Method == http.MethodPost {

		// Extract post data from the form
		title := r.FormValue("title")
		content := r.FormValue("content")
		category := r.FormValue("category")

		// Validate post data
		if title == "" || content == "" || category == "" {
			renderTemplate(w, "create_post",
				"Title, content, and category are required fields")
			return
		}

		// Let's assume the user is already authenticated and we have their user ID in the session
		cookie, err := r.Cookie("session_id")
		if err != nil {
			log.Fatal(err)
		}

		session, ok := sessions[cookie.Value]
		if !ok {
			log.Fatal(err)
		}

		userID := session.UserID
		// Insert the post into the database
		stmt, err := db.Prepare("INSERT INTO posts (users_id, title, content, category, date) VALUES (?, ?, ?, ?, ?);")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error preparing SQL statement:", err)
			return
		}

		defer stmt.Close()

		timestamp := time.Now().Format(time.DateTime)
		_, err = stmt.Exec(userID, title, content, category, timestamp)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error executing SQL statement:", err)
			return
		}

		// Redirect the user to the home page or display a success message
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
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
		Name:   "session_id",
		MaxAge: -1,
	})

	// Redirect the user to the login page or any other appropriate page after logout
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func likePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session, ok := sessions[cookie.Value]
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userID := session.UserID
		postID := r.FormValue("post_id")
		action := r.FormValue("action")

		var isDislike int
		if action == "like" {
			isDislike = 0
		} else if action == "dislike" {
			isDislike = 1
		} else {
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}

		// Insert or update like/dislike
		_, err = db.Exec(`INSERT INTO posts_likes (users_id, posts_id, is_dislike) VALUES (?, ?, ?)
                          ON CONFLICT(users_id, posts_id) DO UPDATE SET is_dislike=excluded.is_dislike;`,
			userID, postID, isDislike)
		if err != nil {
			http.Error(w, "Failed to update like/dislike", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
