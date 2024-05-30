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
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session, ok := sessions[cookie.Value]
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID := session.UserID

	var bio string
	err = db.QueryRow("SELECT bio FROM users WHERE id = ?", userID).Scan(&bio)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT id, users_id, title, content, category, date FROM posts WHERE users_id = ?", userID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var createdPosts []Post
	for rows.Next() {
		var post Post
		err = rows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			log.Fatal(err)
		}
		createdPosts = append(createdPosts, post)
	}

	likedRows, err := db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date
                                FROM posts p
                                JOIN posts_likes pl ON p.id = pl.posts_id
                                WHERE pl.users_id = ? AND pl.is_dislike = 0`, userID)
	if err != nil {
		log.Fatal(err)
	}
	defer likedRows.Close()

	var likedPosts []Post
	for likedRows.Next() {
		var post Post
		err = likedRows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			log.Fatal(err)
		}
		likedPosts = append(likedPosts, post)
	}

	profileData := ProfileData{
		Username:     session.Username,
		Bio:          bio,
		CreatedPosts: createdPosts,
		LikedPosts:   likedPosts,
	}

	err = tmpl.ExecuteTemplate(w, "profile.html", profileData)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func profileViewHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/profile/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	username := path

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		log.Fatal(err)
	}

	var bio string
	err = db.QueryRow("SELECT bio FROM users WHERE id = ?", userID).Scan(&bio)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT id, users_id, title, content, category, date FROM posts WHERE users_id = ?", userID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var createdPosts []Post
	for rows.Next() {
		var post Post
		err = rows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			log.Fatal(err)
		}
		createdPosts = append(createdPosts, post)
	}

	likedRows, err := db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date
                                FROM posts p
                                JOIN posts_likes pl ON p.id = pl.posts_id
                                WHERE pl.users_id = ? AND pl.is_dislike = 0`, userID)
	if err != nil {
		log.Fatal(err)
	}
	defer likedRows.Close()

	var likedPosts []Post
	for likedRows.Next() {
		var post Post
		err = likedRows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			log.Fatal(err)
		}
		likedPosts = append(likedPosts, post)
	}

	profileData := ProfileData{
		Username:     username,
		Bio:          bio,
		CreatedPosts: createdPosts,
		LikedPosts:   likedPosts,
	}

	err = tmpl.ExecuteTemplate(w, "profile_view.html", profileData)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func updateBioHandler(w http.ResponseWriter, r *http.Request) {
	// Extract bio data from the form submission
	r.ParseForm()
	bio := r.Form.Get("bio")

	// Retrieve the session ID from the user's cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}

	// Retrieve the userID from the session
	session, ok := sessions[cookie.Value]
	if !ok {
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}
	userID := session.UserID

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
		return
	}

	// Update the user's bio in the database
	_, err = tx.Exec("UPDATE users SET bio = ? WHERE id = ?", bio, userID)
	if err != nil {
		// Rollback transaction if an error occurs
		tx.Rollback()
		http.Error(w, "Failed to update bio", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	// Redirect the user back to their profile page
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
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
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/post/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	postID := path

	var post Post
	err := db.QueryRow(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date, u.username,
                        COALESCE(SUM(CASE WHEN pl.is_dislike = 0 THEN 1 ELSE 0 END), 0) as likes,
                        COALESCE(SUM(CASE WHEN pl.is_dislike = 1 THEN 1 ELSE 0 END), 0) as dislikes
                        FROM posts p
                        JOIN users u ON p.users_id = u.id
                        LEFT JOIN posts_likes pl ON p.id = pl.posts_id
                        WHERE p.id = ?
                        GROUP BY p.id, p.users_id, p.title, p.content, p.category, p.date, u.username`, postID).
		Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date, &post.Username, &post.Likes, &post.Dislikes)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		log.Fatal(err)
	}

	// Define the fetchCommentsForPost function
	fetchCommentsForPost := func(postID string) ([]Comment, error) {
		var comments []Comment
		// Query comments from the database based on the postID
		rows, err := db.Query(`SELECT c.id, c.posts_id, c.content, c.date, c.users_id, u.username 
							   FROM comments c
							   JOIN users u ON c.users_id = u.id
							   WHERE c.posts_id = ?`, postID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		// Iterate over the rows and scan each comment into a Comment struct
		for rows.Next() {
			var comment Comment
			if err := rows.Scan(&comment.ID, &comment.PostID, &comment.Content, &comment.Date, &comment.UserID, &comment.Username); err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}

		return comments, nil
	}

	// Fetch comments for the post
	comments, err := fetchCommentsForPost(postID)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Combine post data and comments data into a single struct
	data := struct {
		Post     Post
		Comments []Comment
	}{
		Post:     post,
		Comments: comments,
	}

	err = tmpl.ExecuteTemplate(w, "post.html", data)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func submitCommentHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
		return
	}

	// Extract data from the form
	postID := r.Form.Get("post_id")
	content := r.Form.Get("content")

	// Retrieve the user ID from the session
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}
	session, ok := sessions[cookie.Value]
	if !ok {
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}
	userID := session.UserID

	// Insert the comment into the database
	_, err = db.Exec("INSERT INTO comments (posts_id, content, date, users_id) VALUES (?, ?, ?, ?)",
		postID, content, time.Now(), userID)
	if err != nil {
		http.Error(w, "Failed to submit comment", http.StatusInternalServerError)
		return
	}

	// Redirect the user back to the post detail page
	http.Redirect(w, r, fmt.Sprintf("/post/%s", postID), http.StatusSeeOther)
}

func likeCommentHandler(w http.ResponseWriter, r *http.Request) {
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
		commentID := r.FormValue("comment_id")
		postID := r.FormValue("post_id") // Assuming you have the post ID available
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

		// Insert or update like/dislike for the comment
		_, err = db.Exec(`INSERT INTO comments_likes (users_id, comments_id, posts_id, is_dislike) VALUES (?, ?, ?, ?)
            						ON CONFLICT(users_id, comments_id, posts_id) DO UPDATE SET is_dislike=excluded.is_dislike;`,
			userID, commentID, postID, isDislike)
		if err != nil {
			// Log the error
			log.Println("Failed to update like/dislike:", err)

			// Return an internal server error response
			http.Error(w, "Failed to update like/dislike", http.StatusInternalServerError)
			return
		}

		// Redirect back to the page displaying the comment
		http.Redirect(w, r, "/post/"+postID, http.StatusSeeOther)
	}
}
