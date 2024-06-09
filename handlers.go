package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var mu sync.Mutex

func profileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_id")

	session := sessions[cookie.Value]

	userID := session.UserID

	var bio string
	err := db.QueryRow("SELECT bio FROM users WHERE id = ?", userID).Scan(&bio)
	if err != nil && err != sql.ErrNoRows {
		serverError(w, err)
		return
	}

	rows, err := db.Query("SELECT id, users_id, title, content, category, date FROM posts WHERE users_id = ?", userID)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	var createdPosts []Post
	for rows.Next() {
		var post Post
		err = rows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			serverError(w, err)
		}
		createdPosts = append(createdPosts, post)
	}

	likedRows, err := db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date
                                FROM posts p
                                JOIN posts_likes pl ON p.id = pl.posts_id
                                WHERE pl.users_id = ? AND pl.is_dislike = 0`, userID)
	if err != nil {
		serverError(w, err)
		return
	}
	defer likedRows.Close()

	var likedPosts []Post
	for likedRows.Next() {
		var post Post
		err = likedRows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			serverError(w, err)
			return
		}
		likedPosts = append(likedPosts, post)
	}

	profileData := ProfileData{
		Username:     session.Username,
		Bio:          bio,
		CreatedPosts: createdPosts,
		LikedPosts:   likedPosts,
	}

	renderTemplate(w, "profile", profileData, http.StatusOK)
}

func profileViewHandler(w http.ResponseWriter, r *http.Request) {

	path := strings.TrimPrefix(r.URL.Path, "/profile/")
	if path == "" {
		notFound(w)
		return
	}

	username := path

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err == sql.ErrNoRows {
		notFound(w)
		return
	} else if err != nil {
		serverError(w, err)
		return
	}

	var bio string
	err = db.QueryRow("SELECT bio FROM users WHERE id = ?", userID).Scan(&bio)
	if err != nil && err != sql.ErrNoRows {
		serverError(w, err)
		return
	}

	rows, err := db.Query("SELECT id, users_id, title, content, category, date FROM posts WHERE users_id = ?", userID)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	var createdPosts []Post
	for rows.Next() {
		var post Post
		err = rows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			serverError(w, err)
			return
		}
		createdPosts = append(createdPosts, post)
	}

	likedRows, err := db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date
                                FROM posts p
                                JOIN posts_likes pl ON p.id = pl.posts_id
                                WHERE pl.users_id = ? AND pl.is_dislike = 0`, userID)
	if err != nil {
		serverError(w, err)
		return
	}
	defer likedRows.Close()

	var likedPosts []Post
	for likedRows.Next() {
		var post Post
		err = likedRows.Scan(&post.ID, &post.User_id, &post.Title, &post.Content, &post.Category, &post.Date)
		if err != nil {
			serverError(w, err)
			return
		}
		likedPosts = append(likedPosts, post)
	}

	profileData := ProfileData{
		Username:     username,
		Bio:          bio,
		CreatedPosts: createdPosts,
		LikedPosts:   likedPosts,
	}
	renderTemplate(w, "profile_view", profileData, http.StatusOK)
}

func updateBioHandler(w http.ResponseWriter, r *http.Request) {
	// Extract bio data from the form submission
	r.ParseForm()
	bio := r.Form.Get("bio")

	// Retrieve the session ID from the user's cookie
	cookie, _ := r.Cookie("session_id")

	// Retrieve the userID from the session
	session := sessions[cookie.Value]

	userID := session.UserID

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		serverError(w, err)
		return
	}

	// Update the user's bio in the database
	_, err = tx.Exec("UPDATE users SET bio = ? WHERE id = ?", bio, userID)
	if err != nil {
		// Rollback transaction if an error occurs
		tx.Rollback()

		serverError(w, err)
		return
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		serverError(w, err)
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
		serverError(w, err)
		return
	}
	defer rows.Close()

	Posts := []Post{}
	var user_id int
	var id int
	for rows.Next() {
		tmp := Post{}
		err = rows.Scan(&id, &user_id, &tmp.Title, &tmp.Content, &tmp.Category, &tmp.Date)
		if err != nil {
			log.Fatal(err)
		}

		db.QueryRow("SELECT username FROM users WHERE id = ?;", user_id).Scan(&tmp.Username)
		Posts = append(Posts, tmp)

	}

	if err = rows.Err(); err != nil {
		serverError(w, err)
		return
	}

	content := PageContent{Posts: Posts}

	if isAuthenticated {
		renderTemplate(w, "protected", content, http.StatusOK)
	} else {
		renderTemplate(w, "index", content, http.StatusOK)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is authenticated
	isAuthenticated := false
	if _, err := r.Cookie("session_id"); err == nil {
		isAuthenticated = true
	}

	// Get the selected category from the query parameters
	selectedCategory := r.URL.Query().Get("category")

	// Query to get posts with like and dislike counts, filtered by category if provided
	var rows *sql.Rows
	var err error
	if selectedCategory == "" {
		rows, err = db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date,
                           u.username,
                           COALESCE(SUM(CASE WHEN pl.is_dislike = 0 THEN 1 ELSE 0 END), 0) as likes,
                           COALESCE(SUM(CASE WHEN pl.is_dislike = 1 THEN 1 ELSE 0 END), 0) as dislikes
                           FROM posts p
                           JOIN users u ON p.users_id = u.id
                           LEFT JOIN posts_likes pl ON p.id = pl.posts_id
                           GROUP BY p.id, p.users_id, p.title, p.content, p.category, p.date, u.username;`)
	} else {
		rows, err = db.Query(`SELECT p.id, p.users_id, p.title, p.content, p.category, p.date,
                           u.username,
                           COALESCE(SUM(CASE WHEN pl.is_dislike = 0 THEN 1 ELSE 0 END), 0) as likes,
                           COALESCE(SUM(CASE WHEN pl.is_dislike = 1 THEN 1 ELSE 0 END), 0) as dislikes
                           FROM posts p
                           JOIN users u ON p.users_id = u.id
                           LEFT JOIN posts_likes pl ON p.id = pl.posts_id
                           WHERE p.category = ?
                           GROUP BY p.id, p.users_id, p.title, p.content, p.category, p.date, u.username;`, selectedCategory)
	}
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()

	Posts := []Post{}
	for rows.Next() {
		tmp := Post{}
		err = rows.Scan(&tmp.ID, &tmp.User_id, &tmp.Title, &tmp.Content, &tmp.Category, &tmp.Date, &tmp.Username, &tmp.Likes, &tmp.Dislikes)
		if err != nil {
			serverError(w, err)
			return
		}
		Posts = append(Posts, tmp)
	}

	if err = rows.Err(); err != nil {
		serverError(w, err)
		return
	}

	// Hard-coded categories
	hardcodedCategories := []string{
		"Specific Books",
		"In-depth",
		"Character Study",
		"Interviews",
		"Fiction",
		"Biography",
		"Discussion",
	}

	// Query to get the list of categories from the database
	categoryRows, err := db.Query("SELECT DISTINCT category FROM posts")
	if err != nil {
		log.Fatal(err)
	}
	defer categoryRows.Close()

	var categories []string
	for categoryRows.Next() {
		var category string
		if err := categoryRows.Scan(&category); err != nil {
			log.Fatal(err)
		}
		categories = append(categories, category)
	}

	if err = categoryRows.Err(); err != nil {
		log.Fatal(err)
	}

	// Merge hardcoded and dynamically fetched categories, removing duplicates
	categorySet := make(map[string]struct{})
	for _, category := range hardcodedCategories {
		categorySet[category] = struct{}{}
	}
	for _, category := range categories {
		categorySet[category] = struct{}{}
	}

	mergedCategories := make([]string, 0, len(categorySet))
	for category := range categorySet {
		mergedCategories = append(mergedCategories, category)
	}

	// Pass authentication status, posts, categories, and selected category when rendering the template
	content := PageContent{
		Posts:            Posts,
		Categories:       mergedCategories,
		SelectedCategory: selectedCategory,
		IsAuthenticated:  isAuthenticated,
	}

	if isAuthenticated {
		renderTemplate(w, "protected", content, http.StatusOK)
	} else {
		renderTemplate(w, "index", content, http.StatusOK)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		renderTemplate(w, "register", nil, http.StatusOK)

	} else if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			clientError(w, http.StatusBadRequest)
			return
		}

		email := r.Form.Get("email")
		username := r.Form.Get("username")
		password := r.Form.Get("password")

		errors := checkForValidInput(w, username, password, email)
		// errors == nil mean servererror() was called
		if errors == nil {
			return
		}

		data := userFormData{
			FieldErrors: errors,
		}

		if _, ok := data.FieldErrors["username"]; !ok {
			data.Username = username
		}
		if _, ok := data.FieldErrors["email"]; !ok {
			data.Email = email
		}

		if len(data.FieldErrors) > 0 {
			renderTemplate(w, "register", data, http.StatusUnprocessableEntity)
			return
		}

		// Password encrypted for security
		blob, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			serverError(w, err)
			return
		}

		stmtForAddUser, err := db.Prepare("INSERT INTO users (username, email, date_created, password) VALUES (?,?,?,?);")
		if err != nil {
			serverError(w, err)
			return
		}

		defer stmtForAddUser.Close()
		timestamp := time.Now()
		mu.Lock()
		defer mu.Unlock()
		_, err = stmtForAddUser.Exec(username, email, timestamp, blob)
		if err != nil {
			serverError(w, err)
			return
		}

		renderTemplate(w, "login", fmt.Sprintf("New user %s created", strings.ToUpper(username)), http.StatusCreated)
		return

	} else {
		clientError(w, http.StatusMethodNotAllowed)
	}
}

type postDataForm struct {
	Title       string
	Content     string
	Category    string
	FieldErrors map[string]string
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "create_post", nil, http.StatusOK)
	} else if r.Method == http.MethodPost {
		// Extract post data from the form
		title := r.FormValue("title")
		content := r.FormValue("content")
		category := r.FormValue("category")

		// Validate post data

		data := postDataForm{
			FieldErrors: make(map[string]string),
		}
		if title == "" {
			data.FieldErrors["title"] = "Title is required"
		}
		if content == "" {
			data.FieldErrors["content"] = "Content is required"
		}
		if category == "" {
			data.FieldErrors["category"] = "Category is required"
		}

		if len(data.FieldErrors) > 0 {
			if _, ok := data.FieldErrors["title"]; !ok {
				data.Title = title
			}
			if _, ok := data.FieldErrors["content"]; !ok {
				data.Content = content
			}
			if _, ok := data.FieldErrors["category"]; !ok {
				data.Category = category
			}
			renderTemplate(w, "create_post", data, http.StatusUnprocessableEntity)
			return
		}

		// Let's assume the user is already authenticated and we have their user ID in the session
		cookie, err := r.Cookie("session_id")
		if err != nil {
			serverError(w, err)
			return
		}

		session, ok := sessions[cookie.Value]
		if !ok {
			serverError(w, err)
			return
		}

		userID := session.UserID
		// Insert the post into the database
		stmt, err := db.Prepare("INSERT INTO posts (users_id, title, content, category, date) VALUES (?, ?, ?, ?, ?);")
		if err != nil {
			serverError(w, err)
			return
		}

		defer stmt.Close()

		timestamp := time.Now()
		mu.Lock()
		defer mu.Unlock()
		_, err = stmt.Exec(userID, title, content, category, timestamp)
		if err != nil {
			serverError(w, err)
			return
		}

		// Redirect the user to the home page or display a success message
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		clientError(w, http.StatusMethodNotAllowed)
		return
	}
}

type userFormData struct {
	Username    string
	Email       string
	Password    string
	FieldErrors map[string]string
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "login", nil, http.StatusOK)
	} else if r.Method == http.MethodPost {

		err := r.ParseForm()
		if err != nil {
			clientError(w, http.StatusBadRequest)
			return
		}

		usernameOrEmail := r.Form.Get("username")
		passwordFromForm := r.Form.Get("password")

		data := userFormData{
			Username:    usernameOrEmail,
			Password:    passwordFromForm,
			FieldErrors: make(map[string]string),
		}

		if usernameOrEmail == "" {
			data.FieldErrors["username"] = "Username field was empty"
		}
		if passwordFromForm == "" {
			data.FieldErrors["password"] = "Password field was empty"
		}

		stmtForCheck, err := db.Prepare("SELECT id, username, password FROM users WHERE username = ? OR email = ?;")
		if err != nil {
			serverError(w, err)
			return
		}
		defer stmtForCheck.Close()

		var userID int
		var username string
		var password []byte

		err = stmtForCheck.QueryRow(usernameOrEmail, usernameOrEmail).Scan(&userID, &username, &password)
		if err != nil {
			if err == sql.ErrNoRows {
				data.FieldErrors["password"] = "Wrong username or password"
				//do nothing
			} else {
				serverError(w, err)
				return
			}
		}

		// if password field is not empty
		if _, ok := data.FieldErrors["password"]; !ok {
			// checking the validity of the password
			err = bcrypt.CompareHashAndPassword(password, []byte(passwordFromForm))
			if err != nil {
				data.FieldErrors["password"] = "Wrong username or password"
			}
		}

		if len(data.FieldErrors) > 0 {
			if _, ok := data.FieldErrors["username"]; !ok && username != "" {
				data.FieldErrors["password"] = "Wrong username or password"
			}
			renderTemplate(w, "login", data, http.StatusUnprocessableEntity)
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
		clientError(w, http.StatusMethodNotAllowed)
		return
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
		cookie, _ := r.Cookie("session_id")

		session := sessions[cookie.Value]

		userID := session.UserID
		postID := r.FormValue("post_id")
		action := r.FormValue("action")

		var isDislike int
		if action == "like" {
			isDislike = 0
		} else if action == "dislike" {
			isDislike = 1
		} else {
			clientError(w, http.StatusBadRequest)
			return
		}

		// Insert or update like/dislike
		mu.Lock()
		defer mu.Unlock()
		_, err := db.Exec(`INSERT INTO posts_likes (users_id, posts_id, is_dislike) VALUES (?, ?, ?)
                          ON CONFLICT(users_id, posts_id) DO UPDATE SET is_dislike=excluded.is_dislike;`,
			userID, postID, isDislike)
		if err != nil {
			serverError(w, err)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		clientError(w, http.StatusMethodNotAllowed)
	}
}

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/post/")
	if path == "" {
		notFound(w)
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
		clientError(w, http.StatusBadRequest)
		return
	} else if err != nil {
		serverError(w, err)
		return
	}

	fetchCommentsForPost := func(postID string) ([]Comment, error) {
		var comments []Comment
		rows, err := db.Query(`SELECT c.id, c.posts_id, c.content, c.date, c.users_id, u.username,
                               COALESCE(SUM(CASE WHEN cl.is_dislike = 0 THEN 1 ELSE 0 END), 0) as likes,
                               COALESCE(SUM(CASE WHEN cl.is_dislike = 1 THEN 1 ELSE 0 END), 0) as dislikes
                               FROM comments c
                               JOIN users u ON c.users_id = u.id
                               LEFT JOIN comments_likes cl ON c.id = cl.comments_id
                               WHERE c.posts_id = ?
                               GROUP BY c.id, c.posts_id, c.content, c.date, c.users_id, u.username`, postID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var comment Comment
			if err := rows.Scan(&comment.ID, &comment.PostID, &comment.Content, &comment.Date, &comment.UserID, &comment.Username, &comment.Likes, &comment.Dislikes); err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}

		return comments, nil
	}

	comments, err := fetchCommentsForPost(postID)
	if err != nil {
		serverError(w, err)
		return
	}

	data := struct {
		Post     Post
		Comments []Comment
	}{
		Post:     post,
		Comments: comments,
	}

	renderTemplate(w, "post", data, http.StatusOK)
}

func submitCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {

		// Parse the form data
		err := r.ParseForm()
		if err != nil {
			serverError(w, err)
			return
		}

		// Extract data from the form
		postID := r.Form.Get("post_id")
		content := r.Form.Get("content")

		// Retrieve the user ID from the session
		cookie, err := r.Cookie("session_id")
		if err != nil {
			clientError(w, http.StatusUnauthorized)
			return
		}
		session, ok := sessions[cookie.Value]
		if !ok {
			clientError(w, http.StatusUnauthorized)
			return
		}
		userID := session.UserID

		// Insert the comment into the database
		mu.Lock()
		defer mu.Unlock()
		timestamp := time.Now()
		_, err = db.Exec("INSERT INTO comments (posts_id, content, date, users_id) VALUES (?, ?, ?, ?)",
			postID, content, timestamp, userID)
		if err != nil {
			serverError(w, err)
			return
		}

		// Redirect the user back to the post detail page
		http.Redirect(w, r, fmt.Sprintf("/post/%s", postID), http.StatusSeeOther)
	} else {
		clientError(w, http.StatusMethodNotAllowed)
	}
}

func likeCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		cookie, _ := r.Cookie("session_id")

		session := sessions[cookie.Value]

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
			clientError(w, http.StatusBadRequest)
			return
		}

		// Insert or update like/dislike for the comment
		mu.Lock()
		defer mu.Unlock()
		_, err := db.Exec(`INSERT INTO comments_likes (users_id, comments_id, posts_id, is_dislike) VALUES (?, ?, ?, ?)
            						ON CONFLICT(users_id, comments_id, posts_id) DO UPDATE SET is_dislike=excluded.is_dislike;`,
			userID, commentID, postID, isDislike)
		if err != nil {
			serverError(w, err)
			return
		}

		// Redirect back to the page displaying the comment
		http.Redirect(w, r, "/post/"+postID, http.StatusSeeOther)
	} else {
		clientError(w, http.StatusMethodNotAllowed)
	}
}

func categoriesHandler(w http.ResponseWriter, r *http.Request) {
	// Hard-coded categories
	hardcodedCategories := []string{
		"Specific Books",
		"In-depth",
		"Character Study",
		"Interviews",
		"Fiction",
		"Biography",
		"Discussion",
	}

	// Query to get the list of categories from the database
	rows, err := db.Query("SELECT DISTINCT category FROM posts")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			log.Fatal(err)
		}
		categories = append(categories, category)
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	// Merge hardcoded and dynamically fetched categories, removing duplicates
	categorySet := make(map[string]struct{})
	for _, category := range hardcodedCategories {
		categorySet[category] = struct{}{}
	}
	for _, category := range categories {
		categorySet[category] = struct{}{}
	}

	mergedCategories := make([]string, 0, len(categorySet))
	for category := range categorySet {
		mergedCategories = append(mergedCategories, category)
	}

	// Pass categories to the template
	err = tmpl.ExecuteTemplate(w, "categories.html", struct{ Categories []string }{Categories: mergedCategories})
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	// Render the about.html template
	err := tmpl.ExecuteTemplate(w, "about.html", nil)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
