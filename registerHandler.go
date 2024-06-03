package main

// func registerHandler(w http.ResponseWriter, r *http.Request) {

// 	if r.Method == http.MethodGet {
// 		renderTemplate(w, "register", nil, http.StatusOK)

// 	} else if r.Method == http.MethodPost {
// 		fmt.Println("I WAS HERE")

// 		err := r.ParseForm()
// 		if err != nil {
// 			clientError(w, http.StatusBadRequest)
// 			return
// 		}

// 		email := r.Form.Get("email")
// 		username := r.Form.Get("username")
// 		password := r.Form.Get("password")

// 		data := userFormData{
// 			FieldErrors: make(map[string]string),
// 		}

// 		// on falid checkForValidInput generates error with empty body to be able to check for return
// 		if password == "" {
// 			data.FieldErrors["password"] = "Please fill in the password field"

// 		} else if len(password) < 8 {
// 			data.FieldErrors["password"] = "Passwrod has to be at least 8 characters"
// 			return
// 		}

// 		if !isValidEmail(email) {
// 			data.FieldErrors["email"] = "Please enter a correct email"
// 			return
// 		}

// 		if username == "" {
// 			data.FieldErrors["username"] = "Please fill in the username field"
// 		}

// 		if email == "" {
// 			data.FieldErrors["email"] = "Please fill in the email field"
// 		}

// 		// err = checkForValidInput(w, username, password, email)
// 		// if err != nil {
// 		// 	return
// 		// }

// 		stmtForCheck, err := db.Prepare("SELECT username FROM users WHERE username = ?;")
// 		if err != nil {
// 			serverError(w, err)
// 			return
// 		}
// 		defer stmtForCheck.Close()

// 		var userExists string
// 		var emailExists string
// 		err = stmtForCheck.QueryRow(username).Scan(&userExists)
// 		if err != nil && err != sql.ErrNoRows {
// 			serverError(w, err)
// 			return
// 		}
// 		err = stmtForCheck.QueryRow(password).Scan(&emailExists)
// 		if err != nil && err != sql.ErrNoRows {
// 			serverError(w, err)
// 			return
// 		}

// 		if userExists != "" {
// 			data.FieldErrors["username"] = "Username is already taken"
// 		}

// 		if emailExists == "" {
// 			data.FieldErrors["email"] = "Email is already registered"
// 		}
// 		if len(data.FieldErrors) > 0 {
// 			if _, ok := data.FieldErrors["email"]; !ok {
// 				data.Email = email
// 			}
// 			if _, ok := data.FieldErrors["username"]; !ok {
// 				data.Username = username
// 			}
// 			if _, ok := data.FieldErrors["password"]; !ok {
// 				data.Password = password
// 			}
// 			renderTemplate(w, "register", data, http.StatusUnprocessableEntity)
// 			return
// 		}

// 		// Password encrypted for security
// 		blob, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 		if err != nil {
// 			serverError(w, err)
// 			return
// 		}

// 		stmtForAddUser, err := db.Prepare("INSERT INTO users (username, email, date_created, password) VALUES (?,?,?,?);")
// 		if err != nil {
// 			serverError(w, err)
// 			return
// 		}

// 		defer stmtForAddUser.Close()
// 		timestamp := time.Now().Format(time.DateTime)
// 		_, err = stmtForAddUser.Exec(username, email, timestamp, blob)
// 		if err != nil {
// 			serverError(w, err)
// 			return
// 		}

// 		renderTemplate(w, "login", fmt.Sprintf("New user %s created", strings.ToUpper(username)), http.StatusCreated)
// 		return

// 	} else {
// 		clientError(w, http.StatusMethodNotAllowed)
// 	}
// }
