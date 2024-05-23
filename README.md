## TODO

- [ ] Category filtering (connected with search)
- [ ] Complete profile page
- [ ] Comment functionality
- [x] Like/Vote functionality
- [ ] Thread pages


### General
- [x] Only allowed packages are used.
- [x] Server uses correct HTTP methods (GET, POST, PUT, etc.).

### Site functionality
- [x] Sessions implemented for user persistence. (Cookies)
- [ ] Multiple browser sessions function correctly.
- [ ] Empty posts and comments not allowed.
- [ ] Posts can be filtered by category.
- [ ] Number of likes and dislikes for comments visible to all users.
- [ ] Number of likes and dislikes displayed and updated correctly.
- [ ] Posts cannot be liked and disliked simultaneously.
- [ ] Search functionality implemented with advanced options. [Extra]
- [ ] Interface is clear, well set out, and navigable. [Extra]
- [ ] Intuitive content filtering. [Extra]
- [ ] Categories effective in organizing discussions. [Extra]
- [ ] Easy to respond to posts and comments. [Extra]

### SQLite
- [x] Database designed with an Entity Relationship Diagram (ERD).
- [x] Code uses at least one SELECT query.
- [x] Code uses at least one CREATE query.
- [x] Code uses at least one INSERT query.
- [x] User registration data stored in the database.
- [x] Posts stored in the database.
- [ ] Comments stored in the database.
- [ ] SQL queries effective and efficient. [Extra]
- [ ] Update README with new ERD image

### Registration and login
- [x] Registration requires email, username, and password.
- [x] Incorrect email or password detected during login.
- [x] Registered users can log in and access features.
- [x] Duplicate email or username detected during registration.
- [x] Users can register successfully.
- [x] Forum displays warning message for invalid login attempts.
- [x] User-friendly and secure registration process. [Extra]
- [x] Passwords secured and encrypted using bcrypt or other strong algorithms. [Extra]

### User Interaction
- [x] Only registered users can create posts and comments.
- [x] Posts can be associated with categories.
- [ ] Only registered users can like or dislike posts and comments.
- [ ] Registered users can view their created and liked posts.
- [x] Users have access to profile pages. [Extra]

### Error Handling
- [ ] Server uses appropriate HTTP response codes (2XX, 4XX).
- [ ] All pages function correctly (no unhandled 404 errors).
- [ ] Project handles HTTP status 400 and 500 errors gracefully.
- [ ] Interface handles 5XX HTTP response codes gracefully.
- [ ] Server behaves as expected (no crashes).
- [ ] Informative and user-friendly error messages. [Extra]

### Docker Integration
- [ ] Docker image can be built successfully using Dockerfile.
- [ ] Container runs successfully using created image.
- [ ] Project has no unused Docker objects.

<img src="ERD.png" width="80%" height="80%">

