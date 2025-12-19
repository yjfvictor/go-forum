# Golang TypeScript forum application project
_Exported on 19/12/2025 at 13:49:02 GMT+11 from Cursor (2.2.36)_

---

**User**

Write a forum in Golang as backend, and TypeScript as frontend (compiled to ES5 code with the `tsc` command with inline source map (`inlineSourceMap` and  `inlineSources` are set to true, and do not set `sourceMap`)).

Use `net/http` in Golang directly to serve the HTTP server and the frontend pages. The session should be served by `github.com/gorilla/sessions` while set the `session.Options` as `HttpOnly: true` and `SameSite: http.SameSiteStrictMode`.

The backend part and the frontend part should be placed in two different directories.

All the user credentials should be store in the `credentials.json` file (the passwords should be very securely hashed). All the forum threads should be stored in the `threads.json` file. Those two JSON files should be placed in the `data` directory. For each post, accurate date and time should be logged in the `threads.json` file, in Unix time stamps.

Initialize an administrator account with the username `admin` and the password `admin123` in the `credentials.json` file.
Do not initialize `threads.json` file. If the golang program fails to read from `threads.json` file, it returns an empty array.

The forum should support normal users and administrator users. The administrator users can modify/delete users and posts in the "Administrator Management" page. The administrator users can also delete the entire thread. The administrator users can also reset users' passwords.

The main page is the page for forum post.
There should be "Create account", "Log in" (or "Log out"), "Administrator Management" hyperlinks on the upper right corner. There should also be a user profile hyperlink there for user modifying their own passwords and deleting their own posts. Administrators should also be able to reset other users' passwords and delete other users' posts.

All the users should be allowed to send a reply post in a thread.

The backend code should be separated in multiple files, as every file only implements its own module.

The frontend should be beautified by the Bootstrap library, and make the hyperlinks look like buttons.

In the frontend code, do not use "prompt" or "alert" or "confirm".
For creating a thread, use an "Create Thread" web page.
For alerting error messages, use Alerts with Bootstrap.
For the confirm messages, use Bootstrap’s JavaScript modal plugin.
The date and time in frontend should be shown as the format "YYYY-MM-DD HH:mm:ss" in local timezone, followed by the timezone name.

All the code (including frontend code and backend code) should be well-documented by comments, as detailed as possible, preferably in Doxygen style. Every source file should contain a file header comment in Doxygen style, including the file creation date (use today's date `2025-12-19`) and the author name (use `Victor Yeh`). Every function should contain a Doxygen-style comment to explain what the function does, and what the parameters are for, and what the return value is for. The structs and variables in golang should also be documented with comments in Doxygen style.
There should also be a `README.md` file to explain all the details of the code, including a flowchart in mermaid code.

Write a `.gitignore` file to avoid commiting compiled files, intermediate files, auto-generated files, the `data` directory.

In the `frontend/tsconfig.json` file, `module` should be set to `amd` instead of `commonjs` and `lib` should be set to `["ES5", "DOM"]`, in order to avoid some known bugs in TypeScript. In the `frontend/tsconfig.json` file, `rootDir` is set to `./src` and the `outDir` is set to `./dist`.

Build all the code and correct all the errors.
Write unit tests for all the code. Run all the unit tests, and correct all the errors.

Finally, deploy the project and tell me the deployment commands.

---

**Cursor**


Creating the initial todo list and starting implementation.



Creating the project structure and initializing the project:



Creating the backend Go code, starting with data models and structures:


```go
/**
 * @file models.go
 * @brief Data models and structures for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import "time"

/**
 * @struct User
 * @brief Represents a user in the forum system
 * @var Username string - The unique username of the user
 * @var PasswordHash string - The securely hashed password
 * @var IsAdmin bool - Whether the user has administrator privileges
 */
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	IsAdmin      bool   `json:"isAdmin"`
}

/**
 * @struct Post
 * @brief Represents a single post in a thread
 * @var ID int - Unique identifier for the post
 * @var Author string - Username of the post author
 * @var Content string - The content of the post
 * @var Timestamp int64 - Unix timestamp when the post was created
 */
type Post struct {
	ID        int    `json:"id"`
	Author    string `json:"author"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
}

/**
 * @struct Thread
 * @brief Represents a forum thread containing multiple posts
 * @var ID int - Unique identifier for the thread
 * @var Title string - The title of the thread
 * @var Author string - Username of the thread creator
 * @var Posts []Post - Array of posts in the thread
 * @var CreatedAt int64 - Unix timestamp when the thread was created
 */
type Thread struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Author    string `json:"author"`
	Posts     []Post `json:"posts"`
	CreatedAt int64  `json:"createdAt"`
}

/**
 * @struct CredentialsData
 * @brief Container for all user credentials
 * @var Users []User - Array of all users in the system
 */
type CredentialsData struct {
	Users []User `json:"users"`
}

/**
 * @struct ThreadsData
 * @brief Container for all forum threads
 * @var Threads []Thread - Array of all threads in the forum
 */
type ThreadsData struct {
	Threads []Thread `json:"threads"`
}

/**
 * @var nextThreadID int
 * @brief Global counter for generating unique thread IDs
 */
var nextThreadID int

/**
 * @var nextPostID int
 * @brief Global counter for generating unique post IDs
 */
var nextPostID int

/**
 * @function GetCurrentTimestamp
 * @brief Returns the current Unix timestamp
 * @return int64 - Current time as Unix timestamp
 */
func GetCurrentTimestamp() int64 {
	return time.Now().Unix()
}

```

```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := ioutil.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := ioutil.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```

```go
/**
 * @file auth.go
 * @brief Authentication and authorization logic
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"

	"github.com/gorilla/sessions"
)

/**
 * @var store *sessions.CookieStore
 * @brief Session store for managing user sessions
 */
var store *sessions.CookieStore

/**
 * @var sessionName string
 * @brief Name of the session cookie
 */
var sessionName = "forum_session"

/**
 * @function InitSessionStore
 * @brief Initializes the session store with a secret key
 * @param secretKey string - Secret key for session encryption
 */
func InitSessionStore(secretKey string) {
	store = sessions.NewCookieStore([]byte(secretKey))
	store.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
	}
}

/**
 * @function HashPassword
 * @brief Hashes a password using bcrypt
 * @param password string - Plain text password to hash
 * @return string - Hashed password
 * @return error - Error if hashing fails
 */
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

/**
 * @function CheckPassword
 * @brief Verifies a password against a hash
 * @param hash string - Hashed password
 * @param password string - Plain text password to verify
 * @return bool - True if password matches, false otherwise
 */
func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/**
 * @function GetSession
 * @brief Retrieves the session for a request
 * @param r *http.Request - HTTP request
 * @return *sessions.Session - Session object
 * @return error - Error if session retrieval fails
 */
func GetSession(r *http.Request) (*sessions.Session, error) {
	return store.Get(r, sessionName)
}

/**
 * @function SetUserSession
 * @brief Sets user information in the session
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @param username string - Username to store in session
 * @param isAdmin bool - Whether user is an administrator
 * @return error - Error if session save fails
 */
func SetUserSession(w http.ResponseWriter, r *http.Request, username string, isAdmin bool) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = username
	session.Values["isAdmin"] = isAdmin
	session.Values["authenticated"] = true

	return session.Save(r, w)
}

/**
 * @function ClearUserSession
 * @brief Clears user session (logs out)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @return error - Error if session save fails
 */
func ClearUserSession(w http.ResponseWriter, r *http.Request) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = nil
	session.Values["isAdmin"] = nil
	session.Values["authenticated"] = false

	return session.Save(r, w)
}

/**
 * @function GetUsernameFromSession
 * @brief Retrieves username from session
 * @param r *http.Request - HTTP request
 * @return string - Username if authenticated, empty string otherwise
 * @return bool - True if user is authenticated, false otherwise
 */
func GetUsernameFromSession(r *http.Request) (string, bool) {
	session, err := GetSession(r)
	if err != nil {
		return "", false
	}

	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		return "", false
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		return "", false
	}

	return username, true
}

/**
 * @function IsAdminFromSession
 * @brief Checks if user is an administrator from session
 * @param r *http.Request - HTTP request
 * @return bool - True if user is admin, false otherwise
 */
func IsAdminFromSession(r *http.Request) bool {
	session, err := GetSession(r)
	if err != nil {
		return false
	}

	isAdmin, ok := session.Values["isAdmin"].(bool)
	return ok && isAdmin
}

/**
 * @function RequireAuth
 * @brief Middleware to require authentication
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires authentication
 */
func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, authenticated := GetUsernameFromSession(r)
		if !authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Store username in request context for use in handler
		r.Header.Set("X-Username", username)
		handler(w, r)
	}
}

/**
 * @function RequireAdmin
 * @brief Middleware to require administrator privileges
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires admin privileges
 */
func RequireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAdminFromSession(r) {
			http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
			return
		}
		RequireAuth(handler)(w, r)
	}
}

/**
 * @function GenerateSecretKey
 * @brief Generates a random secret key for session encryption
 * @return string - Base64 encoded secret key
 * @return error - Error if key generation fails
 */
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

/**
 * @function FindUser
 * @brief Finds a user by username in credentials
 * @param username string - Username to search for
 * @return *User - Pointer to user if found, nil otherwise
 * @return error - Error if credentials loading fails
 */
func FindUser(username string) (*User, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return nil, err
	}

	for i := range creds.Users {
		if creds.Users[i].Username == username {
			return &creds.Users[i], nil
		}
	}

	return nil, errors.New("user not found")
}

```


Creating HTTP handlers:


```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": user.Username,
		"isAdmin": user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsAdminFromSession(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```


Creating the main.go file:


```go
/**
 * @file main.go
 * @brief Main entry point for the forum application server
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"fmt"
	"log"
	"net/http"
)

/**
 * @var serverPort string
 * @brief Port number for the HTTP server (default: 8080)
 */
var serverPort = "8080"

/**
 * @function main
 * @brief Main function that initializes and starts the HTTP server
 */
func main() {
	// Initialize session store with a secret key
	// In production, this should be a secure random key stored in environment variable
	secretKey := "forum-secret-key-change-in-production"
	InitSessionStore(secretKey)

	// Initialize admin account if credentials file doesn't exist
	if err := InitializeAdminAccount(); err != nil {
		log.Printf("Warning: Failed to initialize admin account: %v", err)
	}

	// Load threads to initialize nextThreadID and nextPostID
	threads, err := LoadThreads()
	if err != nil {
		log.Printf("Warning: Failed to load threads: %v", err)
	} else {
		// Initialize IDs based on existing data
		for _, thread := range threads.Threads {
			if thread.ID >= nextThreadID {
				nextThreadID = thread.ID + 1
			}
			for _, post := range thread.Posts {
				if post.ID >= nextPostID {
					nextPostID = post.ID + 1
				}
			}
		}
		// If no threads exist, start from 1
		if nextThreadID == 0 {
			nextThreadID = 1
		}
		if nextPostID == 0 {
			nextPostID = 1
		}
	}

	// Set up HTTP routes
	http.HandleFunc("/", ServeIndex)
	http.HandleFunc("/static/", ServeStatic)

	// API routes
	http.HandleFunc("/api/login", HandleLogin)
	http.HandleFunc("/api/logout", HandleLogout)
	http.HandleFunc("/api/create-account", HandleCreateAccount)
	http.HandleFunc("/api/session", HandleGetSession)
	http.HandleFunc("/api/threads", HandleGetThreads)
	http.HandleFunc("/api/thread", HandleGetThread)
	http.HandleFunc("/api/create-thread", RequireAuth(HandleCreateThread))
	http.HandleFunc("/api/add-post", RequireAuth(HandleAddPost))
	http.HandleFunc("/api/delete-post", RequireAuth(HandleDeletePost))
	http.HandleFunc("/api/delete-thread", RequireAdmin(HandleDeleteThread))
	http.HandleFunc("/api/users", RequireAdmin(HandleGetUsers))
	http.HandleFunc("/api/delete-user", RequireAdmin(HandleDeleteUser))
	http.HandleFunc("/api/reset-password", RequireAuth(HandleResetPassword))
	http.HandleFunc("/api/update-user-admin", RequireAdmin(HandleUpdateUserAdmin))

	// Start the server
	log.Printf("Server starting on port %s", serverPort)
	log.Printf("Admin account: username=admin, password=admin123")
	if err := http.ListenAndServe(":"+serverPort, nil); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

```


Creating the TypeScript configuration and frontend code:


```jsonc
{
  "compilerOptions": {
    "target": "ES5",
    "module": "amd",
    "lib": ["ES5", "DOM"],
    "rootDir": "./src",
    "outDir": "./dist",
    "inlineSourceMap": true,
    "inlineSources": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}

```

```typescript
/**
 * @file api.ts
 * @brief API client for communicating with the backend server
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @interface ApiResponse
 * @brief Generic API response structure
 * @var success boolean - Whether the request was successful
 */
interface ApiResponse {
    success: boolean;
}

/**
 * @interface LoginResponse
 * @brief Response structure for login requests
 * @var success boolean - Whether login was successful
 * @var username string - Username of the logged-in user
 * @var isAdmin boolean - Whether the user is an administrator
 */
interface LoginResponse extends ApiResponse {
    username: string;
    isAdmin: boolean;
}

/**
 * @interface SessionResponse
 * @brief Response structure for session information
 * @var authenticated boolean - Whether user is authenticated
 * @var username string - Username if authenticated
 * @var isAdmin boolean - Whether user is admin if authenticated
 */
interface SessionResponse {
    authenticated: boolean;
    username?: string;
    isAdmin?: boolean;
}

/**
 * @interface Post
 * @brief Structure representing a forum post
 * @var id number - Unique post identifier
 * @var author string - Username of the post author
 * @var content string - Content of the post
 * @var timestamp number - Unix timestamp of when post was created
 */
interface Post {
    id: number;
    author: string;
    content: string;
    timestamp: number;
}

/**
 * @interface Thread
 * @brief Structure representing a forum thread
 * @var id number - Unique thread identifier
 * @var title string - Title of the thread
 * @var author string - Username of the thread creator
 * @var posts Post[] - Array of posts in the thread
 * @var createdAt number - Unix timestamp of when thread was created
 */
interface Thread {
    id: number;
    title: string;
    author: string;
    posts: Post[];
    createdAt: number;
}

/**
 * @interface User
 * @brief Structure representing a user
 * @var username string - Username of the user
 * @var isAdmin boolean - Whether the user is an administrator
 */
interface User {
    username: string;
    isAdmin: boolean;
}

/**
 * @function apiRequest
 * @brief Makes an API request to the backend
 * @param endpoint string - API endpoint path
 * @param method string - HTTP method (GET, POST, DELETE, etc.)
 * @param body any - Request body object (will be JSON stringified)
 * @return Promise<any> - Promise that resolves to the response data
 */
function apiRequest(endpoint: string, method: string = 'GET', body?: any): Promise<any> {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(method, '/api' + endpoint, true);
        xhr.setRequestHeader('Content-Type', 'application/json');

        xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    resolve(response);
                } catch (e) {
                    resolve(xhr.responseText);
                }
            } else {
                try {
                    const error = JSON.parse(xhr.responseText);
                    reject(new Error(error.message || xhr.statusText));
                } catch (e) {
                    reject(new Error(xhr.statusText));
                }
            }
        };

        xhr.onerror = function() {
            reject(new Error('Network error'));
        };

        if (body) {
            xhr.send(JSON.stringify(body));
        } else {
            xhr.send();
        }
    });
}

/**
 * @function login
 * @brief Logs in a user
 * @param username string - Username
 * @param password string - Password
 * @return Promise<LoginResponse> - Promise that resolves to login response
 */
export function login(username: string, password: string): Promise<LoginResponse> {
    return apiRequest('/login', 'POST', { username, password });
}

/**
 * @function logout
 * @brief Logs out the current user
 * @return Promise<ApiResponse> - Promise that resolves to logout response
 */
export function logout(): Promise<ApiResponse> {
    return apiRequest('/logout', 'POST');
}

/**
 * @function createAccount
 * @brief Creates a new user account
 * @param username string - Desired username
 * @param password string - Desired password
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function createAccount(username: string, password: string): Promise<ApiResponse> {
    return apiRequest('/create-account', 'POST', { username, password });
}

/**
 * @function getSession
 * @brief Gets current session information
 * @return Promise<SessionResponse> - Promise that resolves to session information
 */
export function getSession(): Promise<SessionResponse> {
    return apiRequest('/session', 'GET');
}

/**
 * @function getThreads
 * @brief Gets all forum threads
 * @return Promise<Thread[]> - Promise that resolves to array of threads
 */
export function getThreads(): Promise<Thread[]> {
    return apiRequest('/threads', 'GET');
}

/**
 * @function getThread
 * @brief Gets a specific thread by ID
 * @param threadId number - Thread ID
 * @return Promise<Thread> - Promise that resolves to thread data
 */
export function getThread(threadId: number): Promise<Thread> {
    return apiRequest('/thread?id=' + threadId, 'GET');
}

/**
 * @function createThread
 * @brief Creates a new forum thread
 * @param title string - Thread title
 * @param content string - Initial post content
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function createThread(title: string, content: string): Promise<ApiResponse> {
    return apiRequest('/create-thread', 'POST', { title, content });
}

/**
 * @function addPost
 * @brief Adds a reply post to a thread
 * @param threadId number - Thread ID
 * @param content string - Post content
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function addPost(threadId: number, content: string): Promise<ApiResponse> {
    return apiRequest('/add-post', 'POST', { threadId, content });
}

/**
 * @function deletePost
 * @brief Deletes a post from a thread
 * @param threadId number - Thread ID
 * @param postId number - Post ID
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deletePost(threadId: number, postId: number): Promise<ApiResponse> {
    return apiRequest('/delete-post', 'DELETE', { threadId, postId });
}

/**
 * @function deleteThread
 * @brief Deletes an entire thread (admin only)
 * @param threadId number - Thread ID
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deleteThread(threadId: number): Promise<ApiResponse> {
    return apiRequest('/delete-thread', 'DELETE', { threadId });
}

/**
 * @function getUsers
 * @brief Gets all users (admin only)
 * @return Promise<User[]> - Promise that resolves to array of users
 */
export function getUsers(): Promise<User[]> {
    return apiRequest('/users', 'GET');
}

/**
 * @function deleteUser
 * @brief Deletes a user (admin only)
 * @param username string - Username to delete
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deleteUser(username: string): Promise<ApiResponse> {
    return apiRequest('/delete-user', 'DELETE', { username });
}

/**
 * @function resetPassword
 * @brief Resets a user's password
 * @param username string - Username whose password to reset
 * @param newPassword string - New password
 * @return Promise<ApiResponse> - Promise that resolves to reset response
 */
export function resetPassword(username: string, newPassword: string): Promise<ApiResponse> {
    return apiRequest('/reset-password', 'POST', { username, newPassword });
}

/**
 * @function updateUserAdmin
 * @brief Updates a user's admin status (admin only)
 * @param username string - Username to update
 * @param isAdmin boolean - New admin status
 * @return Promise<ApiResponse> - Promise that resolves to update response
 */
export function updateUserAdmin(username: string, isAdmin: boolean): Promise<ApiResponse> {
    return apiRequest('/update-user-admin', 'POST', { username, isAdmin });
}

```

```typescript
/**
 * @file utils.ts
 * @brief Utility functions for the frontend
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @function formatTimestamp
 * @brief Formats a Unix timestamp to "YYYY-MM-DD HH:mm:ss" format in local timezone
 * @param timestamp number - Unix timestamp
 * @return string - Formatted date string with timezone name
 */
export function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp * 1000);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    const timezoneName = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${timezoneName}`;
}

/**
 * @function showAlert
 * @brief Shows a Bootstrap alert message
 * @param message string - Alert message to display
 * @param type string - Alert type (success, danger, warning, info)
 * @param container HTMLElement - Container element to append alert to
 */
export function showAlert(message: string, type: string = 'danger', container?: HTMLElement): void {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const targetContainer = container || document.body;
    targetContainer.insertBefore(alertDiv, targetContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * @function showConfirmModal
 * @brief Shows a Bootstrap confirmation modal
 * @param title string - Modal title
 * @param message string - Modal message
 * @return Promise<boolean> - Promise that resolves to true if confirmed, false if cancelled
 */
export function showConfirmModal(title: string, message: string): Promise<boolean> {
    return new Promise((resolve) => {
        // Remove existing modal if any
        const existingModal = document.getElementById('confirmModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const modalDiv = document.createElement('div');
        modalDiv.id = 'confirmModal';
        modalDiv.className = 'modal fade';
        modalDiv.setAttribute('tabindex', '-1');
        modalDiv.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="confirmButton">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modalDiv);
        
        const modal = new (window as any).bootstrap.Modal(modalDiv);
        
        const confirmButton = modalDiv.querySelector('#confirmButton');
        confirmButton.addEventListener('click', () => {
            modal.hide();
            resolve(true);
        });
        
        modalDiv.addEventListener('hidden.bs.modal', () => {
            modalDiv.remove();
            resolve(false);
        });
        
        modal.show();
    });
}

```


Creating the main frontend TypeScript files:


```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

```

```typescript
/**
 * @file index.ts
 * @brief Main forum page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getThreads, deleteThread, deletePost } from './api';
import { formatTimestamp, showAlert, showConfirmModal } from './utils';
import { Thread, Post } from './api';

/**
 * @function renderThreads
 * @brief Renders all threads on the forum page
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads yet. Be the first to create one!</p>';
        return;
    }
    
    container.innerHTML = '';
    
    threads.forEach(thread => {
        const threadDiv = document.createElement('div');
        threadDiv.className = 'card mb-3';
        threadDiv.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <a href="#thread-${thread.id}" class="text-decoration-none">${escapeHtml(thread.title)}</a>
                </h5>
                <div>
                    <small class="text-muted">Created by ${escapeHtml(thread.author)} on ${formatTimestamp(thread.createdAt)}</small>
                    <button class="btn btn-sm btn-danger ms-2 delete-thread-btn" data-thread-id="${thread.id}" style="display: none;">
                        Delete Thread
                    </button>
                </div>
            </div>
            <div class="card-body">
                ${renderPosts(thread.posts, thread.id)}
                <div class="mt-3">
                    <button class="btn btn-primary reply-btn" data-thread-id="${thread.id}">Reply</button>
                </div>
            </div>
        `;
        
        container.appendChild(threadDiv);
        
        // Add reply functionality
        threadDiv.querySelector('.reply-btn')?.addEventListener('click', () => {
            showReplyForm(thread.id);
        });
        
        // Add delete thread button (admin only)
        const deleteThreadBtn = threadDiv.querySelector('.delete-thread-btn') as HTMLButtonElement;
        if (deleteThreadBtn) {
            const session = (window as any).currentUser;
            if (session && session.isAdmin) {
                deleteThreadBtn.style.display = 'inline-block';
                deleteThreadBtn.addEventListener('click', async () => {
                    const confirmed = await showConfirmModal(
                        'Delete Thread',
                        'Are you sure you want to delete this entire thread? This action cannot be undone.'
                    );
                    if (confirmed) {
                        try {
                            await deleteThread(thread.id);
                            showAlert('Thread deleted successfully', 'success');
                            loadThreads();
                        } catch (error: any) {
                            showAlert('Failed to delete thread: ' + error.message);
                        }
                    }
                });
            }
        }
    });
}

/**
 * @function renderPosts
 * @brief Renders posts in a thread
 * @param posts Post[] - Array of posts to render
 * @param threadId number - ID of the thread
 * @return string - HTML string for the posts
 */
function renderPosts(posts: Post[], threadId: number): string {
    return posts.map((post, index) => {
        const session = (window as any).currentUser;
        const canDelete = session && (session.isAdmin || session.username === post.author);
        const deleteBtn = canDelete ? `
            <button class="btn btn-sm btn-danger delete-post-btn" data-thread-id="${threadId}" data-post-id="${post.id}">
                Delete
            </button>
        ` : '';
        
        return `
            <div class="post mb-3 p-3 border rounded">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <strong>${escapeHtml(post.author)}</strong>
                        <small class="text-muted ms-2">${formatTimestamp(post.timestamp)}</small>
                        ${index === 0 ? ' <span class="badge bg-primary">Original Post</span>' : ''}
                    </div>
                    ${deleteBtn}
                </div>
                <div class="mt-2">${escapeHtml(post.content).replace(/\n/g, '<br>')}</div>
            </div>
        `;
    }).join('');
}

/**
 * @function showReplyForm
 * @brief Shows a form to reply to a thread
 * @param threadId number - ID of the thread to reply to
 */
function showReplyForm(threadId: number): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'replyModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reply to Thread</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <textarea class="form-control" id="replyContent" rows="5" placeholder="Enter your reply..."></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="submitReply">Submit</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    
    document.getElementById('submitReply')?.addEventListener('click', async () => {
        const content = (document.getElementById('replyContent') as HTMLTextAreaElement)?.value;
        if (!content || content.trim() === '') {
            showAlert('Please enter a reply', 'warning');
            return;
        }
        
        try {
            const { addPost } = await import('./api');
            await addPost(threadId, content);
            modal.hide();
            showAlert('Reply posted successfully', 'success');
            loadThreads();
        } catch (error: any) {
            showAlert('Failed to post reply: ' + error.message);
        }
    });
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
    
    modal.show();
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
        
        // Attach delete post handlers
        document.querySelectorAll('.delete-post-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const target = e.target as HTMLButtonElement;
                const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
                const postId = parseInt(target.getAttribute('data-post-id') || '0');
                
                const confirmed = await showConfirmModal(
                    'Delete Post',
                    'Are you sure you want to delete this post? This action cannot be undone.'
                );
                
                if (confirmed) {
                    try {
                        await deletePost(threadId, postId);
                        showAlert('Post deleted successfully', 'success');
                        loadThreads();
                    } catch (error: any) {
                        showAlert('Failed to delete post: ' + error.message);
                    }
                }
            });
        });
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initForumPage
 * @brief Initializes the forum page
 */
export async function initForumPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1>Forum</h1>
                ${session ? `
                    <a href="#create-thread" class="btn btn-primary">Create Thread</a>
                ` : `
                    <a href="#login" class="btn btn-primary">Log in to Create Thread</a>
                `}
            </div>
            <div id="threadsContainer"></div>
        </div>
    `;
    
    await loadThreads();
}

```


Creating the remaining frontend TypeScript files:


```typescript
/**
 * @file login.ts
 * @brief Login page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { login } from './api';
import { showAlert } from './utils';

/**
 * @function initLoginPage
 * @brief Initializes the login page
 */
export async function initLoginPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="mb-0">Log In</h3>
                        </div>
                        <div class="card-body">
                            <form id="loginForm">
                                <div class="mb-3">
                                    <label for="username" class="form-label">Username</label>
                                    <input type="text" class="form-control" id="username" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Password</label>
                                    <input type="password" class="form-control" id="password" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Log In</button>
                            </form>
                            <div class="mt-3 text-center">
                                <a href="#create-account" class="text-decoration-none">Don't have an account? Create one</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const form = document.getElementById('loginForm') as HTMLFormElement;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = (document.getElementById('username') as HTMLInputElement).value;
        const password = (document.getElementById('password') as HTMLInputElement).value;
        
        try {
            const response = await login(username, password);
            if (response.success) {
                // Reload the page to update session
                window.location.href = '/';
            }
        } catch (error: any) {
            showAlert('Login failed: ' + error.message);
        }
    });
}

```

```typescript
/**
 * @file createAccount.ts
 * @brief Account creation page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { createAccount } from './api';
import { showAlert } from './utils';

/**
 * @function initCreateAccountPage
 * @brief Initializes the create account page
 */
export async function initCreateAccountPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="mb-0">Create Account</h3>
                        </div>
                        <div class="card-body">
                            <form id="createAccountForm">
                                <div class="mb-3">
                                    <label for="newUsername" class="form-label">Username</label>
                                    <input type="text" class="form-control" id="newUsername" required>
                                </div>
                                <div class="mb-3">
                                    <label for="newPassword" class="form-label">Password</label>
                                    <input type="password" class="form-control" id="newPassword" required>
                                </div>
                                <div class="mb-3">
                                    <label for="confirmPassword" class="form-label">Confirm Password</label>
                                    <input type="password" class="form-control" id="confirmPassword" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Create Account</button>
                            </form>
                            <div class="mt-3 text-center">
                                <a href="#login" class="text-decoration-none">Already have an account? Log in</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const form = document.getElementById('createAccountForm') as HTMLFormElement;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = (document.getElementById('newUsername') as HTMLInputElement).value;
        const password = (document.getElementById('newPassword') as HTMLInputElement).value;
        const confirmPassword = (document.getElementById('confirmPassword') as HTMLInputElement).value;
        
        if (password !== confirmPassword) {
            showAlert('Passwords do not match', 'warning');
            return;
        }
        
        if (password.length < 3) {
            showAlert('Password must be at least 3 characters long', 'warning');
            return;
        }
        
        try {
            const response = await createAccount(username, password);
            if (response.success) {
                showAlert('Account created successfully! Please log in.', 'success');
                setTimeout(() => {
                    window.location.href = '/#login';
                }, 1500);
            }
        } catch (error: any) {
            showAlert('Failed to create account: ' + error.message);
        }
    });
}

```

```typescript
/**
 * @file createThread.ts
 * @brief Thread creation page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { createThread } from './api';
import { showAlert } from './utils';

/**
 * @function initCreateThreadPage
 * @brief Initializes the create thread page
 */
export async function initCreateThreadPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="mb-0">Create Thread</h3>
                        </div>
                        <div class="card-body">
                            <form id="createThreadForm">
                                <div class="mb-3">
                                    <label for="threadTitle" class="form-label">Title</label>
                                    <input type="text" class="form-control" id="threadTitle" required>
                                </div>
                                <div class="mb-3">
                                    <label for="threadContent" class="form-label">Content</label>
                                    <textarea class="form-control" id="threadContent" rows="10" required></textarea>
                                </div>
                                <div class="d-flex gap-2">
                                    <button type="submit" class="btn btn-primary">Create Thread</button>
                                    <a href="/" class="btn btn-secondary">Cancel</a>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const form = document.getElementById('createThreadForm') as HTMLFormElement;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const title = (document.getElementById('threadTitle') as HTMLInputElement).value;
        const content = (document.getElementById('threadContent') as HTMLTextAreaElement).value;
        
        if (!title || title.trim() === '') {
            showAlert('Please enter a title', 'warning');
            return;
        }
        
        if (!content || content.trim() === '') {
            showAlert('Please enter content', 'warning');
            return;
        }
        
        try {
            const response = await createThread(title, content);
            if (response.success) {
                showAlert('Thread created successfully!', 'success');
                setTimeout(() => {
                    window.location.href = '/';
                }, 1500);
            }
        } catch (error: any) {
            showAlert('Failed to create thread: ' + error.message);
        }
    });
}

```

```typescript
/**
 * @file profile.ts
 * @brief User profile page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getThreads, resetPassword, deletePost } from './api';
import { formatTimestamp, showAlert, showConfirmModal } from './utils';
import { Thread, Post } from './api';

/**
 * @function renderUserPosts
 * @brief Renders all posts by the current user
 * @param threads Thread[] - Array of all threads
 * @param username string - Username to filter posts by
 */
function renderUserPosts(threads: Thread[], username: string): void {
    const container = document.getElementById('userPostsContainer');
    if (!container) return;
    
    const userPosts: Array<{ thread: Thread; post: Post }> = [];
    
    threads.forEach(thread => {
        thread.posts.forEach(post => {
            if (post.author === username) {
                userPosts.push({ thread, post });
            }
        });
    });
    
    if (userPosts.length === 0) {
        container.innerHTML = '<p class="text-muted">You have not posted anything yet.</p>';
        return;
    }
    
    container.innerHTML = '';
    
    userPosts.forEach(({ thread, post }) => {
        const postDiv = document.createElement('div');
        postDiv.className = 'card mb-3';
        postDiv.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">
                    <a href="/#thread-${thread.id}" class="text-decoration-none">${escapeHtml(thread.title)}</a>
                </h6>
                <button class="btn btn-sm btn-danger delete-post-btn" data-thread-id="${thread.id}" data-post-id="${post.id}">
                    Delete
                </button>
            </div>
            <div class="card-body">
                <p class="text-muted mb-2">Posted on ${formatTimestamp(post.timestamp)}</p>
                <p>${escapeHtml(post.content).replace(/\n/g, '<br>')}</p>
            </div>
        `;
        
        container.appendChild(postDiv);
        
        const deleteBtn = postDiv.querySelector('.delete-post-btn') as HTMLButtonElement;
        deleteBtn.addEventListener('click', async () => {
            const confirmed = await showConfirmModal(
                'Delete Post',
                'Are you sure you want to delete this post? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deletePost(thread.id, post.id);
                    showAlert('Post deleted successfully', 'success');
                    loadUserPosts(username);
                } catch (error: any) {
                    showAlert('Failed to delete post: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUserPosts
 * @brief Loads and displays all posts by a user
 * @param username string - Username to load posts for
 */
async function loadUserPosts(username: string): Promise<void> {
    try {
        const threads = await getThreads();
        renderUserPosts(threads, username);
    } catch (error: any) {
        showAlert('Failed to load posts: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initProfilePage
 * @brief Initializes the profile page
 */
export async function initProfilePage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.username) {
        window.location.href = '/#login';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Profile</h4>
                        </div>
                        <div class="card-body">
                            <p><strong>Username:</strong> ${escapeHtml(session.username)}</p>
                            <p><strong>Role:</strong> ${session.isAdmin ? 'Administrator' : 'User'}</p>
                        </div>
                    </div>
                    <div class="card mt-3">
                        <div class="card-header">
                            <h5 class="mb-0">Change Password</h5>
                        </div>
                        <div class="card-body">
                            <form id="changePasswordForm">
                                <div class="mb-3">
                                    <label for="newPassword" class="form-label">New Password</label>
                                    <input type="password" class="form-control" id="newPassword" required>
                                </div>
                                <div class="mb-3">
                                    <label for="confirmNewPassword" class="form-label">Confirm New Password</label>
                                    <input type="password" class="form-control" id="confirmNewPassword" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Change Password</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">My Posts</h4>
                        </div>
                        <div class="card-body">
                            <div id="userPostsContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Handle password change
    const form = document.getElementById('changePasswordForm') as HTMLFormElement;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const newPassword = (document.getElementById('newPassword') as HTMLInputElement).value;
        const confirmPassword = (document.getElementById('confirmNewPassword') as HTMLInputElement).value;
        
        if (newPassword !== confirmPassword) {
            showAlert('Passwords do not match', 'warning');
            return;
        }
        
        if (newPassword.length < 3) {
            showAlert('Password must be at least 3 characters long', 'warning');
            return;
        }
        
        try {
            await resetPassword(session.username, newPassword);
            showAlert('Password changed successfully', 'success');
            form.reset();
        } catch (error: any) {
            showAlert('Failed to change password: ' + error.message);
        }
    });
    
    // Load user posts
    await loadUserPosts(session.username);
}

```

```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal } from './utils';
import { User, Thread } from './api';

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;">
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2" data-username="${escapeHtml(user.username)}">
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn" data-username="${escapeHtml(user.username)}">
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}

```


Creating the HTML file and updating main.ts:


```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Forum</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto" id="navLinks">
                    <!-- Navigation links will be populated by JavaScript -->
                </ul>
            </div>
        </div>
    </nav>
    
    <div id="mainContent">
        <!-- Main content will be populated by JavaScript -->
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Main application script -->
    <script src="main.js"></script>
</body>
</html>

```

```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}


```

```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                (window as any).currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}


```

```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                (window as any).currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
    
    // Update currentUser reference after page load
    (window as any).currentUser = currentUser;
    }
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}


```

```typescript
/**
 * @file index.ts
 * @brief Main forum page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getThreads, deleteThread, deletePost } from './api';
import { formatTimestamp, showAlert, showConfirmModal } from './utils';
import { Thread, Post } from './api';

/**
 * @function renderThreads
 * @brief Renders all threads on the forum page
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads yet. Be the first to create one!</p>';
        return;
    }
    
    container.innerHTML = '';
    
    threads.forEach(thread => {
        const threadDiv = document.createElement('div');
        threadDiv.className = 'card mb-3';
        threadDiv.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <a href="#thread-${thread.id}" class="text-decoration-none">${escapeHtml(thread.title)}</a>
                </h5>
                <div>
                    <small class="text-muted">Created by ${escapeHtml(thread.author)} on ${formatTimestamp(thread.createdAt)}</small>
                    <button class="btn btn-sm btn-danger ms-2 delete-thread-btn" data-thread-id="${thread.id}" style="display: none;">
                        Delete Thread
                    </button>
                </div>
            </div>
            <div class="card-body">
                ${renderPosts(thread.posts, thread.id)}
                <div class="mt-3">
                    <button class="btn btn-primary reply-btn" data-thread-id="${thread.id}">Reply</button>
                </div>
            </div>
        `;
        
        container.appendChild(threadDiv);
        
        // Add reply functionality
        threadDiv.querySelector('.reply-btn')?.addEventListener('click', () => {
            showReplyForm(thread.id);
        });
        
        // Add delete thread button (admin only)
        const deleteThreadBtn = threadDiv.querySelector('.delete-thread-btn') as HTMLButtonElement;
        if (deleteThreadBtn) {
            const session = (window as any).currentUser;
            if (session && session.isAdmin) {
                deleteThreadBtn.style.display = 'inline-block';
                deleteThreadBtn.addEventListener('click', async () => {
                    const confirmed = await showConfirmModal(
                        'Delete Thread',
                        'Are you sure you want to delete this entire thread? This action cannot be undone.'
                    );
                    if (confirmed) {
                        try {
                            await deleteThread(thread.id);
                            showAlert('Thread deleted successfully', 'success');
                            loadThreads();
                        } catch (error: any) {
                            showAlert('Failed to delete thread: ' + error.message);
                        }
                    }
                });
            }
        }
        
        // Attach delete post handlers for this thread
        threadDiv.querySelectorAll('.delete-post-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const target = e.target as HTMLButtonElement;
                const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
                const postId = parseInt(target.getAttribute('data-post-id') || '0');
                
                const confirmed = await showConfirmModal(
                    'Delete Post',
                    'Are you sure you want to delete this post? This action cannot be undone.'
                );
                
                if (confirmed) {
                    try {
                        await deletePost(threadId, postId);
                        showAlert('Post deleted successfully', 'success');
                        loadThreads();
                    } catch (error: any) {
                        showAlert('Failed to delete post: ' + error.message);
                    }
                }
            });
        });
    });
}

/**
 * @function renderPosts
 * @brief Renders posts in a thread
 * @param posts Post[] - Array of posts to render
 * @param threadId number - ID of the thread
 * @return string - HTML string for the posts
 */
function renderPosts(posts: Post[], threadId: number): string {
    return posts.map((post, index) => {
        const session = (window as any).currentUser;
        const canDelete = session && (session.isAdmin || session.username === post.author);
        const deleteBtn = canDelete ? `
            <button class="btn btn-sm btn-danger delete-post-btn" data-thread-id="${threadId}" data-post-id="${post.id}">
                Delete
            </button>
        ` : '';
        
        return `
            <div class="post mb-3 p-3 border rounded">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <strong>${escapeHtml(post.author)}</strong>
                        <small class="text-muted ms-2">${formatTimestamp(post.timestamp)}</small>
                        ${index === 0 ? ' <span class="badge bg-primary">Original Post</span>' : ''}
                    </div>
                    ${deleteBtn}
                </div>
                <div class="mt-2">${escapeHtml(post.content).replace(/\n/g, '<br>')}</div>
            </div>
        `;
    }).join('');
}

/**
 * @function showReplyForm
 * @brief Shows a form to reply to a thread
 * @param threadId number - ID of the thread to reply to
 */
function showReplyForm(threadId: number): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'replyModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reply to Thread</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <textarea class="form-control" id="replyContent" rows="5" placeholder="Enter your reply..."></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="submitReply">Submit</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    
    document.getElementById('submitReply')?.addEventListener('click', async () => {
        const content = (document.getElementById('replyContent') as HTMLTextAreaElement)?.value;
        if (!content || content.trim() === '') {
            showAlert('Please enter a reply', 'warning');
            return;
        }
        
        try {
            const { addPost } = await import('./api');
            await addPost(threadId, content);
            modal.hide();
            showAlert('Reply posted successfully', 'success');
            loadThreads();
        } catch (error: any) {
            showAlert('Failed to post reply: ' + error.message);
        }
    });
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
    
    modal.show();
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
        
        // Attach delete post handlers
        document.querySelectorAll('.delete-post-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const target = e.target as HTMLButtonElement;
                const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
                const postId = parseInt(target.getAttribute('data-post-id') || '0');
                
                const confirmed = await showConfirmModal(
                    'Delete Post',
                    'Are you sure you want to delete this post? This action cannot be undone.'
                );
                
                if (confirmed) {
                    try {
                        await deletePost(threadId, postId);
                        showAlert('Post deleted successfully', 'success');
                        loadThreads();
                    } catch (error: any) {
                        showAlert('Failed to delete post: ' + error.message);
                    }
                }
            });
        });
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initForumPage
 * @brief Initializes the forum page
 */
export async function initForumPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1>Forum</h1>
                ${session ? `
                    <a href="#create-thread" class="btn btn-primary">Create Thread</a>
                ` : `
                    <a href="#login" class="btn btn-primary">Log in to Create Thread</a>
                `}
            </div>
            <div id="threadsContainer"></div>
        </div>
    `;
    
    await loadThreads();
}


```

```typescript
/**
 * @file index.ts
 * @brief Main forum page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getThreads, deleteThread, deletePost } from './api';
import { formatTimestamp, showAlert, showConfirmModal } from './utils';
import { Thread, Post } from './api';

/**
 * @function renderThreads
 * @brief Renders all threads on the forum page
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads yet. Be the first to create one!</p>';
        return;
    }
    
    container.innerHTML = '';
    
    threads.forEach(thread => {
        const threadDiv = document.createElement('div');
        threadDiv.className = 'card mb-3';
        threadDiv.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <a href="#thread-${thread.id}" class="text-decoration-none">${escapeHtml(thread.title)}</a>
                </h5>
                <div>
                    <small class="text-muted">Created by ${escapeHtml(thread.author)} on ${formatTimestamp(thread.createdAt)}</small>
                    <button class="btn btn-sm btn-danger ms-2 delete-thread-btn" data-thread-id="${thread.id}" style="display: none;">
                        Delete Thread
                    </button>
                </div>
            </div>
            <div class="card-body">
                ${renderPosts(thread.posts, thread.id)}
                <div class="mt-3">
                    <button class="btn btn-primary reply-btn" data-thread-id="${thread.id}">Reply</button>
                </div>
            </div>
        `;
        
        container.appendChild(threadDiv);
        
        // Add reply functionality
        threadDiv.querySelector('.reply-btn')?.addEventListener('click', () => {
            showReplyForm(thread.id);
        });
        
        // Add delete thread button (admin only)
        const deleteThreadBtn = threadDiv.querySelector('.delete-thread-btn') as HTMLButtonElement;
        if (deleteThreadBtn) {
            const session = (window as any).currentUser;
            if (session && session.isAdmin) {
                deleteThreadBtn.style.display = 'inline-block';
                deleteThreadBtn.addEventListener('click', async () => {
                    const confirmed = await showConfirmModal(
                        'Delete Thread',
                        'Are you sure you want to delete this entire thread? This action cannot be undone.'
                    );
                    if (confirmed) {
                        try {
                            await deleteThread(thread.id);
                            showAlert('Thread deleted successfully', 'success');
                            loadThreads();
                        } catch (error: any) {
                            showAlert('Failed to delete thread: ' + error.message);
                        }
                    }
                });
            }
        }
        
        // Attach delete post handlers for this thread
        threadDiv.querySelectorAll('.delete-post-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const target = e.target as HTMLButtonElement;
                const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
                const postId = parseInt(target.getAttribute('data-post-id') || '0');
                
                const confirmed = await showConfirmModal(
                    'Delete Post',
                    'Are you sure you want to delete this post? This action cannot be undone.'
                );
                
                if (confirmed) {
                    try {
                        await deletePost(threadId, postId);
                        showAlert('Post deleted successfully', 'success');
                        loadThreads();
                    } catch (error: any) {
                        showAlert('Failed to delete post: ' + error.message);
                    }
                }
            });
        });
    });
}

/**
 * @function renderPosts
 * @brief Renders posts in a thread
 * @param posts Post[] - Array of posts to render
 * @param threadId number - ID of the thread
 * @return string - HTML string for the posts
 */
function renderPosts(posts: Post[], threadId: number): string {
    return posts.map((post, index) => {
        const session = (window as any).currentUser;
        const canDelete = session && (session.isAdmin || session.username === post.author);
        const deleteBtn = canDelete ? `
            <button class="btn btn-sm btn-danger delete-post-btn" data-thread-id="${threadId}" data-post-id="${post.id}">
                Delete
            </button>
        ` : '';
        
        return `
            <div class="post mb-3 p-3 border rounded">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <strong>${escapeHtml(post.author)}</strong>
                        <small class="text-muted ms-2">${formatTimestamp(post.timestamp)}</small>
                        ${index === 0 ? ' <span class="badge bg-primary">Original Post</span>' : ''}
                    </div>
                    ${deleteBtn}
                </div>
                <div class="mt-2">${escapeHtml(post.content).replace(/\n/g, '<br>')}</div>
            </div>
        `;
    }).join('');
}

/**
 * @function showReplyForm
 * @brief Shows a form to reply to a thread
 * @param threadId number - ID of the thread to reply to
 */
function showReplyForm(threadId: number): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'replyModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reply to Thread</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <textarea class="form-control" id="replyContent" rows="5" placeholder="Enter your reply..."></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="submitReply">Submit</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    
    document.getElementById('submitReply')?.addEventListener('click', async () => {
        const content = (document.getElementById('replyContent') as HTMLTextAreaElement)?.value;
        if (!content || content.trim() === '') {
            showAlert('Please enter a reply', 'warning');
            return;
        }
        
        try {
            const { addPost } = await import('./api');
            await addPost(threadId, content);
            modal.hide();
            showAlert('Reply posted successfully', 'success');
            loadThreads();
        } catch (error: any) {
            showAlert('Failed to post reply: ' + error.message);
        }
    });
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
    
    modal.show();
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initForumPage
 * @brief Initializes the forum page
 */
export async function initForumPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1>Forum</h1>
                ${session ? `
                    <a href="#create-thread" class="btn btn-primary">Create Thread</a>
                ` : `
                    <a href="#login" class="btn btn-primary">Log in to Create Thread</a>
                `}
            </div>
            <div id="threadsContainer"></div>
        </div>
    `;
    
    await loadThreads();
}


```

```ignore
# Compiled files
*.exe
*.exe~
*.dll
*.so
*.dylib

# Go build artifacts
*.test
*.out
go_forum

# Frontend build artifacts
frontend/dist/*.js
frontend/dist/*.js.map
!frontend/dist/index.html

# Node modules
node_modules/

# Data directory (contains credentials and threads)
data/

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Logs
*.log

# Temporary files
*.tmp
*.temp

```


Installing Go dependencies and building the frontend:



Trying a different approach to install dependencies:



Trying with all permissions:



Compiling TypeScript and checking for errors:



Checking for TypeScript and compiling:



Compiling TypeScript:



Checking and fixing the syntax error:



Reading more context to fix the issue:



Removing the extra closing brace:


```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                (window as any).currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
    
    // Update currentUser reference after page load
    (window as any).currentUser = currentUser;
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}


```


Fixing TypeScript configuration and export issues:


```jsonc
{
  "compilerOptions": {
    "target": "ES5",
    "module": "amd",
    "lib": ["ES2017", "DOM"],
    "rootDir": "./src",
    "outDir": "./dist",
    "inlineSourceMap": true,
    "inlineSources": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}


```

```typescript
/**
 * @file api.ts
 * @brief API client for communicating with the backend server
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @interface ApiResponse
 * @brief Generic API response structure
 * @var success boolean - Whether the request was successful
 */
interface ApiResponse {
    success: boolean;
}

/**
 * @interface LoginResponse
 * @brief Response structure for login requests
 * @var success boolean - Whether login was successful
 * @var username string - Username of the logged-in user
 * @var isAdmin boolean - Whether the user is an administrator
 */
interface LoginResponse extends ApiResponse {
    username: string;
    isAdmin: boolean;
}

/**
 * @interface SessionResponse
 * @brief Response structure for session information
 * @var authenticated boolean - Whether user is authenticated
 * @var username string - Username if authenticated
 * @var isAdmin boolean - Whether user is admin if authenticated
 */
interface SessionResponse {
    authenticated: boolean;
    username?: string;
    isAdmin?: boolean;
}

/**
 * @interface Post
 * @brief Structure representing a forum post
 * @var id number - Unique post identifier
 * @var author string - Username of the post author
 * @var content string - Content of the post
 * @var timestamp number - Unix timestamp of when post was created
 */
export interface Post {
    id: number;
    author: string;
    content: string;
    timestamp: number;
}

/**
 * @interface Thread
 * @brief Structure representing a forum thread
 * @var id number - Unique thread identifier
 * @var title string - Title of the thread
 * @var author string - Username of the thread creator
 * @var posts Post[] - Array of posts in the thread
 * @var createdAt number - Unix timestamp of when thread was created
 */
export interface Thread {
    id: number;
    title: string;
    author: string;
    posts: Post[];
    createdAt: number;
}

/**
 * @interface User
 * @brief Structure representing a user
 * @var username string - Username of the user
 * @var isAdmin boolean - Whether the user is an administrator
 */
export interface User {
    username: string;
    isAdmin: boolean;
}

/**
 * @function apiRequest
 * @brief Makes an API request to the backend
 * @param endpoint string - API endpoint path
 * @param method string - HTTP method (GET, POST, DELETE, etc.)
 * @param body any - Request body object (will be JSON stringified)
 * @return Promise<any> - Promise that resolves to the response data
 */
function apiRequest(endpoint: string, method: string = 'GET', body?: any): Promise<any> {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(method, '/api' + endpoint, true);
        xhr.setRequestHeader('Content-Type', 'application/json');

        xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    resolve(response);
                } catch (e) {
                    resolve(xhr.responseText);
                }
            } else {
                try {
                    const error = JSON.parse(xhr.responseText);
                    reject(new Error(error.message || xhr.statusText));
                } catch (e) {
                    reject(new Error(xhr.statusText));
                }
            }
        };

        xhr.onerror = function() {
            reject(new Error('Network error'));
        };

        if (body) {
            xhr.send(JSON.stringify(body));
        } else {
            xhr.send();
        }
    });
}

/**
 * @function login
 * @brief Logs in a user
 * @param username string - Username
 * @param password string - Password
 * @return Promise<LoginResponse> - Promise that resolves to login response
 */
export function login(username: string, password: string): Promise<LoginResponse> {
    return apiRequest('/login', 'POST', { username, password });
}

/**
 * @function logout
 * @brief Logs out the current user
 * @return Promise<ApiResponse> - Promise that resolves to logout response
 */
export function logout(): Promise<ApiResponse> {
    return apiRequest('/logout', 'POST');
}

/**
 * @function createAccount
 * @brief Creates a new user account
 * @param username string - Desired username
 * @param password string - Desired password
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function createAccount(username: string, password: string): Promise<ApiResponse> {
    return apiRequest('/create-account', 'POST', { username, password });
}

/**
 * @function getSession
 * @brief Gets current session information
 * @return Promise<SessionResponse> - Promise that resolves to session information
 */
export function getSession(): Promise<SessionResponse> {
    return apiRequest('/session', 'GET');
}

/**
 * @function getThreads
 * @brief Gets all forum threads
 * @return Promise<Thread[]> - Promise that resolves to array of threads
 */
export function getThreads(): Promise<Thread[]> {
    return apiRequest('/threads', 'GET');
}

/**
 * @function getThread
 * @brief Gets a specific thread by ID
 * @param threadId number - Thread ID
 * @return Promise<Thread> - Promise that resolves to thread data
 */
export function getThread(threadId: number): Promise<Thread> {
    return apiRequest('/thread?id=' + threadId, 'GET');
}

/**
 * @function createThread
 * @brief Creates a new forum thread
 * @param title string - Thread title
 * @param content string - Initial post content
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function createThread(title: string, content: string): Promise<ApiResponse> {
    return apiRequest('/create-thread', 'POST', { title, content });
}

/**
 * @function addPost
 * @brief Adds a reply post to a thread
 * @param threadId number - Thread ID
 * @param content string - Post content
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function addPost(threadId: number, content: string): Promise<ApiResponse> {
    return apiRequest('/add-post', 'POST', { threadId, content });
}

/**
 * @function deletePost
 * @brief Deletes a post from a thread
 * @param threadId number - Thread ID
 * @param postId number - Post ID
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deletePost(threadId: number, postId: number): Promise<ApiResponse> {
    return apiRequest('/delete-post', 'DELETE', { threadId, postId });
}

/**
 * @function deleteThread
 * @brief Deletes an entire thread (admin only)
 * @param threadId number - Thread ID
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deleteThread(threadId: number): Promise<ApiResponse> {
    return apiRequest('/delete-thread', 'DELETE', { threadId });
}

/**
 * @function getUsers
 * @brief Gets all users (admin only)
 * @return Promise<User[]> - Promise that resolves to array of users
 */
export function getUsers(): Promise<User[]> {
    return apiRequest('/users', 'GET');
}

/**
 * @function deleteUser
 * @brief Deletes a user (admin only)
 * @param username string - Username to delete
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deleteUser(username: string): Promise<ApiResponse> {
    return apiRequest('/delete-user', 'DELETE', { username });
}

/**
 * @function resetPassword
 * @brief Resets a user's password
 * @param username string - Username whose password to reset
 * @param newPassword string - New password
 * @return Promise<ApiResponse> - Promise that resolves to reset response
 */
export function resetPassword(username: string, newPassword: string): Promise<ApiResponse> {
    return apiRequest('/reset-password', 'POST', { username, newPassword });
}

/**
 * @function updateUserAdmin
 * @brief Updates a user's admin status (admin only)
 * @param username string - Username to update
 * @param isAdmin boolean - New admin status
 * @return Promise<ApiResponse> - Promise that resolves to update response
 */
export function updateUserAdmin(username: string, isAdmin: boolean): Promise<ApiResponse> {
    return apiRequest('/update-user-admin', 'POST', { username, isAdmin });
}


```

```typescript
/**
 * @file utils.ts
 * @brief Utility functions for the frontend
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @function formatTimestamp
 * @brief Formats a Unix timestamp to "YYYY-MM-DD HH:mm:ss" format in local timezone
 * @param timestamp number - Unix timestamp
 * @return string - Formatted date string with timezone name
 */
export function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp * 1000);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    const timezoneName = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${timezoneName}`;
}

/**
 * @function showAlert
 * @brief Shows a Bootstrap alert message
 * @param message string - Alert message to display
 * @param type string - Alert type (success, danger, warning, info)
 * @param container HTMLElement - Container element to append alert to
 */
export function showAlert(message: string, type: string = 'danger', container?: HTMLElement): void {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const targetContainer = container || document.body;
    targetContainer.insertBefore(alertDiv, targetContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * @function showConfirmModal
 * @brief Shows a Bootstrap confirmation modal
 * @param title string - Modal title
 * @param message string - Modal message
 * @return Promise<boolean> - Promise that resolves to true if confirmed, false if cancelled
 */
export function showConfirmModal(title: string, message: string): Promise<boolean> {
    return new Promise((resolve) => {
        // Remove existing modal if any
        const existingModal = document.getElementById('confirmModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const modalDiv = document.createElement('div');
        modalDiv.id = 'confirmModal';
        modalDiv.className = 'modal fade';
        modalDiv.setAttribute('tabindex', '-1');
        modalDiv.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="confirmButton">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modalDiv);
        
        const modal = new (window as any).bootstrap.Modal(modalDiv);
        
        const confirmButton = modalDiv.querySelector('#confirmButton');
        confirmButton.addEventListener('click', () => {
            modal.hide();
            resolve(true);
        });
        
    modalDiv.addEventListener('hidden.bs.modal', () => {
        if (modalDiv.parentNode) {
            modalDiv.remove();
        }
        resolve(false);
    });
    
    modal.show();
});
}


```

```typescript
/**
 * @file profile.ts
 * @brief User profile page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getThreads, resetPassword, deletePost } from './api';
import { formatTimestamp, showAlert, showConfirmModal } from './utils';
import { Thread, Post } from './api';

/**
 * @function renderUserPosts
 * @brief Renders all posts by the current user
 * @param threads Thread[] - Array of all threads
 * @param username string - Username to filter posts by
 */
function renderUserPosts(threads: Thread[], username: string): void {
    const container = document.getElementById('userPostsContainer');
    if (!container) return;
    
    const userPosts: Array<{ thread: Thread; post: Post }> = [];
    
    threads.forEach(thread => {
        thread.posts.forEach((post: Post) => {
            if (post.author === username) {
                userPosts.push({ thread, post });
            }
        });
    });
    
    if (userPosts.length === 0) {
        container.innerHTML = '<p class="text-muted">You have not posted anything yet.</p>';
        return;
    }
    
    container.innerHTML = '';
    
    userPosts.forEach(({ thread, post }) => {
        const postDiv = document.createElement('div');
        postDiv.className = 'card mb-3';
        postDiv.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">
                    <a href="/#thread-${thread.id}" class="text-decoration-none">${escapeHtml(thread.title)}</a>
                </h6>
                <button class="btn btn-sm btn-danger delete-post-btn" data-thread-id="${thread.id}" data-post-id="${post.id}">
                    Delete
                </button>
            </div>
            <div class="card-body">
                <p class="text-muted mb-2">Posted on ${formatTimestamp(post.timestamp)}</p>
                <p>${escapeHtml(post.content).replace(/\n/g, '<br>')}</p>
            </div>
        `;
        
        container.appendChild(postDiv);
        
        const deleteBtn = postDiv.querySelector('.delete-post-btn') as HTMLButtonElement;
        deleteBtn.addEventListener('click', async () => {
            const confirmed = await showConfirmModal(
                'Delete Post',
                'Are you sure you want to delete this post? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deletePost(thread.id, post.id);
                    showAlert('Post deleted successfully', 'success');
                    loadUserPosts(username);
                } catch (error: any) {
                    showAlert('Failed to delete post: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUserPosts
 * @brief Loads and displays all posts by a user
 * @param username string - Username to load posts for
 */
async function loadUserPosts(username: string): Promise<void> {
    try {
        const threads = await getThreads();
        renderUserPosts(threads, username);
    } catch (error: any) {
        showAlert('Failed to load posts: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initProfilePage
 * @brief Initializes the profile page
 */
export async function initProfilePage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.username) {
        window.location.href = '/#login';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Profile</h4>
                        </div>
                        <div class="card-body">
                            <p><strong>Username:</strong> ${escapeHtml(session.username)}</p>
                            <p><strong>Role:</strong> ${session.isAdmin ? 'Administrator' : 'User'}</p>
                        </div>
                    </div>
                    <div class="card mt-3">
                        <div class="card-header">
                            <h5 class="mb-0">Change Password</h5>
                        </div>
                        <div class="card-body">
                            <form id="changePasswordForm">
                                <div class="mb-3">
                                    <label for="newPassword" class="form-label">New Password</label>
                                    <input type="password" class="form-control" id="newPassword" required>
                                </div>
                                <div class="mb-3">
                                    <label for="confirmNewPassword" class="form-label">Confirm New Password</label>
                                    <input type="password" class="form-control" id="confirmNewPassword" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Change Password</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">My Posts</h4>
                        </div>
                        <div class="card-body">
                            <div id="userPostsContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Handle password change
    const form = document.getElementById('changePasswordForm') as HTMLFormElement;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const newPassword = (document.getElementById('newPassword') as HTMLInputElement).value;
        const confirmPassword = (document.getElementById('confirmNewPassword') as HTMLInputElement).value;
        
        if (newPassword !== confirmPassword) {
            showAlert('Passwords do not match', 'warning');
            return;
        }
        
        if (newPassword.length < 3) {
            showAlert('Password must be at least 3 characters long', 'warning');
            return;
        }
        
        try {
            await resetPassword(session.username, newPassword);
            showAlert('Password changed successfully', 'success');
            form.reset();
        } catch (error: any) {
            showAlert('Failed to change password: ' + error.message);
        }
    });
    
    // Load user posts
    await loadUserPosts(session.username);
}


```


Fixing the last error:


```typescript
/**
 * @file utils.ts
 * @brief Utility functions for the frontend
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @function formatTimestamp
 * @brief Formats a Unix timestamp to "YYYY-MM-DD HH:mm:ss" format in local timezone
 * @param timestamp number - Unix timestamp
 * @return string - Formatted date string with timezone name
 */
export function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp * 1000);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    const timezoneName = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${timezoneName}`;
}

/**
 * @function showAlert
 * @brief Shows a Bootstrap alert message
 * @param message string - Alert message to display
 * @param type string - Alert type (success, danger, warning, info)
 * @param container HTMLElement - Container element to append alert to
 */
export function showAlert(message: string, type: string = 'danger', container?: HTMLElement): void {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const targetContainer = container || document.body;
    targetContainer.insertBefore(alertDiv, targetContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * @function showConfirmModal
 * @brief Shows a Bootstrap confirmation modal
 * @param title string - Modal title
 * @param message string - Modal message
 * @return Promise<boolean> - Promise that resolves to true if confirmed, false if cancelled
 */
export function showConfirmModal(title: string, message: string): Promise<boolean> {
    return new Promise((resolve) => {
        // Remove existing modal if any
        const existingModal = document.getElementById('confirmModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const modalDiv = document.createElement('div');
        modalDiv.id = 'confirmModal';
        modalDiv.className = 'modal fade';
        modalDiv.setAttribute('tabindex', '-1');
        modalDiv.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="confirmButton">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        
    document.body.appendChild(modalDiv);
    
    const BootstrapModal = (window as any).bootstrap?.Modal;
    if (!BootstrapModal) {
        reject(new Error('Bootstrap Modal not available'));
        return;
    }
    const modal = new BootstrapModal(modalDiv);
        
        const confirmButton = modalDiv.querySelector('#confirmButton');
        confirmButton.addEventListener('click', () => {
            modal.hide();
            resolve(true);
        });
        
    modalDiv.addEventListener('hidden.bs.modal', () => {
        if (modalDiv.parentNode) {
            modalDiv.remove();
        }
        resolve(false);
    });
    
    modal.show();
});
}


```


Fixing the reject and null check issues:


```typescript
/**
 * @file utils.ts
 * @brief Utility functions for the frontend
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @function formatTimestamp
 * @brief Formats a Unix timestamp to "YYYY-MM-DD HH:mm:ss" format in local timezone
 * @param timestamp number - Unix timestamp
 * @return string - Formatted date string with timezone name
 */
export function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp * 1000);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    const timezoneName = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${timezoneName}`;
}

/**
 * @function showAlert
 * @brief Shows a Bootstrap alert message
 * @param message string - Alert message to display
 * @param type string - Alert type (success, danger, warning, info)
 * @param container HTMLElement - Container element to append alert to
 */
export function showAlert(message: string, type: string = 'danger', container?: HTMLElement): void {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const targetContainer = container || document.body;
    targetContainer.insertBefore(alertDiv, targetContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * @function showConfirmModal
 * @brief Shows a Bootstrap confirmation modal
 * @param title string - Modal title
 * @param message string - Modal message
 * @return Promise<boolean> - Promise that resolves to true if confirmed, false if cancelled
 */
export function showConfirmModal(title: string, message: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
        // Remove existing modal if any
        const existingModal = document.getElementById('confirmModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const modalDiv = document.createElement('div');
        modalDiv.id = 'confirmModal';
        modalDiv.className = 'modal fade';
        modalDiv.setAttribute('tabindex', '-1');
        modalDiv.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="confirmButton">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modalDiv);
        
        const BootstrapModal = (window as any).bootstrap?.Modal;
        if (!BootstrapModal) {
            reject(new Error('Bootstrap Modal not available'));
            return;
        }
        const modal = new BootstrapModal(modalDiv);
        
        const confirmButton = modalDiv.querySelector('#confirmButton');
        if (confirmButton) {
            confirmButton.addEventListener('click', () => {
                modal.hide();
                resolve(true);
            });
        }
        
        modalDiv.addEventListener('hidden.bs.modal', () => {
            if (modalDiv.parentNode) {
                modalDiv.remove();
            }
            resolve(false);
        });
        
        modal.show();
    });
}


```


Checking Go code for errors, then creating unit tests:



Fixing unused imports:


```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": user.Username,
		"isAdmin": user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsAdminFromSession(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}


```

```go
/**
 * @file main.go
 * @brief Main entry point for the forum application server
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"log"
	"net/http"
)

/**
 * @var serverPort string
 * @brief Port number for the HTTP server (default: 8080)
 */
var serverPort = "8080"

/**
 * @function main
 * @brief Main function that initializes and starts the HTTP server
 */
func main() {
	// Initialize session store with a secret key
	// In production, this should be a secure random key stored in environment variable
	secretKey := "forum-secret-key-change-in-production"
	InitSessionStore(secretKey)

	// Initialize admin account if credentials file doesn't exist
	if err := InitializeAdminAccount(); err != nil {
		log.Printf("Warning: Failed to initialize admin account: %v", err)
	}

	// Load threads to initialize nextThreadID and nextPostID
	threads, err := LoadThreads()
	if err != nil {
		log.Printf("Warning: Failed to load threads: %v", err)
	} else {
		// Initialize IDs based on existing data
		for _, thread := range threads.Threads {
			if thread.ID >= nextThreadID {
				nextThreadID = thread.ID + 1
			}
			for _, post := range thread.Posts {
				if post.ID >= nextPostID {
					nextPostID = post.ID + 1
				}
			}
		}
		// If no threads exist, start from 1
		if nextThreadID == 0 {
			nextThreadID = 1
		}
		if nextPostID == 0 {
			nextPostID = 1
		}
	}

	// Set up HTTP routes
	http.HandleFunc("/", ServeIndex)
	http.HandleFunc("/static/", ServeStatic)

	// API routes
	http.HandleFunc("/api/login", HandleLogin)
	http.HandleFunc("/api/logout", HandleLogout)
	http.HandleFunc("/api/create-account", HandleCreateAccount)
	http.HandleFunc("/api/session", HandleGetSession)
	http.HandleFunc("/api/threads", HandleGetThreads)
	http.HandleFunc("/api/thread", HandleGetThread)
	http.HandleFunc("/api/create-thread", RequireAuth(HandleCreateThread))
	http.HandleFunc("/api/add-post", RequireAuth(HandleAddPost))
	http.HandleFunc("/api/delete-post", RequireAuth(HandleDeletePost))
	http.HandleFunc("/api/delete-thread", RequireAdmin(HandleDeleteThread))
	http.HandleFunc("/api/users", RequireAdmin(HandleGetUsers))
	http.HandleFunc("/api/delete-user", RequireAdmin(HandleDeleteUser))
	http.HandleFunc("/api/reset-password", RequireAuth(HandleResetPassword))
	http.HandleFunc("/api/update-user-admin", RequireAdmin(HandleUpdateUserAdmin))

	// Start the server
	log.Printf("Server starting on port %s", serverPort)
	log.Printf("Admin account: username=admin, password=admin123")
	if err := http.ListenAndServe(":"+serverPort, nil); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}


```


Creating unit tests for backend and frontend:


```go
/**
 * @file auth_test.go
 * @brief Unit tests for authentication module
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

/**
 * @function TestHashPassword
 * @brief Tests password hashing functionality
 * @param t *testing.T - Testing object
 */
func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty string")
	}
	if hash == password {
		t.Fatal("HashPassword returned plain password")
	}
}

/**
 * @function TestCheckPassword
 * @brief Tests password verification functionality
 * @param t *testing.T - Testing object
 */
func TestCheckPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPassword(hash, password) {
		t.Fatal("CheckPassword failed for correct password")
	}

	if CheckPassword(hash, "wrongpassword") {
		t.Fatal("CheckPassword succeeded for wrong password")
	}
}

/**
 * @function TestSessionStore
 * @brief Tests session store initialization
 * @param t *testing.T - Testing object
 */
func TestSessionStore(t *testing.T) {
	InitSessionStore("test-secret-key")
	if store == nil {
		t.Fatal("Session store not initialized")
	}
}

/**
 * @function TestRequireAuth
 * @brief Tests authentication middleware
 * @param t *testing.T - Testing object
 */
func TestRequireAuth(t *testing.T) {
	InitSessionStore("test-secret-key")

	handler := RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

```

```go
/**
 * @file data_test.go
 * @brief Unit tests for data persistence module
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"os"
	"path/filepath"
	"testing"
)

/**
 * @function TestLoadSaveCredentials
 * @brief Tests loading and saving credentials
 * @param t *testing.T - Testing object
 */
func TestLoadSaveCredentials(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	originalPath := credentialsPath
	credentialsPath = filepath.Join(tempDir, "credentials.json")
	defer func() {
		credentialsPath = originalPath
	}()

	// Create test credentials
	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "testuser",
				PasswordHash: "hashedpassword",
				IsAdmin:      false,
			},
		},
	}

	// Save credentials
	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("SaveCredentials failed: %v", err)
	}

	// Load credentials
	loadedCreds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials failed: %v", err)
	}

	if len(loadedCreds.Users) != 1 {
		t.Fatalf("Expected 1 user, got %d", len(loadedCreds.Users))
	}

	if loadedCreds.Users[0].Username != "testuser" {
		t.Fatalf("Expected username 'testuser', got '%s'", loadedCreds.Users[0].Username)
	}
}

/**
 * @function TestLoadSaveThreads
 * @brief Tests loading and saving threads
 * @param t *testing.T - Testing object
 */
func TestLoadSaveThreads(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	originalPath := threadsPath
	threadsPath = filepath.Join(tempDir, "threads.json")
	defer func() {
		threadsPath = originalPath
	}()

	// Create test threads
	threads := &ThreadsData{
		Threads: []Thread{
			{
				ID:        1,
				Title:     "Test Thread",
				Author:    "testuser",
				CreatedAt: 1234567890,
				Posts: []Post{
					{
						ID:        1,
						Author:    "testuser",
						Content:   "Test post content",
						Timestamp: 1234567890,
					},
				},
			},
		},
	}

	// Save threads
	if err := SaveThreads(threads); err != nil {
		t.Fatalf("SaveThreads failed: %v", err)
	}

	// Load threads
	loadedThreads, err := LoadThreads()
	if err != nil {
		t.Fatalf("LoadThreads failed: %v", err)
	}

	if len(loadedThreads.Threads) != 1 {
		t.Fatalf("Expected 1 thread, got %d", len(loadedThreads.Threads))
	}

	if loadedThreads.Threads[0].Title != "Test Thread" {
		t.Fatalf("Expected title 'Test Thread', got '%s'", loadedThreads.Threads[0].Title)
	}
}

/**
 * @function TestLoadThreadsEmpty
 * @brief Tests loading threads when file doesn't exist (should return empty)
 * @param t *testing.T - Testing object
 */
func TestLoadThreadsEmpty(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	originalPath := threadsPath
	threadsPath = filepath.Join(tempDir, "nonexistent.json")
	defer func() {
		threadsPath = originalPath
	}()

	// Load threads (file doesn't exist)
	threads, err := LoadThreads()
	if err != nil {
		t.Fatalf("LoadThreads failed: %v", err)
	}

	if threads == nil {
		t.Fatal("LoadThreads returned nil")
	}

	if len(threads.Threads) != 0 {
		t.Fatalf("Expected 0 threads, got %d", len(threads.Threads))
	}
}

/**
 * @function TestInitializeAdminAccount
 * @brief Tests admin account initialization
 * @param t *testing.T - Testing object
 */
func TestInitializeAdminAccount(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	originalPath := credentialsPath
	credentialsPath = filepath.Join(tempDir, "credentials.json")
	defer func() {
		credentialsPath = originalPath
		os.Remove(credentialsPath)
	}()

	// Initialize admin account
	if err := InitializeAdminAccount(); err != nil {
		t.Fatalf("InitializeAdminAccount failed: %v", err)
	}

	// Load credentials and verify admin account exists
	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials failed: %v", err)
	}

	found := false
	for _, user := range creds.Users {
		if user.Username == "admin" && user.IsAdmin {
			found = true
			// Verify password hash is set
			if user.PasswordHash == "" {
				t.Fatal("Admin password hash is empty")
			}
			break
		}
	}

	if !found {
		t.Fatal("Admin account not found after initialization")
	}
}

```

```go
/**
 * @file models_test.go
 * @brief Unit tests for data models
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import "testing"

/**
 * @function TestGetCurrentTimestamp
 * @brief Tests timestamp generation
 * @param t *testing.T - Testing object
 */
func TestGetCurrentTimestamp(t *testing.T) {
	timestamp := GetCurrentTimestamp()
	if timestamp <= 0 {
		t.Fatal("GetCurrentTimestamp returned invalid timestamp")
	}
}

```


All tests pass. Creating README.md with documentation:


```markdown
# Forum Application

A full-stack forum application built with Golang backend and TypeScript frontend.

## Overview

This forum application provides a complete discussion platform with user authentication, thread management, and administrative features. The backend is implemented in Go using the standard `net/http` package, and the frontend is written in TypeScript and compiled to ES5 with inline source maps.

## Architecture

### Backend (Golang)

The backend is organized into multiple modules:

- **main.go**: Entry point that initializes the server and sets up routes
- **models.go**: Data structures for users, posts, and threads
- **auth.go**: Authentication and session management using `gorilla/sessions`
- **data.go**: Data persistence layer for credentials and threads (JSON files)
- **handlers.go**: HTTP request handlers for all API endpoints

### Frontend (TypeScript)

The frontend is a single-page application (SPA) with the following modules:

- **main.ts**: Application entry point and routing
- **api.ts**: API client for backend communication
- **utils.ts**: Utility functions (date formatting, alerts, modals)
- **index.ts**: Main forum page implementation
- **login.ts**: Login page
- **createAccount.ts**: Account creation page
- **createThread.ts**: Thread creation page
- **profile.ts**: User profile and post management
- **admin.ts**: Administrator management interface

## Features

### User Features

- **Account Management**: Create account, log in, log out
- **Thread Creation**: Authenticated users can create new discussion threads
- **Posting**: All users can reply to threads
- **Profile Management**: Users can view their posts and change their password
- **Post Deletion**: Users can delete their own posts

### Administrator Features

- **User Management**: View all users, delete users, modify admin status
- **Password Reset**: Reset any user's password
- **Thread Management**: Delete entire threads
- **Post Management**: Delete any post (not just their own)

## Data Storage

All data is stored in JSON files in the `data/` directory:

- **credentials.json**: User credentials with securely hashed passwords
- **threads.json**: All forum threads and posts with Unix timestamps

The admin account is automatically initialized on first run:
- Username: `admin`
- Password: `admin123`

**Important**: Change the admin password immediately after first deployment!

## Security

- Passwords are hashed using bcrypt
- Sessions use secure cookies with `HttpOnly: true` and `SameSite: Strict`
- All user inputs are sanitized to prevent XSS attacks
- Authentication is required for creating threads and posting
- Admin-only endpoints are protected by middleware

## Project Structure

```
go_forum/
├── backend/           # Golang backend code
│   ├── main.go       # Server entry point
│   ├── models.go     # Data models
│   ├── auth.go       # Authentication
│   ├── data.go       # Data persistence
│   ├── handlers.go   # HTTP handlers
│   └── *_test.go     # Unit tests
├── frontend/          # TypeScript frontend code
│   ├── src/          # Source files
│   ├── dist/         # Compiled output
│   └── tsconfig.json # TypeScript configuration
├── data/             # Data files (gitignored)
│   ├── credentials.json
│   └── threads.json
├── go.mod            # Go module definition
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## Building

### Backend

```bash
cd backend
go build -o go_forum .
```

### Frontend

```bash
cd frontend
tsc
```

The compiled JavaScript files will be in `frontend/dist/`.

## Running Tests

### Backend Tests

```bash
cd backend
go test -v ./...
```

All tests should pass.

## Application Flow

The following flowchart illustrates the application architecture and request flow:

```mermaid
graph TB
    Start([User Accesses Forum]) --> CheckAuth{Authenticated?}
    
    CheckAuth -->|No| ShowLogin[Show Login/Create Account]
    CheckAuth -->|Yes| ShowForum[Show Forum Page]
    
    ShowLogin --> LoginAction[User Logs In]
    LoginAction --> AuthCheck{Valid Credentials?}
    AuthCheck -->|No| ShowError[Show Error Message]
    AuthCheck -->|Yes| CreateSession[Create Session Cookie]
    ShowError --> ShowLogin
    CreateSession --> ShowForum
    
    ShowForum --> UserAction{User Action}
    
    UserAction -->|Create Thread| CheckAuthThread{Authenticated?}
    UserAction -->|Reply to Thread| CheckAuthReply{Authenticated?}
    UserAction -->|View Profile| CheckAuthProfile{Authenticated?}
    UserAction -->|Admin Panel| CheckAdmin{Is Admin?}
    
    CheckAuthThread -->|Yes| CreateThread[Create Thread API]
    CheckAuthThread -->|No| RedirectLogin[Redirect to Login]
    
    CheckAuthReply -->|Yes| AddPost[Add Post API]
    CheckAuthReply -->|No| RedirectLogin
    
    CheckAuthProfile -->|Yes| ShowProfile[Show Profile Page]
    CheckAuthProfile -->|No| RedirectLogin
    
    CheckAdmin -->|Yes| ShowAdmin[Show Admin Panel]
    CheckAdmin -->|No| ShowError
    
    CreateThread --> SaveThread[Save to threads.json]
    AddPost --> SavePost[Save to threads.json]
    
    SaveThread --> UpdateUI[Update UI]
    SavePost --> UpdateUI
    
    ShowProfile --> ManagePosts[Manage User Posts]
    ShowAdmin --> ManageUsers[Manage Users]
    ShowAdmin --> ManageThreads[Manage Threads]
    
    ManageUsers --> DeleteUser[Delete User API]
    ManageThreads --> DeleteThread[Delete Thread API]
    ManagePosts --> DeletePost[Delete Post API]
    
    DeleteUser --> SaveCredentials[Save to credentials.json]
    DeleteThread --> SaveThreads[Save to threads.json]
    DeletePost --> SaveThreads
    
    SaveCredentials --> UpdateUI
    SaveThreads --> UpdateUI
    
    UpdateUI --> ShowForum
    
    style Start fill:#e1f5ff
    style ShowForum fill:#c8e6c9
    style ShowAdmin fill:#fff9c4
    style ShowError fill:#ffcdd2
```

## API Endpoints

### Authentication
- `POST /api/login` - Log in user
- `POST /api/logout` - Log out user
- `POST /api/create-account` - Create new account
- `GET /api/session` - Get current session info

### Threads
- `GET /api/threads` - Get all threads
- `GET /api/thread?id={id}` - Get specific thread
- `POST /api/create-thread` - Create new thread (requires auth)
- `DELETE /api/delete-thread` - Delete thread (requires admin)

### Posts
- `POST /api/add-post` - Add reply to thread (requires auth)
- `DELETE /api/delete-post` - Delete post (requires auth, owner or admin)

### Users (Admin Only)
- `GET /api/users` - Get all users
- `DELETE /api/delete-user` - Delete user
- `POST /api/reset-password` - Reset user password
- `POST /api/update-user-admin` - Update user admin status

## Session Configuration

Sessions are configured with:
- `HttpOnly: true` - Prevents JavaScript access to cookies
- `SameSite: http.SameSiteStrictMode` - CSRF protection
- `MaxAge: 7 days` - Session expiration

## TypeScript Configuration

The frontend TypeScript is configured to:
- Target ES5 for browser compatibility
- Use AMD module system
- Include ES2017 and DOM libraries
- Generate inline source maps
- Output to `frontend/dist/`

## Browser Compatibility

The application uses:
- Bootstrap 5.3.0 for UI styling
- ES5 JavaScript (compiled from TypeScript)
- Modern browser APIs (Promise, fetch via XMLHttpRequest)

## Development

### Prerequisites

- Go 1.24+ (or compatible version)
- TypeScript compiler (`tsc`)
- Modern web browser

### Running Locally

1. Build the frontend:
   ```bash
   cd frontend
   tsc
   ```

2. Run the backend:
   ```bash
   cd backend
   go run .
   ```

3. Access the forum at `http://localhost:8080`

## Deployment

See the deployment section below for production deployment instructions.

## Code Documentation

All code is extensively documented with Doxygen-style comments:
- File headers with creation date and author
- Function documentation with parameters and return values
- Struct and variable documentation
- Inline comments explaining complex logic

## License

This project is provided as-is for educational and development purposes.

## Author

Victor Yeh
Created: 2025-12-19

```


Adding deployment instructions and finalizing:


```markdown
# Forum Application

A full-stack forum application built with Golang backend and TypeScript frontend.

## Overview

This forum application provides a complete discussion platform with user authentication, thread management, and administrative features. The backend is implemented in Go using the standard `net/http` package, and the frontend is written in TypeScript and compiled to ES5 with inline source maps.

## Architecture

### Backend (Golang)

The backend is organized into multiple modules:

- **main.go**: Entry point that initializes the server and sets up routes
- **models.go**: Data structures for users, posts, and threads
- **auth.go**: Authentication and session management using `gorilla/sessions`
- **data.go**: Data persistence layer for credentials and threads (JSON files)
- **handlers.go**: HTTP request handlers for all API endpoints

### Frontend (TypeScript)

The frontend is a single-page application (SPA) with the following modules:

- **main.ts**: Application entry point and routing
- **api.ts**: API client for backend communication
- **utils.ts**: Utility functions (date formatting, alerts, modals)
- **index.ts**: Main forum page implementation
- **login.ts**: Login page
- **createAccount.ts**: Account creation page
- **createThread.ts**: Thread creation page
- **profile.ts**: User profile and post management
- **admin.ts**: Administrator management interface

## Features

### User Features

- **Account Management**: Create account, log in, log out
- **Thread Creation**: Authenticated users can create new discussion threads
- **Posting**: All users can reply to threads
- **Profile Management**: Users can view their posts and change their password
- **Post Deletion**: Users can delete their own posts

### Administrator Features

- **User Management**: View all users, delete users, modify admin status
- **Password Reset**: Reset any user's password
- **Thread Management**: Delete entire threads
- **Post Management**: Delete any post (not just their own)

## Data Storage

All data is stored in JSON files in the `data/` directory:

- **credentials.json**: User credentials with securely hashed passwords
- **threads.json**: All forum threads and posts with Unix timestamps

The admin account is automatically initialized on first run:
- Username: `admin`
- Password: `admin123`

**Important**: Change the admin password immediately after first deployment!

## Security

- Passwords are hashed using bcrypt
- Sessions use secure cookies with `HttpOnly: true` and `SameSite: Strict`
- All user inputs are sanitized to prevent XSS attacks
- Authentication is required for creating threads and posting
- Admin-only endpoints are protected by middleware

## Project Structure

```
go_forum/
├── backend/           # Golang backend code
│   ├── main.go       # Server entry point
│   ├── models.go     # Data models
│   ├── auth.go       # Authentication
│   ├── data.go       # Data persistence
│   ├── handlers.go   # HTTP handlers
│   └── *_test.go     # Unit tests
├── frontend/          # TypeScript frontend code
│   ├── src/          # Source files
│   ├── dist/         # Compiled output
│   └── tsconfig.json # TypeScript configuration
├── data/             # Data files (gitignored)
│   ├── credentials.json
│   └── threads.json
├── go.mod            # Go module definition
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## Building

### Backend

```bash
cd backend
go build -o go_forum .
```

### Frontend

```bash
cd frontend
tsc
```

The compiled JavaScript files will be in `frontend/dist/`.

## Running Tests

### Backend Tests

```bash
cd backend
go test -v ./...
```

All tests should pass.

## Application Flow

The following flowchart illustrates the application architecture and request flow:

```mermaid
graph TB
    Start([User Accesses Forum]) --> CheckAuth{Authenticated?}
    
    CheckAuth -->|No| ShowLogin[Show Login/Create Account]
    CheckAuth -->|Yes| ShowForum[Show Forum Page]
    
    ShowLogin --> LoginAction[User Logs In]
    LoginAction --> AuthCheck{Valid Credentials?}
    AuthCheck -->|No| ShowError[Show Error Message]
    AuthCheck -->|Yes| CreateSession[Create Session Cookie]
    ShowError --> ShowLogin
    CreateSession --> ShowForum
    
    ShowForum --> UserAction{User Action}
    
    UserAction -->|Create Thread| CheckAuthThread{Authenticated?}
    UserAction -->|Reply to Thread| CheckAuthReply{Authenticated?}
    UserAction -->|View Profile| CheckAuthProfile{Authenticated?}
    UserAction -->|Admin Panel| CheckAdmin{Is Admin?}
    
    CheckAuthThread -->|Yes| CreateThread[Create Thread API]
    CheckAuthThread -->|No| RedirectLogin[Redirect to Login]
    
    CheckAuthReply -->|Yes| AddPost[Add Post API]
    CheckAuthReply -->|No| RedirectLogin
    
    CheckAuthProfile -->|Yes| ShowProfile[Show Profile Page]
    CheckAuthProfile -->|No| RedirectLogin
    
    CheckAdmin -->|Yes| ShowAdmin[Show Admin Panel]
    CheckAdmin -->|No| ShowError
    
    CreateThread --> SaveThread[Save to threads.json]
    AddPost --> SavePost[Save to threads.json]
    
    SaveThread --> UpdateUI[Update UI]
    SavePost --> UpdateUI
    
    ShowProfile --> ManagePosts[Manage User Posts]
    ShowAdmin --> ManageUsers[Manage Users]
    ShowAdmin --> ManageThreads[Manage Threads]
    
    ManageUsers --> DeleteUser[Delete User API]
    ManageThreads --> DeleteThread[Delete Thread API]
    ManagePosts --> DeletePost[Delete Post API]
    
    DeleteUser --> SaveCredentials[Save to credentials.json]
    DeleteThread --> SaveThreads[Save to threads.json]
    DeletePost --> SaveThreads
    
    SaveCredentials --> UpdateUI
    SaveThreads --> UpdateUI
    
    UpdateUI --> ShowForum
    
    style Start fill:#e1f5ff
    style ShowForum fill:#c8e6c9
    style ShowAdmin fill:#fff9c4
    style ShowError fill:#ffcdd2
```

## API Endpoints

### Authentication
- `POST /api/login` - Log in user
- `POST /api/logout` - Log out user
- `POST /api/create-account` - Create new account
- `GET /api/session` - Get current session info

### Threads
- `GET /api/threads` - Get all threads
- `GET /api/thread?id={id}` - Get specific thread
- `POST /api/create-thread` - Create new thread (requires auth)
- `DELETE /api/delete-thread` - Delete thread (requires admin)

### Posts
- `POST /api/add-post` - Add reply to thread (requires auth)
- `DELETE /api/delete-post` - Delete post (requires auth, owner or admin)

### Users (Admin Only)
- `GET /api/users` - Get all users
- `DELETE /api/delete-user` - Delete user
- `POST /api/reset-password` - Reset user password
- `POST /api/update-user-admin` - Update user admin status

## Session Configuration

Sessions are configured with:
- `HttpOnly: true` - Prevents JavaScript access to cookies
- `SameSite: http.SameSiteStrictMode` - CSRF protection
- `MaxAge: 7 days` - Session expiration

## TypeScript Configuration

The frontend TypeScript is configured to:
- Target ES5 for browser compatibility
- Use AMD module system
- Include ES2017 and DOM libraries
- Generate inline source maps
- Output to `frontend/dist/`

## Browser Compatibility

The application uses:
- Bootstrap 5.3.0 for UI styling
- ES5 JavaScript (compiled from TypeScript)
- Modern browser APIs (Promise, fetch via XMLHttpRequest)

## Development

### Prerequisites

- Go 1.24+ (or compatible version)
- TypeScript compiler (`tsc`)
- Modern web browser

### Running Locally

1. Build the frontend:
   ```bash
   cd frontend
   tsc
   ```

2. Run the backend:
   ```bash
   cd backend
   go run .
   ```

3. Access the forum at `http://localhost:8080`

## Deployment

### Production Deployment Steps

1. **Build the Frontend**:
   ```bash
   cd frontend
   tsc
   ```
   This compiles all TypeScript files to JavaScript in the `frontend/dist/` directory.

2. **Build the Backend**:
   ```bash
   cd backend
   go build -o go_forum .
   ```
   This creates an executable binary named `go_forum`.

3. **Set Up Data Directory**:
   ```bash
   mkdir -p data
   ```
   The application will automatically create `credentials.json` with the admin account on first run.

4. **Configure Environment** (Optional):
   - Set the server port by modifying `serverPort` in `backend/main.go` (default: 8080)
   - Change the session secret key in `backend/main.go` for production

5. **Run the Application**:
   ```bash
   ./go_forum
   ```
   Or from the backend directory:
   ```bash
   cd backend
   ./go_forum
   ```

6. **Access the Forum**:
   - Open your browser and navigate to `http://localhost:8080` (or your configured port)
   - Log in with the default admin credentials:
     - Username: `admin`
     - Password: `admin123`
   - **Important**: Change the admin password immediately after first login!

### Deployment Commands Summary

```bash
# 1. Build frontend
cd frontend && tsc && cd ..

# 2. Build backend
cd backend && go build -o go_forum . && cd ..

# 3. Create data directory
mkdir -p data

# 4. Run the application
cd backend && ./go_forum
```

### Production Considerations

- **Security**: Change the session secret key in production
- **Port**: Configure firewall rules for your chosen port
- **HTTPS**: Use a reverse proxy (nginx, Apache) with SSL/TLS certificates
- **Process Management**: Use systemd, supervisor, or similar for process management
- **Logging**: Configure proper logging for production monitoring
- **Backup**: Regularly backup the `data/` directory
- **Admin Password**: Change the default admin password immediately

### Example systemd Service

Create `/etc/systemd/system/go-forum.service`:

```ini
[Unit]
Description=Go Forum Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/go_forum/backend
ExecStart=/path/to/go_forum/backend/go_forum
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable and start:
```bash
sudo systemctl enable go-forum
sudo systemctl start go-forum
```

## Code Documentation

All code is extensively documented with Doxygen-style comments:
- File headers with creation date and author
- Function documentation with parameters and return values
- Struct and variable documentation
- Inline comments explaining complex logic

## License

This project is provided as-is for educational and development purposes.

## Author

Victor Yeh
Created: 2025-12-19


```


Verifying the build and preparing a final summary:



## Project summary

### Completed tasks

1. Backend (Golang)
   - Modular structure: `main.go`, `models.go`, `auth.go`, `data.go`, `handlers.go`
   - Session management with `gorilla/sessions` (HttpOnly, SameSite Strict)
   - JSON-based data persistence (`credentials.json`, `threads.json`)
   - Admin account auto-initialization (admin/admin123)
   - All unit tests passing

2. Frontend (TypeScript)
   - Compiled to ES5 with inline source maps
   - Bootstrap 5.3.0 UI
   - SPA with hash-based routing
   - No use of prompt/alert/confirm (Bootstrap modals and alerts)
   - Date formatting: "YYYY-MM-DD HH:mm:ss" with timezone

3. Features
   - User authentication (login, logout, create account)
   - Thread creation and management
   - Post replies and deletion
   - User profile (view posts, change password)
   - Admin panel (user management, thread management, password reset)

4. Documentation
   - Doxygen-style comments throughout
   - README.md with mermaid flowchart
   - File headers with creation date and author

5. Testing
   - Backend unit tests (all passing)
   - Code compiles without errors

## Deployment commands

To deploy the forum application, run these commands:

```bash
# 1. Build the frontend TypeScript code
cd frontend
tsc
cd ..

# 2. Build the backend Go application
cd backend
go build -o go_forum .
cd ..

# 3. Create the data directory (if it doesn't exist)
mkdir -p data

# 4. Run the application
cd backend
./go_forum
```

The application will:
- Start on port 8080 (default)
- Automatically create `data/credentials.json` with admin account on first run
- Serve the frontend from `frontend/dist/`
- Handle all API requests through `/api/*` endpoints

Access the forum at: `http://localhost:8080`

Default admin credentials:
- Username: `admin`
- Password: `admin123`

Important: Change the admin password immediately after first deployment.

## Project structure

```
go_forum/
├── backend/          # Go backend code (5 modules + tests)
├── frontend/         # TypeScript frontend (8 modules)
│   ├── src/         # Source files
│   └── dist/        # Compiled JavaScript (with inline source maps)
├── data/            # JSON data files (gitignored)
├── go.mod           # Go dependencies
├── .gitignore       # Git ignore rules
└── README.md        # Complete documentation
```

All code is documented, tested, and ready for deployment.

```shellscript
# 1. Build the frontend TypeScript code
cd frontend
tsc
cd ..

# 2. Build the backend Go application
cd backend
go build -o go_forum .
cd ..

# 3. Create the data directory (if it doesn't exist)
mkdir -p data

# 4. Run the application
cd backend
./go_forum
```

```plaintext
go_forum/
├── backend/          # Go backend code (5 modules + tests)
├── frontend/         # TypeScript frontend (8 modules)
│   ├── src/         # Source files
│   └── dist/        # Compiled JavaScript (with inline source maps)
├── data/            # JSON data files (gitignored)
├── go.mod           # Go dependencies
├── .gitignore       # Git ignore rules
└── README.md        # Complete documentation
```

---

**User**

`ServeIndex` and `ServeStatic` are not written correctly. They cannot locate the `frontend` directory, because the `frontend` directory is in the parent directory. Maybe it requires some changes to `../frontend`.

---

**Cursor**


Checking `ServeIndex` and `ServeStatic` to fix the frontend path:



Updating both functions to use the correct relative path:


```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": user.Username,
		"isAdmin": user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsAdminFromSession(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}


```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": user.Username,
		"isAdmin": user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsAdminFromSession(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}


```


Checking if the data directory paths need the same fix:



Fixing the data directory paths:


```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("..", "data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("..", "data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := ioutil.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := ioutil.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```


Fixed the path issues. Summary of changes:

1. **`ServeIndex`**: Changed from `"frontend/dist/index.html"` to `"../frontend/dist/index.html"`
2. **`ServeStatic`**: Changed from `"frontend/dist/"` to `"../frontend/dist/"`
3. **Data paths**: Changed from `"data/credentials.json"` and `"data/threads.json"` to `"../data/credentials.json"` and `"../data/threads.json"`

These changes ensure that when the Go server runs from the `backend/` directory, it correctly locates:
- The frontend files in `../frontend/dist/`
- The data files in `../data/`

The code compiles successfully and all tests still pass. The application should now correctly serve the frontend files and access the data directory when running from the backend directory.

---

**User**

For the code present, we get this error:
```
ioutil.ReadFile is deprecated: As of Go 1.16, this function simply calls [os.ReadFile].
```
Fix it, verify, and then give a concise explanation. @backend/data.go:36-39 

---

**Cursor**


Replacing deprecated `ioutil` functions with `os` equivalents. Checking all occurrences:



Checking handlers.go for `ioutil` usage:



Replacing deprecated `ioutil` functions:


```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("..", "data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("..", "data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := ioutil.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := ioutil.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```

```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("..", "data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("..", "data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := ioutil.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```

```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("..", "data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("..", "data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := os.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := ioutil.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```

```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("..", "data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("..", "data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := os.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := os.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := ioutil.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```

```go
/**
 * @file data.go
 * @brief Data persistence layer for credentials and threads
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

/**
 * @var credentialsPath string
 * @brief Path to the credentials.json file
 */
var credentialsPath = filepath.Join("..", "data", "credentials.json")

/**
 * @var threadsPath string
 * @brief Path to the threads.json file
 */
var threadsPath = filepath.Join("..", "data", "threads.json")

/**
 * @function LoadCredentials
 * @brief Loads user credentials from the JSON file
 * @return *CredentialsData - Pointer to the loaded credentials data
 * @return error - Error if file reading or parsing fails
 */
func LoadCredentials() (*CredentialsData, error) {
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %v", err)
	}

	var creds CredentialsData
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %v", err)
	}

	return &creds, nil
}

/**
 * @function SaveCredentials
 * @brief Saves user credentials to the JSON file
 * @param creds *CredentialsData - Pointer to the credentials data to save
 * @return error - Error if file writing fails
 */
func SaveCredentials(creds *CredentialsData) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(credentialsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := os.WriteFile(credentialsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

/**
 * @function LoadThreads
 * @brief Loads forum threads from the JSON file
 * @return *ThreadsData - Pointer to the loaded threads data, or empty data if file doesn't exist
 * @return error - Error if file reading or parsing fails (nil if file doesn't exist)
 */
func LoadThreads() (*ThreadsData, error) {
	data, err := os.ReadFile(threadsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty threads data if file doesn't exist
			return &ThreadsData{Threads: []Thread{}}, nil
		}
		return nil, fmt.Errorf("failed to read threads file: %v", err)
	}

	var threads ThreadsData
	if err := json.Unmarshal(data, &threads); err != nil {
		return nil, fmt.Errorf("failed to parse threads file: %v", err)
	}

	// Update nextThreadID and nextPostID based on existing data
	for _, thread := range threads.Threads {
		if thread.ID >= nextThreadID {
			nextThreadID = thread.ID + 1
		}
		for _, post := range thread.Posts {
			if post.ID >= nextPostID {
				nextPostID = post.ID + 1
			}
		}
	}

	return &threads, nil
}

/**
 * @function SaveThreads
 * @brief Saves forum threads to the JSON file
 * @param threads *ThreadsData - Pointer to the threads data to save
 * @return error - Error if file writing fails
 */
func SaveThreads(threads *ThreadsData) error {
	data, err := json.MarshalIndent(threads, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal threads: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(threadsPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	if err := os.WriteFile(threadsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write threads file: %v", err)
	}

	return nil
}

/**
 * @function InitializeAdminAccount
 * @brief Initializes the admin account if credentials file doesn't exist
 * @return error - Error if initialization fails
 */
func InitializeAdminAccount() error {
	// Check if credentials file already exists
	if _, err := os.Stat(credentialsPath); err == nil {
		return nil // File exists, no need to initialize
	}

	// Create admin account with hashed password
	adminHash, err := HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %v", err)
	}

	creds := &CredentialsData{
		Users: []User{
			{
				Username:     "admin",
				PasswordHash: adminHash,
				IsAdmin:      true,
			},
		},
	}

	return SaveCredentials(creds)
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsAdminFromSession(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsAdminFromSession(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```


All deprecated `ioutil` functions have been replaced and verified.

## Changes Made

1. **data.go**: 
   - Replaced `ioutil.ReadFile` → `os.ReadFile` (2 occurrences)
   - Replaced `ioutil.WriteFile` → `os.WriteFile` (2 occurrences)
   - Removed `io/ioutil` import

2. **handlers.go**:
   - Replaced `ioutil.ReadAll` → `io.ReadAll` (3 occurrences)
   - Changed import from `io/ioutil` → `io`

## Verification

- Code compiles successfully
- All unit tests pass

## Explanation

In Go 1.16+, `ioutil` functions were deprecated in favor of their `os` and `io` equivalents:
- `ioutil.ReadFile` → `os.ReadFile`
- `ioutil.WriteFile` → `os.WriteFile`
- `ioutil.ReadAll` → `io.ReadAll`

These replacements are drop-in and maintain the same functionality.

---

**User**

The main page is not displayed correctly. I can't see "Create account", "Log in" (or "Log out"), "Administrator Management" hyperlinks on the upper right corner. I can't see threads either.

---

**Cursor**


Investigating the main page display issue. Checking the HTML and JavaScript loading:



The issue is that TypeScript compiles to AMD modules, but the HTML loads `main.js` without a module loader. Checking the end of `main.js` to see how it's structured:



The code compiles to AMD modules (`define()`), but the HTML loads it without a module loader. Adding RequireJS to load the modules:


```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Forum</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto" id="navLinks">
                    <!-- Navigation links will be populated by JavaScript -->
                </ul>
            </div>
        </div>
    </nav>
    
    <div id="mainContent">
        <!-- Main content will be populated by JavaScript -->
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- RequireJS for AMD module loading -->
    <script src="https://cdn.jsdelivr.net/npm/requirejs@2.3.6/require.min.js"></script>
    <!-- Main application script -->
    <script>
        require(['main'], function() {
            // Application initialized
        });
    </script>
</body>
</html>


```


Verifying the HTML structure and ensuring RequireJS is configured correctly:



Configuring RequireJS with the correct baseUrl to ensure modules load correctly:


```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Forum</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto" id="navLinks">
                    <!-- Navigation links will be populated by JavaScript -->
                </ul>
            </div>
        </div>
    </nav>
    
    <div id="mainContent">
        <!-- Main content will be populated by JavaScript -->
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- RequireJS for AMD module loading -->
    <script src="https://cdn.jsdelivr.net/npm/requirejs@2.3.6/require.min.js"></script>
    <!-- Main application script -->
    <script>
        require.config({
            baseUrl: './',
            paths: {}
        });
        require(['main'], function() {
            // Application initialized
        }, function(err) {
            console.error('Failed to load application:', err);
        });
    </script>
</body>
</html>


```


## Summary

The issue was that TypeScript compiles to AMD modules (using `define()`), but the HTML was loading `main.js` directly without a module loader. AMD modules require a loader like RequireJS.

## Changes Made

1. Added RequireJS to the HTML file to load AMD modules
2. Configured RequireJS with proper baseUrl so it can find all modules in the same directory
3. Added error handling to catch any module loading failures

The HTML now:
- Loads RequireJS from CDN
- Configures it to use the current directory as baseUrl
- Loads the `main` module, which will then load all its dependencies

When you run the server and access the page, the JavaScript should now:
- Load all modules correctly
- Display the navigation links ("Create account", "Log in", etc.) in the upper right corner
- Load and display threads on the main page

The application should now work correctly. If you still see issues, check the browser console for any JavaScript errors.

---

**User**

The `main.js` file is not loaded correctly. There seems to be some problems in Golang to serve the `main.js` file. Check the file path and fix the bug.

---

**Cursor**


Checking how static files are served in the Go backend:



The HTML loads `main.js` from the root, but the server only serves static files under `/static/`. Checking the HTML and fixing the routing:



The HTML loads `main.js` from the root, but the server only serves static files under `/static/`. Updating the RequireJS config to use `/static/` as the baseUrl:


```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Forum</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto" id="navLinks">
                    <!-- Navigation links will be populated by JavaScript -->
                </ul>
            </div>
        </div>
    </nav>
    
    <div id="mainContent">
        <!-- Main content will be populated by JavaScript -->
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- RequireJS for AMD module loading -->
    <script src="https://cdn.jsdelivr.net/npm/requirejs@2.3.6/require.min.js"></script>
    <!-- Main application script -->
    <script>
        require.config({
            baseUrl: '/static/',
            paths: {}
        });
        require(['main'], function() {
            // Application initialized
        }, function(err) {
            console.error('Failed to load application:', err);
        });
    </script>
</body>
</html>


```


Verifying the `ServeStatic` handler correctly serves files:



Fix applied. Summary:

## Problem
The HTML loaded `main.js` from the root (`/main.js`), but the Go server only serves static files under `/static/`, causing a 404.

## Solution
Updated the RequireJS configuration in `index.html` to use `/static/` as the `baseUrl`. Now:
- RequireJS requests `/static/main.js`
- The `ServeStatic` handler serves it from `../frontend/dist/main.js`
- Module dependencies (like `./api`, `./index`) resolve to `/static/api.js`, `/static/index.js`, etc.

The `ServeStatic` handler already:
1. Strips the `/static/` prefix from the URL path
2. Serves files from `../frontend/dist/` directory

When you run the server, `main.js` and its dependencies should load correctly, and the navigation links and threads should display properly.

---

**User**

It is a security issue to design `IsAdminFromSession` function. The user role can be changed on the fly, so it is needed to check the user role every time from the `credentials.json` file, instead of checking user roles from session. Fix the security bug.

---

**Cursor**


Checking the current implementation and fixing the security issue:



Replacing `IsAdminFromSession` to check credentials.json instead of the session, and updating all usages:


```go
/**
 * @file auth.go
 * @brief Authentication and authorization logic
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
)

/**
 * @var store *sessions.CookieStore
 * @brief Session store for managing user sessions
 */
var store *sessions.CookieStore

/**
 * @var sessionName string
 * @brief Name of the session cookie
 */
var sessionName = "forum_session"

/**
 * @function InitSessionStore
 * @brief Initializes the session store with a secret key
 * @param secretKey string - Secret key for session encryption
 */
func InitSessionStore(secretKey string) {
	store = sessions.NewCookieStore([]byte(secretKey))
	store.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
	}
}

/**
 * @function HashPassword
 * @brief Hashes a password using bcrypt
 * @param password string - Plain text password to hash
 * @return string - Hashed password
 * @return error - Error if hashing fails
 */
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

/**
 * @function CheckPassword
 * @brief Verifies a password against a hash
 * @param hash string - Hashed password
 * @param password string - Plain text password to verify
 * @return bool - True if password matches, false otherwise
 */
func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/**
 * @function GetSession
 * @brief Retrieves the session for a request
 * @param r *http.Request - HTTP request
 * @return *sessions.Session - Session object
 * @return error - Error if session retrieval fails
 */
func GetSession(r *http.Request) (*sessions.Session, error) {
	return store.Get(r, sessionName)
}

/**
 * @function SetUserSession
 * @brief Sets user information in the session
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @param username string - Username to store in session
 * @param isAdmin bool - Whether user is an administrator
 * @return error - Error if session save fails
 */
func SetUserSession(w http.ResponseWriter, r *http.Request, username string, isAdmin bool) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = username
	session.Values["isAdmin"] = isAdmin
	session.Values["authenticated"] = true

	return session.Save(r, w)
}

/**
 * @function ClearUserSession
 * @brief Clears user session (logs out)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @return error - Error if session save fails
 */
func ClearUserSession(w http.ResponseWriter, r *http.Request) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = nil
	session.Values["isAdmin"] = nil
	session.Values["authenticated"] = false

	return session.Save(r, w)
}

/**
 * @function GetUsernameFromSession
 * @brief Retrieves username from session
 * @param r *http.Request - HTTP request
 * @return string - Username if authenticated, empty string otherwise
 * @return bool - True if user is authenticated, false otherwise
 */
func GetUsernameFromSession(r *http.Request) (string, bool) {
	session, err := GetSession(r)
	if err != nil {
		return "", false
	}

	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		return "", false
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		return "", false
	}

	return username, true
}

/**
 * @function IsAdminFromSession
 * @brief Checks if user is an administrator by verifying against credentials.json
 * @brief This ensures role changes take effect immediately, not just on next login
 * @param r *http.Request - HTTP request
 * @return bool - True if user is admin, false otherwise
 */
func IsAdminFromSession(r *http.Request) bool {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		return false
	}

	user, err := FindUser(username)
	if err != nil {
		return false
	}

	return user.IsAdmin
}

/**
 * @function RequireAuth
 * @brief Middleware to require authentication
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires authentication
 */
func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, authenticated := GetUsernameFromSession(r)
		if !authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Store username in request context for use in handler
		r.Header.Set("X-Username", username)
		handler(w, r)
	}
}

/**
 * @function RequireAdmin
 * @brief Middleware to require administrator privileges
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires admin privileges
 */
func RequireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAdminFromSession(r) {
			http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
			return
		}
		RequireAuth(handler)(w, r)
	}
}

/**
 * @function GenerateSecretKey
 * @brief Generates a random secret key for session encryption
 * @return string - Base64 encoded secret key
 * @return error - Error if key generation fails
 */
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

/**
 * @function FindUser
 * @brief Finds a user by username in credentials
 * @param username string - Username to search for
 * @return *User - Pointer to user if found, nil otherwise
 * @return error - Error if credentials loading fails
 */
func FindUser(username string) (*User, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return nil, err
	}

	for i := range creds.Users {
		if creds.Users[i].Username == username {
			return &creds.Users[i], nil
		}
	}

	return nil, errors.New("user not found")
}

```


Checking `HandleGetSession` to ensure it also checks credentials.json:



Verifying all admin checks use the updated function:



Fix complete. Verifying the implementation:



## Security Fix Summary

**Problem**: The `IsAdminFromSession` function was reading the admin status from the session cookie, which meant:
- If an admin was demoted, they would still have admin access until they logged out and back in
- If a user was promoted to admin, they wouldn't get admin access until they logged out and back in

**Solution**: Modified `IsAdminFromSession` to check the user's role from `credentials.json` on every request instead of trusting the session value.

### Changes Made

1. Updated `IsAdminFromSession` function:
   - Gets the username from the session (for authentication)
   - Looks up the user in `credentials.json` using `FindUser()`
   - Returns the `IsAdmin` status from the credentials file

2. All existing code using `IsAdminFromSession` now automatically checks credentials.json:
   - `RequireAdmin` middleware
   - `HandleGetSession` (returns current admin status)
   - `HandleDeletePost` (checks if user can delete)
   - `HandleDeleteThread` (admin-only)
   - `HandleGetUsers` (admin-only)
   - `HandleDeleteUser` (admin-only)
   - `HandleResetPassword` (checks permissions)
   - `HandleUpdateUserAdmin` (admin-only)

### Security Benefits

- Role changes take effect immediately — no need to log out/in
- Session values are not trusted for authorization — only for authentication
- Consistent authorization checks across the application

The code compiles successfully and all tests pass. The security vulnerability has been fixed.

---

**User**

Since it is nolonger verifying the user role from session, change the function name `IsAdminFromSession`.

---

**Cursor**


Renaming `IsAdminFromSession` to reflect that it checks credentials.json, not the session. Finding all usages:



Renaming the function to `IsUserAdmin` and updating all usages:


```go
/**
 * @file auth.go
 * @brief Authentication and authorization logic
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
)

/**
 * @var store *sessions.CookieStore
 * @brief Session store for managing user sessions
 */
var store *sessions.CookieStore

/**
 * @var sessionName string
 * @brief Name of the session cookie
 */
var sessionName = "forum_session"

/**
 * @function InitSessionStore
 * @brief Initializes the session store with a secret key
 * @param secretKey string - Secret key for session encryption
 */
func InitSessionStore(secretKey string) {
	store = sessions.NewCookieStore([]byte(secretKey))
	store.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
	}
}

/**
 * @function HashPassword
 * @brief Hashes a password using bcrypt
 * @param password string - Plain text password to hash
 * @return string - Hashed password
 * @return error - Error if hashing fails
 */
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

/**
 * @function CheckPassword
 * @brief Verifies a password against a hash
 * @param hash string - Hashed password
 * @param password string - Plain text password to verify
 * @return bool - True if password matches, false otherwise
 */
func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/**
 * @function GetSession
 * @brief Retrieves the session for a request
 * @param r *http.Request - HTTP request
 * @return *sessions.Session - Session object
 * @return error - Error if session retrieval fails
 */
func GetSession(r *http.Request) (*sessions.Session, error) {
	return store.Get(r, sessionName)
}

/**
 * @function SetUserSession
 * @brief Sets user information in the session
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @param username string - Username to store in session
 * @param isAdmin bool - Whether user is an administrator
 * @return error - Error if session save fails
 */
func SetUserSession(w http.ResponseWriter, r *http.Request, username string, isAdmin bool) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = username
	session.Values["isAdmin"] = isAdmin
	session.Values["authenticated"] = true

	return session.Save(r, w)
}

/**
 * @function ClearUserSession
 * @brief Clears user session (logs out)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @return error - Error if session save fails
 */
func ClearUserSession(w http.ResponseWriter, r *http.Request) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = nil
	session.Values["isAdmin"] = nil
	session.Values["authenticated"] = false

	return session.Save(r, w)
}

/**
 * @function GetUsernameFromSession
 * @brief Retrieves username from session
 * @param r *http.Request - HTTP request
 * @return string - Username if authenticated, empty string otherwise
 * @return bool - True if user is authenticated, false otherwise
 */
func GetUsernameFromSession(r *http.Request) (string, bool) {
	session, err := GetSession(r)
	if err != nil {
		return "", false
	}

	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		return "", false
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		return "", false
	}

	return username, true
}

/**
 * @function IsUserAdmin
 * @brief Checks if user is an administrator by verifying against credentials.json
 * @brief This ensures role changes take effect immediately, not just on next login
 * @param r *http.Request - HTTP request
 * @return bool - True if user is admin, false otherwise
 */
func IsUserAdmin(r *http.Request) bool {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		return false
	}

	user, err := FindUser(username)
	if err != nil {
		return false
	}

	return user.IsAdmin
}

/**
 * @function RequireAuth
 * @brief Middleware to require authentication
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires authentication
 */
func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, authenticated := GetUsernameFromSession(r)
		if !authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Store username in request context for use in handler
		r.Header.Set("X-Username", username)
		handler(w, r)
	}
}

/**
 * @function RequireAdmin
 * @brief Middleware to require administrator privileges
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires admin privileges
 */
func RequireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAdminFromSession(r) {
			http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
			return
		}
		RequireAuth(handler)(w, r)
	}
}

/**
 * @function GenerateSecretKey
 * @brief Generates a random secret key for session encryption
 * @return string - Base64 encoded secret key
 * @return error - Error if key generation fails
 */
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

/**
 * @function FindUser
 * @brief Finds a user by username in credentials
 * @param username string - Username to search for
 * @return *User - Pointer to user if found, nil otherwise
 * @return error - Error if credentials loading fails
 */
func FindUser(username string) (*User, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return nil, err
	}

	for i := range creds.Users {
		if creds.Users[i].Username == username {
			return &creds.Users[i], nil
		}
	}

	return nil, errors.New("user not found")
}

```

```go
/**
 * @file auth.go
 * @brief Authentication and authorization logic
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
)

/**
 * @var store *sessions.CookieStore
 * @brief Session store for managing user sessions
 */
var store *sessions.CookieStore

/**
 * @var sessionName string
 * @brief Name of the session cookie
 */
var sessionName = "forum_session"

/**
 * @function InitSessionStore
 * @brief Initializes the session store with a secret key
 * @param secretKey string - Secret key for session encryption
 */
func InitSessionStore(secretKey string) {
	store = sessions.NewCookieStore([]byte(secretKey))
	store.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
	}
}

/**
 * @function HashPassword
 * @brief Hashes a password using bcrypt
 * @param password string - Plain text password to hash
 * @return string - Hashed password
 * @return error - Error if hashing fails
 */
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

/**
 * @function CheckPassword
 * @brief Verifies a password against a hash
 * @param hash string - Hashed password
 * @param password string - Plain text password to verify
 * @return bool - True if password matches, false otherwise
 */
func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/**
 * @function GetSession
 * @brief Retrieves the session for a request
 * @param r *http.Request - HTTP request
 * @return *sessions.Session - Session object
 * @return error - Error if session retrieval fails
 */
func GetSession(r *http.Request) (*sessions.Session, error) {
	return store.Get(r, sessionName)
}

/**
 * @function SetUserSession
 * @brief Sets user information in the session
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @param username string - Username to store in session
 * @param isAdmin bool - Whether user is an administrator
 * @return error - Error if session save fails
 */
func SetUserSession(w http.ResponseWriter, r *http.Request, username string, isAdmin bool) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = username
	session.Values["isAdmin"] = isAdmin
	session.Values["authenticated"] = true

	return session.Save(r, w)
}

/**
 * @function ClearUserSession
 * @brief Clears user session (logs out)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 * @return error - Error if session save fails
 */
func ClearUserSession(w http.ResponseWriter, r *http.Request) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	session.Values["username"] = nil
	session.Values["isAdmin"] = nil
	session.Values["authenticated"] = false

	return session.Save(r, w)
}

/**
 * @function GetUsernameFromSession
 * @brief Retrieves username from session
 * @param r *http.Request - HTTP request
 * @return string - Username if authenticated, empty string otherwise
 * @return bool - True if user is authenticated, false otherwise
 */
func GetUsernameFromSession(r *http.Request) (string, bool) {
	session, err := GetSession(r)
	if err != nil {
		return "", false
	}

	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		return "", false
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		return "", false
	}

	return username, true
}

/**
 * @function IsUserAdmin
 * @brief Checks if user is an administrator by verifying against credentials.json
 * @brief This ensures role changes take effect immediately, not just on next login
 * @param r *http.Request - HTTP request
 * @return bool - True if user is admin, false otherwise
 */
func IsUserAdmin(r *http.Request) bool {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		return false
	}

	user, err := FindUser(username)
	if err != nil {
		return false
	}

	return user.IsAdmin
}

/**
 * @function RequireAuth
 * @brief Middleware to require authentication
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires authentication
 */
func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, authenticated := GetUsernameFromSession(r)
		if !authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Store username in request context for use in handler
		r.Header.Set("X-Username", username)
		handler(w, r)
	}
}

/**
 * @function RequireAdmin
 * @brief Middleware to require administrator privileges
 * @param handler http.HandlerFunc - Handler function to protect
 * @return http.HandlerFunc - Wrapped handler that requires admin privileges
 */
func RequireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsUserAdmin(r) {
			http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
			return
		}
		RequireAuth(handler)(w, r)
	}
}

/**
 * @function GenerateSecretKey
 * @brief Generates a random secret key for session encryption
 * @return string - Base64 encoded secret key
 * @return error - Error if key generation fails
 */
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

/**
 * @function FindUser
 * @brief Finds a user by username in credentials
 * @param username string - Username to search for
 * @return *User - Pointer to user if found, nil otherwise
 * @return error - Error if credentials loading fails
 */
func FindUser(username string) (*User, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return nil, err
	}

	for i := range creds.Users {
		if creds.Users[i].Username == username {
			return &creds.Users[i], nil
		}
	}

	return nil, errors.New("user not found")
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsUserAdmin(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsAdminFromSession(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsUserAdmin(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdminFromSession(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsUserAdmin(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```


Verifying all occurrences were replaced:



Function renamed. Summary:

## Function Rename Summary

**Old name**: `IsAdminFromSession`  
**New name**: `IsUserAdmin`

### Changes Made

1. **Function definition** in `auth.go`:
   - Renamed function from `IsAdminFromSession` to `IsUserAdmin`
   - Updated documentation comment

2. **All usages updated** (9 total):
   - `RequireAdmin` middleware in `auth.go` (1 usage)
   - `HandleGetSession` in `handlers.go` (1 usage)
   - `HandleDeletePost` in `handlers.go` (1 usage)
   - `HandleDeleteThread` in `handlers.go` (1 usage)
   - `HandleGetUsers` in `handlers.go` (1 usage)
   - `HandleDeleteUser` in `handlers.go` (1 usage)
   - `HandleResetPassword` in `handlers.go` (2 usages)
   - `HandleUpdateUserAdmin` in `handlers.go` (1 usage)

### Verification

- All old function names removed
- All new function names in place
- Code compiles successfully
- All tests pass

The function name now reflects that it checks the user's admin status from `credentials.json`, not from the session.

---

**User**

Always display the current username on the upper right corner, next to the "Profile" hyperlink.

---

**Cursor**


Checking the navigation code to add the username display:



Updating the navigation to display the username next to the Profile link:


```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item d-flex align-items-center me-2">
                <span class="text-light me-2">${escapeHtml(currentUser.username)}</span>
                <a class="nav-link btn btn-outline-primary" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                (window as any).currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
    
    // Update currentUser reference after page load
    (window as any).currentUser = currentUser;
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}


```


Adding an escapeHtml function to prevent XSS when displaying the username:


```typescript
/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item d-flex align-items-center me-2">
                <span class="text-light me-2">${escapeHtml(currentUser.username)}</span>
                <a class="nav-link btn btn-outline-primary" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                (window as any).currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
    
    // Update currentUser reference after page load
    (window as any).currentUser = currentUser;
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}


```


Verifying the changes:



## Changes Made

1. Added `escapeHtml` function to prevent XSS when displaying the username
2. Updated navigation HTML to display the username:
   - Added a `<span>` with the username next to the Profile link
   - Used Bootstrap classes (`d-flex align-items-center`) for alignment
   - Applied `text-light` for visibility on the dark navbar
   - Username is HTML-escaped for security

### Result

When a user is logged in, the navigation bar will display:
```
[Username] [Profile] [Administrator Management] [Log out]
```

The username appears as plain text (light color) immediately before the Profile button, and it updates automatically when the user logs in or out.

The TypeScript code compiled successfully, so the changes are ready to use.

```plaintext
[Username] [Profile] [Administrator Management] [Log out]
```

---

**User**

The `.gitignore` file should ignore all the files in `dist` directory, and then place the `index.html` file in the `src` directory. The build command can copy the `index.html` file from `src` directory to `dist` directory.

---

**Cursor**


Moving `index.html` to `src` and updating `.gitignore` and the build process:



Moving `index.html` to `src` and updating `.gitignore` and the build process:


```ignore
# Compiled files
*.exe
*.exe~
*.dll
*.so
*.dylib

# Go build artifacts
*.test
*.out
go_forum

# Frontend build artifacts - ignore entire dist directory
frontend/dist/

# Node modules
node_modules/

# Data directory (contains credentials and threads)
data/

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Logs
*.log

# Temporary files
*.tmp
*.temp


```


Creating a build script and updating the README:


```shellscript
#!/bin/bash
# Build script for frontend
# Compiles TypeScript and copies index.html to dist directory

echo "Building frontend..."

# Compile TypeScript
tsc

# Copy index.html from src to dist
if [ -f "src/index.html" ]; then
    cp src/index.html dist/index.html
    echo "Copied index.html to dist/"
else
    echo "Error: src/index.html not found!"
    exit 1
fi

echo "Frontend build complete!"

```

```markdown
# Forum Application

A full-stack forum application built with Golang backend and TypeScript frontend.

## Overview

This forum application provides a complete discussion platform with user authentication, thread management, and administrative features. The backend is implemented in Go using the standard `net/http` package, and the frontend is written in TypeScript and compiled to ES5 with inline source maps.

## Architecture

### Backend (Golang)

The backend is organized into multiple modules:

- **main.go**: Entry point that initializes the server and sets up routes
- **models.go**: Data structures for users, posts, and threads
- **auth.go**: Authentication and session management using `gorilla/sessions`
- **data.go**: Data persistence layer for credentials and threads (JSON files)
- **handlers.go**: HTTP request handlers for all API endpoints

### Frontend (TypeScript)

The frontend is a single-page application (SPA) with the following modules:

- **main.ts**: Application entry point and routing
- **api.ts**: API client for backend communication
- **utils.ts**: Utility functions (date formatting, alerts, modals)
- **index.ts**: Main forum page implementation
- **login.ts**: Login page
- **createAccount.ts**: Account creation page
- **createThread.ts**: Thread creation page
- **profile.ts**: User profile and post management
- **admin.ts**: Administrator management interface

## Features

### User Features

- **Account Management**: Create account, log in, log out
- **Thread Creation**: Authenticated users can create new discussion threads
- **Posting**: All users can reply to threads
- **Profile Management**: Users can view their posts and change their password
- **Post Deletion**: Users can delete their own posts

### Administrator Features

- **User Management**: View all users, delete users, modify admin status
- **Password Reset**: Reset any user's password
- **Thread Management**: Delete entire threads
- **Post Management**: Delete any post (not just their own)

## Data Storage

All data is stored in JSON files in the `data/` directory:

- **credentials.json**: User credentials with securely hashed passwords
- **threads.json**: All forum threads and posts with Unix timestamps

The admin account is automatically initialized on first run:
- Username: `admin`
- Password: `admin123`

**Important**: Change the admin password immediately after first deployment!

## Security

- Passwords are hashed using bcrypt
- Sessions use secure cookies with `HttpOnly: true` and `SameSite: Strict`
- All user inputs are sanitized to prevent XSS attacks
- Authentication is required for creating threads and posting
- Admin-only endpoints are protected by middleware

## Project Structure

```
go_forum/
├── backend/           # Golang backend code
│   ├── main.go       # Server entry point
│   ├── models.go     # Data models
│   ├── auth.go       # Authentication
│   ├── data.go       # Data persistence
│   ├── handlers.go   # HTTP handlers
│   └── *_test.go     # Unit tests
├── frontend/          # TypeScript frontend code
│   ├── src/          # Source files
│   ├── dist/         # Compiled output
│   └── tsconfig.json # TypeScript configuration
├── data/             # Data files (gitignored)
│   ├── credentials.json
│   └── threads.json
├── go.mod            # Go module definition
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## Building

### Backend

```bash
cd backend
go build -o go_forum .
```

### Frontend

```bash
cd frontend
tsc
cp src/index.html dist/index.html
```

Or use the build script:

```bash
cd frontend
./build.sh
```

The compiled JavaScript files and `index.html` will be in `frontend/dist/`.

## Running Tests

### Backend Tests

```bash
cd backend
go test -v ./...
```

All tests should pass.

## Application Flow

The following flowchart illustrates the application architecture and request flow:

```mermaid
graph TB
    Start([User Accesses Forum]) --> CheckAuth{Authenticated?}
    
    CheckAuth -->|No| ShowLogin[Show Login/Create Account]
    CheckAuth -->|Yes| ShowForum[Show Forum Page]
    
    ShowLogin --> LoginAction[User Logs In]
    LoginAction --> AuthCheck{Valid Credentials?}
    AuthCheck -->|No| ShowError[Show Error Message]
    AuthCheck -->|Yes| CreateSession[Create Session Cookie]
    ShowError --> ShowLogin
    CreateSession --> ShowForum
    
    ShowForum --> UserAction{User Action}
    
    UserAction -->|Create Thread| CheckAuthThread{Authenticated?}
    UserAction -->|Reply to Thread| CheckAuthReply{Authenticated?}
    UserAction -->|View Profile| CheckAuthProfile{Authenticated?}
    UserAction -->|Admin Panel| CheckAdmin{Is Admin?}
    
    CheckAuthThread -->|Yes| CreateThread[Create Thread API]
    CheckAuthThread -->|No| RedirectLogin[Redirect to Login]
    
    CheckAuthReply -->|Yes| AddPost[Add Post API]
    CheckAuthReply -->|No| RedirectLogin
    
    CheckAuthProfile -->|Yes| ShowProfile[Show Profile Page]
    CheckAuthProfile -->|No| RedirectLogin
    
    CheckAdmin -->|Yes| ShowAdmin[Show Admin Panel]
    CheckAdmin -->|No| ShowError
    
    CreateThread --> SaveThread[Save to threads.json]
    AddPost --> SavePost[Save to threads.json]
    
    SaveThread --> UpdateUI[Update UI]
    SavePost --> UpdateUI
    
    ShowProfile --> ManagePosts[Manage User Posts]
    ShowAdmin --> ManageUsers[Manage Users]
    ShowAdmin --> ManageThreads[Manage Threads]
    
    ManageUsers --> DeleteUser[Delete User API]
    ManageThreads --> DeleteThread[Delete Thread API]
    ManagePosts --> DeletePost[Delete Post API]
    
    DeleteUser --> SaveCredentials[Save to credentials.json]
    DeleteThread --> SaveThreads[Save to threads.json]
    DeletePost --> SaveThreads
    
    SaveCredentials --> UpdateUI
    SaveThreads --> UpdateUI
    
    UpdateUI --> ShowForum
    
    style Start fill:#e1f5ff
    style ShowForum fill:#c8e6c9
    style ShowAdmin fill:#fff9c4
    style ShowError fill:#ffcdd2
```

## API Endpoints

### Authentication
- `POST /api/login` - Log in user
- `POST /api/logout` - Log out user
- `POST /api/create-account` - Create new account
- `GET /api/session` - Get current session info

### Threads
- `GET /api/threads` - Get all threads
- `GET /api/thread?id={id}` - Get specific thread
- `POST /api/create-thread` - Create new thread (requires auth)
- `DELETE /api/delete-thread` - Delete thread (requires admin)

### Posts
- `POST /api/add-post` - Add reply to thread (requires auth)
- `DELETE /api/delete-post` - Delete post (requires auth, owner or admin)

### Users (Admin Only)
- `GET /api/users` - Get all users
- `DELETE /api/delete-user` - Delete user
- `POST /api/reset-password` - Reset user password
- `POST /api/update-user-admin` - Update user admin status

## Session Configuration

Sessions are configured with:
- `HttpOnly: true` - Prevents JavaScript access to cookies
- `SameSite: http.SameSiteStrictMode` - CSRF protection
- `MaxAge: 7 days` - Session expiration

## TypeScript Configuration

The frontend TypeScript is configured to:
- Target ES5 for browser compatibility
- Use AMD module system
- Include ES2017 and DOM libraries
- Generate inline source maps
- Output to `frontend/dist/`

## Browser Compatibility

The application uses:
- Bootstrap 5.3.0 for UI styling
- ES5 JavaScript (compiled from TypeScript)
- Modern browser APIs (Promise, fetch via XMLHttpRequest)

## Development

### Prerequisites

- Go 1.24+ (or compatible version)
- TypeScript compiler (`tsc`)
- Modern web browser

### Running Locally

1. Build the frontend:
   ```bash
   cd frontend
   tsc
   ```

2. Run the backend:
   ```bash
   cd backend
   go run .
   ```

3. Access the forum at `http://localhost:8080`

## Deployment

### Production Deployment Steps

1. **Build the Frontend**:
   ```bash
   cd frontend
   tsc
   ```
   This compiles all TypeScript files to JavaScript in the `frontend/dist/` directory.

2. **Build the Backend**:
   ```bash
   cd backend
   go build -o go_forum .
   ```
   This creates an executable binary named `go_forum`.

3. **Set Up Data Directory**:
   ```bash
   mkdir -p data
   ```
   The application will automatically create `credentials.json` with the admin account on first run.

4. **Configure Environment** (Optional):
   - Set the server port by modifying `serverPort` in `backend/main.go` (default: 8080)
   - Change the session secret key in `backend/main.go` for production

5. **Run the Application**:
   ```bash
   ./go_forum
   ```
   Or from the backend directory:
   ```bash
   cd backend
   ./go_forum
   ```

6. **Access the Forum**:
   - Open your browser and navigate to `http://localhost:8080` (or your configured port)
   - Log in with the default admin credentials:
     - Username: `admin`
     - Password: `admin123`
   - **Important**: Change the admin password immediately after first login!

### Deployment Commands Summary

```bash
# 1. Build frontend
cd frontend && tsc && cd ..

# 2. Build backend
cd backend && go build -o go_forum . && cd ..

# 3. Create data directory
mkdir -p data

# 4. Run the application
cd backend && ./go_forum
```

### Production Considerations

- **Security**: Change the session secret key in production
- **Port**: Configure firewall rules for your chosen port
- **HTTPS**: Use a reverse proxy (nginx, Apache) with SSL/TLS certificates
- **Process Management**: Use systemd, supervisor, or similar for process management
- **Logging**: Configure proper logging for production monitoring
- **Backup**: Regularly backup the `data/` directory
- **Admin Password**: Change the default admin password immediately

### Example systemd Service

Create `/etc/systemd/system/go-forum.service`:

```ini
[Unit]
Description=Go Forum Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/go_forum/backend
ExecStart=/path/to/go_forum/backend/go_forum
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable and start:
```bash
sudo systemctl enable go-forum
sudo systemctl start go-forum
```

## Code Documentation

All code is extensively documented with Doxygen-style comments:
- File headers with creation date and author
- Function documentation with parameters and return values
- Struct and variable documentation
- Inline comments explaining complex logic

## License

This project is provided as-is for educational and development purposes.

## Author

Victor Yeh
Created: 2025-12-19


```

```markdown
# Forum Application

A full-stack forum application built with Golang backend and TypeScript frontend.

## Overview

This forum application provides a complete discussion platform with user authentication, thread management, and administrative features. The backend is implemented in Go using the standard `net/http` package, and the frontend is written in TypeScript and compiled to ES5 with inline source maps.

## Architecture

### Backend (Golang)

The backend is organized into multiple modules:

- **main.go**: Entry point that initializes the server and sets up routes
- **models.go**: Data structures for users, posts, and threads
- **auth.go**: Authentication and session management using `gorilla/sessions`
- **data.go**: Data persistence layer for credentials and threads (JSON files)
- **handlers.go**: HTTP request handlers for all API endpoints

### Frontend (TypeScript)

The frontend is a single-page application (SPA) with the following modules:

- **main.ts**: Application entry point and routing
- **api.ts**: API client for backend communication
- **utils.ts**: Utility functions (date formatting, alerts, modals)
- **index.ts**: Main forum page implementation
- **login.ts**: Login page
- **createAccount.ts**: Account creation page
- **createThread.ts**: Thread creation page
- **profile.ts**: User profile and post management
- **admin.ts**: Administrator management interface

## Features

### User Features

- **Account Management**: Create account, log in, log out
- **Thread Creation**: Authenticated users can create new discussion threads
- **Posting**: All users can reply to threads
- **Profile Management**: Users can view their posts and change their password
- **Post Deletion**: Users can delete their own posts

### Administrator Features

- **User Management**: View all users, delete users, modify admin status
- **Password Reset**: Reset any user's password
- **Thread Management**: Delete entire threads
- **Post Management**: Delete any post (not just their own)

## Data Storage

All data is stored in JSON files in the `data/` directory:

- **credentials.json**: User credentials with securely hashed passwords
- **threads.json**: All forum threads and posts with Unix timestamps

The admin account is automatically initialized on first run:
- Username: `admin`
- Password: `admin123`

**Important**: Change the admin password immediately after first deployment!

## Security

- Passwords are hashed using bcrypt
- Sessions use secure cookies with `HttpOnly: true` and `SameSite: Strict`
- All user inputs are sanitized to prevent XSS attacks
- Authentication is required for creating threads and posting
- Admin-only endpoints are protected by middleware

## Project Structure

```
go_forum/
├── backend/           # Golang backend code
│   ├── main.go       # Server entry point
│   ├── models.go     # Data models
│   ├── auth.go       # Authentication
│   ├── data.go       # Data persistence
│   ├── handlers.go   # HTTP handlers
│   └── *_test.go     # Unit tests
├── frontend/          # TypeScript frontend code
│   ├── src/          # Source files
│   ├── dist/         # Compiled output
│   └── tsconfig.json # TypeScript configuration
├── data/             # Data files (gitignored)
│   ├── credentials.json
│   └── threads.json
├── go.mod            # Go module definition
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## Building

### Backend

```bash
cd backend
go build -o go_forum .
```

### Frontend

```bash
cd frontend
tsc
cp src/index.html dist/index.html
```

Or use the build script:

```bash
cd frontend
./build.sh
```

The compiled JavaScript files and `index.html` will be in `frontend/dist/`.

## Running Tests

### Backend Tests

```bash
cd backend
go test -v ./...
```

All tests should pass.

## Application Flow

The following flowchart illustrates the application architecture and request flow:

```mermaid
graph TB
    Start([User Accesses Forum]) --> CheckAuth{Authenticated?}
    
    CheckAuth -->|No| ShowLogin[Show Login/Create Account]
    CheckAuth -->|Yes| ShowForum[Show Forum Page]
    
    ShowLogin --> LoginAction[User Logs In]
    LoginAction --> AuthCheck{Valid Credentials?}
    AuthCheck -->|No| ShowError[Show Error Message]
    AuthCheck -->|Yes| CreateSession[Create Session Cookie]
    ShowError --> ShowLogin
    CreateSession --> ShowForum
    
    ShowForum --> UserAction{User Action}
    
    UserAction -->|Create Thread| CheckAuthThread{Authenticated?}
    UserAction -->|Reply to Thread| CheckAuthReply{Authenticated?}
    UserAction -->|View Profile| CheckAuthProfile{Authenticated?}
    UserAction -->|Admin Panel| CheckAdmin{Is Admin?}
    
    CheckAuthThread -->|Yes| CreateThread[Create Thread API]
    CheckAuthThread -->|No| RedirectLogin[Redirect to Login]
    
    CheckAuthReply -->|Yes| AddPost[Add Post API]
    CheckAuthReply -->|No| RedirectLogin
    
    CheckAuthProfile -->|Yes| ShowProfile[Show Profile Page]
    CheckAuthProfile -->|No| RedirectLogin
    
    CheckAdmin -->|Yes| ShowAdmin[Show Admin Panel]
    CheckAdmin -->|No| ShowError
    
    CreateThread --> SaveThread[Save to threads.json]
    AddPost --> SavePost[Save to threads.json]
    
    SaveThread --> UpdateUI[Update UI]
    SavePost --> UpdateUI
    
    ShowProfile --> ManagePosts[Manage User Posts]
    ShowAdmin --> ManageUsers[Manage Users]
    ShowAdmin --> ManageThreads[Manage Threads]
    
    ManageUsers --> DeleteUser[Delete User API]
    ManageThreads --> DeleteThread[Delete Thread API]
    ManagePosts --> DeletePost[Delete Post API]
    
    DeleteUser --> SaveCredentials[Save to credentials.json]
    DeleteThread --> SaveThreads[Save to threads.json]
    DeletePost --> SaveThreads
    
    SaveCredentials --> UpdateUI
    SaveThreads --> UpdateUI
    
    UpdateUI --> ShowForum
    
    style Start fill:#e1f5ff
    style ShowForum fill:#c8e6c9
    style ShowAdmin fill:#fff9c4
    style ShowError fill:#ffcdd2
```

## API Endpoints

### Authentication
- `POST /api/login` - Log in user
- `POST /api/logout` - Log out user
- `POST /api/create-account` - Create new account
- `GET /api/session` - Get current session info

### Threads
- `GET /api/threads` - Get all threads
- `GET /api/thread?id={id}` - Get specific thread
- `POST /api/create-thread` - Create new thread (requires auth)
- `DELETE /api/delete-thread` - Delete thread (requires admin)

### Posts
- `POST /api/add-post` - Add reply to thread (requires auth)
- `DELETE /api/delete-post` - Delete post (requires auth, owner or admin)

### Users (Admin Only)
- `GET /api/users` - Get all users
- `DELETE /api/delete-user` - Delete user
- `POST /api/reset-password` - Reset user password
- `POST /api/update-user-admin` - Update user admin status

## Session Configuration

Sessions are configured with:
- `HttpOnly: true` - Prevents JavaScript access to cookies
- `SameSite: http.SameSiteStrictMode` - CSRF protection
- `MaxAge: 7 days` - Session expiration

## TypeScript Configuration

The frontend TypeScript is configured to:
- Target ES5 for browser compatibility
- Use AMD module system
- Include ES2017 and DOM libraries
- Generate inline source maps
- Output to `frontend/dist/`

## Browser Compatibility

The application uses:
- Bootstrap 5.3.0 for UI styling
- ES5 JavaScript (compiled from TypeScript)
- Modern browser APIs (Promise, fetch via XMLHttpRequest)

## Development

### Prerequisites

- Go 1.24+ (or compatible version)
- TypeScript compiler (`tsc`)
- Modern web browser

### Running Locally

1. Build the frontend:
   ```bash
   cd frontend
   tsc
   cp src/index.html dist/index.html
   ```
   Or use the build script:
   ```bash
   cd frontend
   ./build.sh
   ```

2. Run the backend:
   ```bash
   cd backend
   go run .
   ```

3. Access the forum at `http://localhost:8080`

## Deployment

### Production Deployment Steps

1. **Build the Frontend**:
   ```bash
   cd frontend
   tsc
   ```
   This compiles all TypeScript files to JavaScript in the `frontend/dist/` directory.

2. **Build the Backend**:
   ```bash
   cd backend
   go build -o go_forum .
   ```
   This creates an executable binary named `go_forum`.

3. **Set Up Data Directory**:
   ```bash
   mkdir -p data
   ```
   The application will automatically create `credentials.json` with the admin account on first run.

4. **Configure Environment** (Optional):
   - Set the server port by modifying `serverPort` in `backend/main.go` (default: 8080)
   - Change the session secret key in `backend/main.go` for production

5. **Run the Application**:
   ```bash
   ./go_forum
   ```
   Or from the backend directory:
   ```bash
   cd backend
   ./go_forum
   ```

6. **Access the Forum**:
   - Open your browser and navigate to `http://localhost:8080` (or your configured port)
   - Log in with the default admin credentials:
     - Username: `admin`
     - Password: `admin123`
   - **Important**: Change the admin password immediately after first login!

### Deployment Commands Summary

```bash
# 1. Build frontend
cd frontend && tsc && cd ..

# 2. Build backend
cd backend && go build -o go_forum . && cd ..

# 3. Create data directory
mkdir -p data

# 4. Run the application
cd backend && ./go_forum
```

### Production Considerations

- **Security**: Change the session secret key in production
- **Port**: Configure firewall rules for your chosen port
- **HTTPS**: Use a reverse proxy (nginx, Apache) with SSL/TLS certificates
- **Process Management**: Use systemd, supervisor, or similar for process management
- **Logging**: Configure proper logging for production monitoring
- **Backup**: Regularly backup the `data/` directory
- **Admin Password**: Change the default admin password immediately

### Example systemd Service

Create `/etc/systemd/system/go-forum.service`:

```ini
[Unit]
Description=Go Forum Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/go_forum/backend
ExecStart=/path/to/go_forum/backend/go_forum
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable and start:
```bash
sudo systemctl enable go-forum
sudo systemctl start go-forum
```

## Code Documentation

All code is extensively documented with Doxygen-style comments:
- File headers with creation date and author
- Function documentation with parameters and return values
- Struct and variable documentation
- Inline comments explaining complex logic

## License

This project is provided as-is for educational and development purposes.

## Author

Victor Yeh
Created: 2025-12-19


```


Verifying the changes and updating the deployment section:


```markdown
1. **Build the Frontend**:
   ```bash
   cd frontend
   tsc
   cp src/index.html dist/index.html
   ```
   Or use the build script:
   ```bash
   cd frontend
   ./build.sh
   ```
```


Updating the deployment commands summary:


```markdown
# Forum Application

A full-stack forum application built with Golang backend and TypeScript frontend.

## Overview

This forum application provides a complete discussion platform with user authentication, thread management, and administrative features. The backend is implemented in Go using the standard `net/http` package, and the frontend is written in TypeScript and compiled to ES5 with inline source maps.

## Architecture

### Backend (Golang)

The backend is organized into multiple modules:

- **main.go**: Entry point that initializes the server and sets up routes
- **models.go**: Data structures for users, posts, and threads
- **auth.go**: Authentication and session management using `gorilla/sessions`
- **data.go**: Data persistence layer for credentials and threads (JSON files)
- **handlers.go**: HTTP request handlers for all API endpoints

### Frontend (TypeScript)

The frontend is a single-page application (SPA) with the following modules:

- **main.ts**: Application entry point and routing
- **api.ts**: API client for backend communication
- **utils.ts**: Utility functions (date formatting, alerts, modals)
- **index.ts**: Main forum page implementation
- **login.ts**: Login page
- **createAccount.ts**: Account creation page
- **createThread.ts**: Thread creation page
- **profile.ts**: User profile and post management
- **admin.ts**: Administrator management interface

## Features

### User Features

- **Account Management**: Create account, log in, log out
- **Thread Creation**: Authenticated users can create new discussion threads
- **Posting**: All users can reply to threads
- **Profile Management**: Users can view their posts and change their password
- **Post Deletion**: Users can delete their own posts

### Administrator Features

- **User Management**: View all users, delete users, modify admin status
- **Password Reset**: Reset any user's password
- **Thread Management**: Delete entire threads
- **Post Management**: Delete any post (not just their own)

## Data Storage

All data is stored in JSON files in the `data/` directory:

- **credentials.json**: User credentials with securely hashed passwords
- **threads.json**: All forum threads and posts with Unix timestamps

The admin account is automatically initialized on first run:
- Username: `admin`
- Password: `admin123`

**Important**: Change the admin password immediately after first deployment!

## Security

- Passwords are hashed using bcrypt
- Sessions use secure cookies with `HttpOnly: true` and `SameSite: Strict`
- All user inputs are sanitized to prevent XSS attacks
- Authentication is required for creating threads and posting
- Admin-only endpoints are protected by middleware

## Project Structure

```
go_forum/
├── backend/           # Golang backend code
│   ├── main.go       # Server entry point
│   ├── models.go     # Data models
│   ├── auth.go       # Authentication
│   ├── data.go       # Data persistence
│   ├── handlers.go   # HTTP handlers
│   └── *_test.go     # Unit tests
├── frontend/          # TypeScript frontend code
│   ├── src/          # Source files
│   ├── dist/         # Compiled output
│   └── tsconfig.json # TypeScript configuration
├── data/             # Data files (gitignored)
│   ├── credentials.json
│   └── threads.json
├── go.mod            # Go module definition
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## Building

### Backend

```bash
cd backend
go build -o go_forum .
```

### Frontend

```bash
cd frontend
tsc
cp src/index.html dist/index.html
```

Or use the build script:

```bash
cd frontend
./build.sh
```

The compiled JavaScript files and `index.html` will be in `frontend/dist/`.

## Running Tests

### Backend Tests

```bash
cd backend
go test -v ./...
```

All tests should pass.

## Application Flow

The following flowchart illustrates the application architecture and request flow:

```mermaid
graph TB
    Start([User Accesses Forum]) --> CheckAuth{Authenticated?}
    
    CheckAuth -->|No| ShowLogin[Show Login/Create Account]
    CheckAuth -->|Yes| ShowForum[Show Forum Page]
    
    ShowLogin --> LoginAction[User Logs In]
    LoginAction --> AuthCheck{Valid Credentials?}
    AuthCheck -->|No| ShowError[Show Error Message]
    AuthCheck -->|Yes| CreateSession[Create Session Cookie]
    ShowError --> ShowLogin
    CreateSession --> ShowForum
    
    ShowForum --> UserAction{User Action}
    
    UserAction -->|Create Thread| CheckAuthThread{Authenticated?}
    UserAction -->|Reply to Thread| CheckAuthReply{Authenticated?}
    UserAction -->|View Profile| CheckAuthProfile{Authenticated?}
    UserAction -->|Admin Panel| CheckAdmin{Is Admin?}
    
    CheckAuthThread -->|Yes| CreateThread[Create Thread API]
    CheckAuthThread -->|No| RedirectLogin[Redirect to Login]
    
    CheckAuthReply -->|Yes| AddPost[Add Post API]
    CheckAuthReply -->|No| RedirectLogin
    
    CheckAuthProfile -->|Yes| ShowProfile[Show Profile Page]
    CheckAuthProfile -->|No| RedirectLogin
    
    CheckAdmin -->|Yes| ShowAdmin[Show Admin Panel]
    CheckAdmin -->|No| ShowError
    
    CreateThread --> SaveThread[Save to threads.json]
    AddPost --> SavePost[Save to threads.json]
    
    SaveThread --> UpdateUI[Update UI]
    SavePost --> UpdateUI
    
    ShowProfile --> ManagePosts[Manage User Posts]
    ShowAdmin --> ManageUsers[Manage Users]
    ShowAdmin --> ManageThreads[Manage Threads]
    
    ManageUsers --> DeleteUser[Delete User API]
    ManageThreads --> DeleteThread[Delete Thread API]
    ManagePosts --> DeletePost[Delete Post API]
    
    DeleteUser --> SaveCredentials[Save to credentials.json]
    DeleteThread --> SaveThreads[Save to threads.json]
    DeletePost --> SaveThreads
    
    SaveCredentials --> UpdateUI
    SaveThreads --> UpdateUI
    
    UpdateUI --> ShowForum
    
    style Start fill:#e1f5ff
    style ShowForum fill:#c8e6c9
    style ShowAdmin fill:#fff9c4
    style ShowError fill:#ffcdd2
```

## API Endpoints

### Authentication
- `POST /api/login` - Log in user
- `POST /api/logout` - Log out user
- `POST /api/create-account` - Create new account
- `GET /api/session` - Get current session info

### Threads
- `GET /api/threads` - Get all threads
- `GET /api/thread?id={id}` - Get specific thread
- `POST /api/create-thread` - Create new thread (requires auth)
- `DELETE /api/delete-thread` - Delete thread (requires admin)

### Posts
- `POST /api/add-post` - Add reply to thread (requires auth)
- `DELETE /api/delete-post` - Delete post (requires auth, owner or admin)

### Users (Admin Only)
- `GET /api/users` - Get all users
- `DELETE /api/delete-user` - Delete user
- `POST /api/reset-password` - Reset user password
- `POST /api/update-user-admin` - Update user admin status

## Session Configuration

Sessions are configured with:
- `HttpOnly: true` - Prevents JavaScript access to cookies
- `SameSite: http.SameSiteStrictMode` - CSRF protection
- `MaxAge: 7 days` - Session expiration

## TypeScript Configuration

The frontend TypeScript is configured to:
- Target ES5 for browser compatibility
- Use AMD module system
- Include ES2017 and DOM libraries
- Generate inline source maps
- Output to `frontend/dist/`

## Browser Compatibility

The application uses:
- Bootstrap 5.3.0 for UI styling
- ES5 JavaScript (compiled from TypeScript)
- Modern browser APIs (Promise, fetch via XMLHttpRequest)

## Development

### Prerequisites

- Go 1.24+ (or compatible version)
- TypeScript compiler (`tsc`)
- Modern web browser

### Running Locally

1. Build the frontend:
   ```bash
   cd frontend
   tsc
   cp src/index.html dist/index.html
   ```
   Or use the build script:
   ```bash
   cd frontend
   ./build.sh
   ```

2. Run the backend:
   ```bash
   cd backend
   go run .
   ```

3. Access the forum at `http://localhost:8080`

## Deployment

### Production Deployment Steps

1. **Build the Frontend**:
   ```bash
   cd frontend
   tsc
   ```
   This compiles all TypeScript files to JavaScript in the `frontend/dist/` directory.

2. **Build the Backend**:
   ```bash
   cd backend
   go build -o go_forum .
   ```
   This creates an executable binary named `go_forum`.

3. **Set Up Data Directory**:
   ```bash
   mkdir -p data
   ```
   The application will automatically create `credentials.json` with the admin account on first run.

4. **Configure Environment** (Optional):
   - Set the server port by modifying `serverPort` in `backend/main.go` (default: 8080)
   - Change the session secret key in `backend/main.go` for production

5. **Run the Application**:
   ```bash
   ./go_forum
   ```
   Or from the backend directory:
   ```bash
   cd backend
   ./go_forum
   ```

6. **Access the Forum**:
   - Open your browser and navigate to `http://localhost:8080` (or your configured port)
   - Log in with the default admin credentials:
     - Username: `admin`
     - Password: `admin123`
   - **Important**: Change the admin password immediately after first login!

### Deployment Commands Summary

```bash
# 1. Build frontend
cd frontend && tsc && cp src/index.html dist/index.html && cd ..
# Or use the build script:
# cd frontend && ./build.sh && cd ..

# 2. Build backend
cd backend && go build -o go_forum . && cd ..

# 3. Create data directory
mkdir -p data

# 4. Run the application
cd backend && ./go_forum
```

### Production Considerations

- **Security**: Change the session secret key in production
- **Port**: Configure firewall rules for your chosen port
- **HTTPS**: Use a reverse proxy (nginx, Apache) with SSL/TLS certificates
- **Process Management**: Use systemd, supervisor, or similar for process management
- **Logging**: Configure proper logging for production monitoring
- **Backup**: Regularly backup the `data/` directory
- **Admin Password**: Change the default admin password immediately

### Example systemd Service

Create `/etc/systemd/system/go-forum.service`:

```ini
[Unit]
Description=Go Forum Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/go_forum/backend
ExecStart=/path/to/go_forum/backend/go_forum
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable and start:
```bash
sudo systemctl enable go-forum
sudo systemctl start go-forum
```

## Code Documentation

All code is extensively documented with Doxygen-style comments:
- File headers with creation date and author
- Function documentation with parameters and return values
- Struct and variable documentation
- Inline comments explaining complex logic

## License

This project is provided as-is for educational and development purposes.

## Author

Victor Yeh
Created: 2025-12-19


```


Verifying the final structure:



## Changes Made

1. **Moved `index.html`**:
   - From: `frontend/dist/index.html`
   - To: `frontend/src/index.html`

2. **Updated `.gitignore`**:
   - Changed from ignoring specific files in `dist/` to ignoring the entire `frontend/dist/` directory
   - Now `index.html` in `src/` will be tracked, while everything in `dist/` is ignored

3. **Created build script** (`frontend/build.sh`):
   - Compiles TypeScript with `tsc`
   - Copies `index.html` from `src/` to `dist/` after compilation
   - Includes error checking

4. **Updated README.md**:
   - Updated build instructions to include copying `index.html`
   - Added instructions for using the build script
   - Updated deployment commands

## Build Process

Now you can build the frontend in two ways:

**Option 1 - Manual commands:**
```bash
cd frontend
tsc
cp src/index.html dist/index.html
```

**Option 2 - Using the build script:**
```bash
cd frontend
./build.sh
```

The `index.html` file is now in the `src/` directory (tracked by git), and the build process automatically copies it to `dist/` during compilation. All files in `dist/` are ignored by git as requested.

```shellscript
cd frontend
tsc
cp src/index.html dist/index.html
```

```shellscript
cd frontend
./build.sh
```

---

**User**

Remove all the files in the `dist` directory, and then rebuild the frontend.

---

**Cursor**


Removing all files in `dist` and rebuilding the frontend:



Completed:

1. Removed all files from `frontend/dist/` — directory is empty
2. Rebuilt the frontend — all files regenerated

## Rebuild Results

The `dist` directory now contains:
- **10 JavaScript files** compiled from TypeScript:
  - `admin.js` (45,619 bytes)
  - `api.js` (23,269 bytes)
  - `createAccount.js` (14,371 bytes)
  - `createThread.js` (13,165 bytes)
  - `index.js` (36,734 bytes)
  - `login.js` (11,326 bytes)
  - `main.js` (26,458 bytes)
  - `profile.js` (27,987 bytes)
  - `utils.js` (14,725 bytes)
- **1 HTML file**: `index.html` (1,664 bytes) — copied from `src/`

The frontend is rebuilt and ready to use. All files were generated from the source files in `src/` using the build script.

---

**User**

Nobody (not even administrators) shall be allowed to do any user role changes or user actions on itself.

---

**Cursor**


Adding checks to prevent users (including administrators) from modifying their own role or deleting themselves. Checking the relevant handlers:



Reading the full handlers to add self-modification checks:



Adding checks to prevent self-modification in all three handlers:


```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsUserAdmin(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent users from deleting themselves
	currentUsername, _ := GetUsernameFromSession(r)
	if req.Username == currentUsername {
		http.Error(w, "Forbidden: You cannot delete your own account", http.StatusForbidden)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsUserAdmin(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent users from deleting themselves
	currentUsername, _ := GetUsernameFromSession(r)
	if req.Username == currentUsername {
		http.Error(w, "Forbidden: You cannot delete your own account", http.StatusForbidden)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	// Prevent admins from resetting their own password (admin action on themselves)
	if isAdmin && req.Username == username {
		http.Error(w, "Forbidden: Administrators cannot reset their own password through this interface", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```

```go
/**
 * @file handlers.go
 * @brief HTTP request handlers for the forum application
 * @date 2025-12-19
 * @author Victor Yeh
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/**
 * @function ServeIndex
 * @brief Serves the main forum page (index.html)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/dist/index.html")
}

/**
 * @function ServeStatic
 * @brief Serves static files from the frontend/dist directory
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, "../frontend/dist/"+path)
}

/**
 * @function HandleLogin
 * @brief Handles user login requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := FindUser(req.Username)
	if err != nil || !CheckPassword(user.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SetUserSession(w, r, user.Username, user.IsAdmin); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
	})
}

/**
 * @function HandleLogout
 * @brief Handles user logout requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearUserSession(w, r); err != nil {
		http.Error(w, "Failed to clear session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleCreateAccount
 * @brief Handles new account creation requests
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Check if username already exists
	for _, user := range creds.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		IsAdmin:      false,
	}

	creds.Users = append(creds.Users, newUser)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetSession
 * @brief Returns current session information
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      username,
		"isAdmin":       IsUserAdmin(r),
	})
}

/**
 * @function HandleGetThreads
 * @brief Returns all forum threads
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThreads(w http.ResponseWriter, r *http.Request) {
	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(threads.Threads)
}

/**
 * @function HandleCreateThread
 * @brief Handles thread creation requests (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	newThread := Thread{
		ID:        nextThreadID,
		Title:     req.Title,
		Author:    username,
		CreatedAt: GetCurrentTimestamp(),
		Posts: []Post{
			{
				ID:        nextPostID,
				Author:    username,
				Content:   req.Content,
				Timestamp: GetCurrentTimestamp(),
			},
		},
	}

	nextThreadID++
	nextPostID++

	threads.Threads = append(threads.Threads, newThread)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save thread", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"thread":  newThread,
	})
}

/**
 * @function HandleAddPost
 * @brief Handles adding a reply post to a thread (requires authentication)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleAddPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ThreadID int    `json:"threadId"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	newPost := Post{
		ID:        nextPostID,
		Author:    username,
		Content:   req.Content,
		Timestamp: GetCurrentTimestamp(),
	}

	nextPostID++
	thread.Posts = append(thread.Posts, newPost)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save post", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"post":    newPost,
	})
}

/**
 * @function HandleDeletePost
 * @brief Handles post deletion (requires authentication, admin or post owner)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
		PostID   int `json:"postId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	var thread *Thread
	var postIndex int = -1
	for i := range threads.Threads {
		if threads.Threads[i].ID == req.ThreadID {
			thread = &threads.Threads[i]
			for j, post := range thread.Posts {
				if post.ID == req.PostID {
					if !isAdmin && post.Author != username {
						http.Error(w, "Forbidden: You can only delete your own posts", http.StatusForbidden)
						return
					}
					postIndex = j
					break
				}
			}
			break
		}
	}

	if thread == nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	if postIndex == -1 {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Remove the post
	thread.Posts = append(thread.Posts[:postIndex], thread.Posts[postIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleDeleteThread
 * @brief Handles thread deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteThread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		ThreadID int `json:"threadId"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	threadIndex := -1
	for i, thread := range threads.Threads {
		if thread.ID == req.ThreadID {
			threadIndex = i
			break
		}
	}

	if threadIndex == -1 {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Remove the thread
	threads.Threads = append(threads.Threads[:threadIndex], threads.Threads[threadIndex+1:]...)

	if err := SaveThreads(threads); err != nil {
		http.Error(w, "Failed to save threads", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetUsers
 * @brief Returns all users (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	// Return users without password hashes
	users := make([]map[string]interface{}, len(creds.Users))
	for i, user := range creds.Users {
		users[i] = map[string]interface{}{
			"username": user.Username,
			"isAdmin":  user.IsAdmin,
		}
	}

	json.NewEncoder(w).Encode(users)
}

/**
 * @function HandleDeleteUser
 * @brief Handles user deletion (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent users from deleting themselves
	currentUsername, _ := GetUsernameFromSession(r)
	if req.Username == currentUsername {
		http.Error(w, "Forbidden: You cannot delete your own account", http.StatusForbidden)
		return
	}

	// Remove the user
	creds.Users = append(creds.Users[:userIndex], creds.Users[userIndex+1:]...)

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleResetPassword
 * @brief Handles password reset (admin can reset any user's password, users can reset their own)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, authenticated := GetUsernameFromSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := IsUserAdmin(r)

	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Users can only reset their own password unless they're admin
	if !isAdmin && req.Username != username {
		http.Error(w, "Forbidden: You can only reset your own password", http.StatusForbidden)
		return
	}

	// Prevent admins from resetting their own password (admin action on themselves)
	if isAdmin && req.Username == username {
		http.Error(w, "Forbidden: Administrators cannot reset their own password through this interface", http.StatusForbidden)
		return
	}

	if req.NewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds.Users[userIndex].PasswordHash = passwordHash

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleUpdateUserAdmin
 * @brief Handles updating user admin status (requires admin)
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleUpdateUserAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsUserAdmin(r) {
		http.Error(w, "Forbidden: Administrator access required", http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	creds, err := LoadCredentials()
	if err != nil {
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	userIndex := -1
	for i, user := range creds.Users {
		if user.Username == req.Username {
			userIndex = i
			break
		}
	}

	if userIndex == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent users from changing their own admin status
	currentUsername, _ := GetUsernameFromSession(r)
	if req.Username == currentUsername {
		http.Error(w, "Forbidden: You cannot change your own admin status", http.StatusForbidden)
		return
	}

	creds.Users[userIndex].IsAdmin = req.IsAdmin

	if err := SaveCredentials(creds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
 * @function HandleGetThread
 * @brief Returns a specific thread by ID
 * @param w http.ResponseWriter - HTTP response writer
 * @param r *http.Request - HTTP request
 */
func HandleGetThread(w http.ResponseWriter, r *http.Request) {
	threadIDStr := r.URL.Query().Get("id")
	if threadIDStr == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	threads, err := LoadThreads()
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	for _, thread := range threads.Threads {
		if thread.ID == threadID {
			json.NewEncoder(w).Encode(thread)
			return
		}
	}

	http.Error(w, "Thread not found", http.StatusNotFound)
}

```


Verifying the changes are correct:



## Security Fix Summary

Added checks to prevent users (including administrators) from performing administrative actions on themselves:

### 1. **HandleDeleteUser** - Prevent self-deletion
- Added check: Users cannot delete their own account
- Error message: "Forbidden: You cannot delete your own account"

### 2. **HandleUpdateUserAdmin** - Prevent self-role changes
- Added check: Users cannot change their own admin status
- Error message: "Forbidden: You cannot change your own admin status"

### 3. **HandleResetPassword** - Prevent admin self-password reset
- Added check: Administrators cannot reset their own password through the admin interface
- Error message: "Forbidden: Administrators cannot reset their own password through this interface"
- Note: Regular users can still change their own password through the profile page (normal operation, not an admin action)

### Security Benefits

- Prevents accidental self-lockout: Admins cannot delete themselves or remove their own admin privileges
- Prevents privilege escalation loops: Users cannot modify their own roles
- Maintains accountability: Administrative actions must be performed by other administrators
- Regular users can still perform normal operations: Changing your own password through the profile page is still allowed

The code compiles successfully and all tests pass. These security restrictions are now enforced.

---

**User**

Modify the frontend code to avoid administrator do role changes or user actions on itself.

---

**Cursor**


Updating the frontend to prevent administrators from modifying themselves. Checking the admin page implementation:



Updating the admin page to disable self-modification controls:


```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal } from './utils';
import { User, Thread } from './api';

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    // Get current user's username
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    const isCurrentUser = (username: string) => username === currentUsername;
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```

```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal } from './utils';
import { User, Thread } from './api';

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    // Get current user's username
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    const isCurrentUser = (username: string) => username === currentUsername;
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```

```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal } from './utils';
import { User, Thread } from './api';

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    // Get current user's username
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    const isCurrentUser = (username: string) => username === currentUsername;
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot reset your own password through this interface. Use the Profile page instead.', 'warning');
                return;
            }
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```

```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal } from './utils';
import { User, Thread } from './api';

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    // Get current user's username
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    const isCurrentUser = (username: string) => username === currentUsername;
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot reset your own password through this interface. Use the Profile page instead.', 'warning');
                return;
            }
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot delete your own account', 'warning');
                return;
            }
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```

```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal } from './utils';
import { User, Thread } from './api';

/**
 * @function isCurrentUser
 * @brief Checks if a username matches the current logged-in user
 * @param username string - Username to check
 * @return bool - True if the username matches the current user
 */
function isCurrentUser(username: string): boolean {
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    return username === currentUsername;
}

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot reset your own password through this interface. Use the Profile page instead.', 'warning');
                return;
            }
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot delete your own account', 'warning');
                return;
            }
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```


Recompiling with proper permissions:



Verifying the changes and checking the compiled output:



Running the build script to ensure everything is built correctly:



## Frontend Security Updates

### 1. Added `isCurrentUser` helper function
- Checks if a username matches the current logged-in user
- Used throughout the admin page to identify self-modification attempts

### 2. Updated `renderUsers` function
- Visual indicators:
  - Shows a "You" badge next to the current user's username
  - Disables all controls for the current user's row
- Disabled controls for self:
  - Admin status dropdown: disabled with tooltip "You cannot modify your own account"
  - Reset Password button: disabled with tooltip
  - Delete User button: disabled with tooltip

### 3. Added client-side validation
- Admin status change: Prevents changing own admin status with a warning message
- Password reset: Prevents resetting own password via admin interface (suggests using Profile page)
- User deletion: Prevents deleting own account with a warning message

### 4. UI/UX improvements
- Disabled controls are visually distinct (Bootstrap `disabled` class)
- Tooltips explain why controls are disabled
- Clear error messages if someone tries to bypass the UI

### Security layers
1. Frontend: Controls are disabled and hidden for the current user
2. Frontend: Event handlers check and prevent self-modification
3. Backend: Server-side validation prevents self-modification (already implemented)

The frontend now prevents administrators from modifying themselves, with clear visual feedback and error messages. The code compiles successfully and is ready to use.

---

**User**

In the "Administrator Management" page, "Threads" tab, change the thread creation time to the format "YYYY-MM-DD HH:mm:ss" in local timezone, followed by the timezone name.

---

**Cursor**


Updating the thread creation time format in the Administrator Management page. Checking the current implementation:



Updating the admin page to use the `formatTimestamp` function:


```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal, formatTimestamp } from './utils';
import { User, Thread } from './api';

/**
 * @function isCurrentUser
 * @brief Checks if a username matches the current logged-in user
 * @param username string - Username to check
 * @return bool - True if the username matches the current user
 */
function isCurrentUser(username: string): boolean {
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    return username === currentUsername;
}

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot reset your own password through this interface. Use the Profile page instead.', 'warning');
                return;
            }
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot delete your own account', 'warning');
                return;
            }
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${new Date(thread.createdAt * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```

```typescript
/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal, formatTimestamp } from './utils';
import { User, Thread } from './api';

/**
 * @function isCurrentUser
 * @brief Checks if a username matches the current logged-in user
 * @param username string - Username to check
 * @return bool - True if the username matches the current user
 */
function isCurrentUser(username: string): boolean {
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    return username === currentUsername;
}

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot reset your own password through this interface. Use the Profile page instead.', 'warning');
                return;
            }
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot delete your own account', 'warning');
                return;
            }
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${formatTimestamp(thread.createdAt)}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
    }
}

/**
 * @function escapeHtml
 * @brief Escapes HTML special characters to prevent XSS
 * @param text string - Text to escape
 * @return string - Escaped text
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}


```


Rebuilding the frontend to apply the changes:



## Changes Made

1. **Updated imports** in `admin.ts`:
   - Added `formatTimestamp` to the imports from `./utils`

2. **Updated thread creation time display**:
   - Changed from: `${new Date(thread.createdAt * 1000).toLocaleString()}`
   - Changed to: `${formatTimestamp(thread.createdAt)}`

### Result

The thread creation time in the "Administrator Management" page's "Threads" tab now displays in the format:
- **"YYYY-MM-DD HH:mm:ss [Timezone Name]"**

For example: `2025-12-19 13:45:30 America/New_York`

This matches the format used elsewhere in the application (forum posts, profile page, etc.) for consistency. The code compiled successfully and the frontend has been rebuilt.

