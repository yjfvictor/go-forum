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
