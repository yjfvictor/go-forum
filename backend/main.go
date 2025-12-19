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
