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
