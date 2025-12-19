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
