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

