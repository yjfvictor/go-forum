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
