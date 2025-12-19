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

