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

