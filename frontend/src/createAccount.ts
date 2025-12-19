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

