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

