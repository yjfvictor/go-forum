/**
 * @file admin.ts
 * @brief Administrator management page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getUsers, deleteUser, resetPassword, updateUserAdmin, getThreads, deleteThread, deletePost } from './api';
import { showAlert, showConfirmModal, formatTimestamp } from './utils';
import { User, Thread } from './api';

/**
 * @function isCurrentUser
 * @brief Checks if a username matches the current logged-in user
 * @param username string - Username to check
 * @return bool - True if the username matches the current user
 */
function isCurrentUser(username: string): boolean {
    const session = (window as any).currentUser;
    const currentUsername = session ? session.username : '';
    return username === currentUsername;
}

/**
 * @function renderUsers
 * @brief Renders the user management table
 * @param users User[] - Array of users to render
 */
function renderUsers(users: User[]): void {
    const container = document.getElementById('usersContainer');
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="text-muted">No users found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        const isSelf = isCurrentUser(user.username);
        const disabledAttr = isSelf ? 'disabled' : '';
        const disabledClass = isSelf ? 'disabled' : '';
        const disabledTitle = isSelf ? ' title="You cannot modify your own account"' : '';
        
        tableHTML += `
            <tr>
                <td>${escapeHtml(user.username)}${isSelf ? ' <span class="badge bg-info">You</span>' : ''}</td>
                <td>
                    <select class="form-select form-select-sm admin-status-select ${disabledClass}" data-username="${escapeHtml(user.username)}" style="width: auto; display: inline-block;" ${disabledAttr}${disabledTitle}>
                        <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
                        <option value="true" ${user.isAdmin ? 'selected' : ''}>Administrator</option>
                    </select>
                </td>
                <td>
                    <button class="btn btn-sm btn-warning reset-password-btn me-2 ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Reset Password
                    </button>
                    <button class="btn btn-sm btn-danger delete-user-btn ${disabledClass}" data-username="${escapeHtml(user.username)}" ${disabledAttr}${disabledTitle}>
                        Delete User
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach event handlers
    document.querySelectorAll('.admin-status-select').forEach(select => {
        const selectElement = select as HTMLSelectElement;
        if (selectElement.disabled) return; // Skip disabled (self) elements
        
        select.addEventListener('change', async (e) => {
            const target = e.target as HTMLSelectElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot change your own admin status', 'warning');
                loadUsers(); // Reload to revert change
                return;
            }
            
            const isAdmin = target.value === 'true';
            
            try {
                await updateUserAdmin(username, isAdmin);
                showAlert(`User ${username} ${isAdmin ? 'promoted to' : 'demoted from'} administrator`, 'success');
                loadUsers();
            } catch (error: any) {
                showAlert('Failed to update user: ' + error.message);
                loadUsers(); // Reload to revert change
            }
        });
    });
    
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot reset your own password through this interface. Use the Profile page instead.', 'warning');
                return;
            }
            
            const modalDiv = document.createElement('div');
            modalDiv.id = 'resetPasswordModal';
            modalDiv.className = 'modal fade';
            modalDiv.setAttribute('tabindex', '-1');
            modalDiv.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Reset Password for ${escapeHtml(username)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="resetPasswordInput" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="resetPasswordInput" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="confirmResetPassword">Reset Password</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modalDiv);
            
            const modal = new (window as any).bootstrap.Modal(modalDiv);
            
            document.getElementById('confirmResetPassword')?.addEventListener('click', async () => {
                const newPassword = (document.getElementById('resetPasswordInput') as HTMLInputElement)?.value;
                if (!newPassword || newPassword.length < 3) {
                    showAlert('Password must be at least 3 characters long', 'warning');
                    return;
                }
                
                try {
                    await resetPassword(username, newPassword);
                    modal.hide();
                    showAlert(`Password reset successfully for ${username}`, 'success');
                } catch (error: any) {
                    showAlert('Failed to reset password: ' + error.message);
                }
            });
            
            modalDiv.addEventListener('hidden.bs.modal', () => {
                modalDiv.remove();
            });
            
            modal.show();
        });
    });
    
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        const buttonElement = btn as HTMLButtonElement;
        if (buttonElement.disabled) return; // Skip disabled (self) elements
        
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const username = target.getAttribute('data-username') || '';
            
            // Double-check: prevent self-modification
            if (isCurrentUser(username)) {
                showAlert('You cannot delete your own account', 'warning');
                return;
            }
            
            const confirmed = await showConfirmModal(
                'Delete User',
                `Are you sure you want to delete user "${username}"? This action cannot be undone.`
            );
            
            if (confirmed) {
                try {
                    await deleteUser(username);
                    showAlert(`User ${username} deleted successfully`, 'success');
                    loadUsers();
                } catch (error: any) {
                    showAlert('Failed to delete user: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function renderThreads
 * @brief Renders the thread management section
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsAdminContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads found.</p>';
        return;
    }
    
    let tableHTML = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Author</th>
                    <th>Posts</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    threads.forEach(thread => {
        tableHTML += `
            <tr>
                <td>${thread.id}</td>
                <td>${escapeHtml(thread.title)}</td>
                <td>${escapeHtml(thread.author)}</td>
                <td>${thread.posts.length}</td>
                <td>${formatTimestamp(thread.createdAt)}</td>
                <td>
                    <button class="btn btn-sm btn-danger delete-thread-admin-btn" data-thread-id="${thread.id}">
                        Delete Thread
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Attach delete thread handlers
    document.querySelectorAll('.delete-thread-admin-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target as HTMLButtonElement;
            const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
            
            const confirmed = await showConfirmModal(
                'Delete Thread',
                'Are you sure you want to delete this entire thread? This action cannot be undone.'
            );
            
            if (confirmed) {
                try {
                    await deleteThread(threadId);
                    showAlert('Thread deleted successfully', 'success');
                    loadThreads();
                } catch (error: any) {
                    showAlert('Failed to delete thread: ' + error.message);
                }
            }
        });
    });
}

/**
 * @function loadUsers
 * @brief Loads and displays all users
 */
async function loadUsers(): Promise<void> {
    try {
        const users = await getUsers();
        renderUsers(users);
    } catch (error: any) {
        showAlert('Failed to load users: ' + error.message);
    }
}

/**
 * @function loadThreads
 * @brief Loads and displays all threads
 */
async function loadThreads(): Promise<void> {
    try {
        const threads = await getThreads();
        renderThreads(threads);
    } catch (error: any) {
        showAlert('Failed to load threads: ' + error.message);
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
 * @function initAdminPage
 * @brief Initializes the administrator management page
 */
export async function initAdminPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    if (!session || !session.isAdmin) {
        window.location.href = '/';
        return;
    }
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <h1>Administrator Management</h1>
            
            <ul class="nav nav-tabs mt-4" id="adminTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                        Users
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="threads-tab" data-bs-toggle="tab" data-bs-target="#threads" type="button" role="tab">
                        Threads
                    </button>
                </li>
            </ul>
            
            <div class="tab-content mt-3" id="adminTabContent">
                <div class="tab-pane fade show active" id="users" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">User Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="usersContainer"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="threads" role="tabpanel">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Thread Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="threadsAdminContainer"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    await loadUsers();
    await loadThreads();
}

