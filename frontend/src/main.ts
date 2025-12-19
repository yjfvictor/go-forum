/**
 * @file main.ts
 * @brief Main entry point for the frontend application
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getSession } from './api';
import { initForumPage } from './index';
import { initLoginPage } from './login';
import { initCreateAccountPage } from './createAccount';
import { initCreateThreadPage } from './createThread';
import { initProfilePage } from './profile';
import { initAdminPage } from './admin';

/**
 * @var currentUser
 * @brief Current user session information
 */
let currentUser: { username: string; isAdmin: boolean } | null = null;

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
 * @function updateNavigation
 * @brief Updates the navigation bar based on current session
 */
function updateNavigation(): void {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    navLinks.innerHTML = '';
    
    if (currentUser) {
        navLinks.innerHTML = `
            <li class="nav-item d-flex align-items-center me-2">
                <span class="text-light me-2">${escapeHtml(currentUser.username)}</span>
                <a class="nav-link btn btn-outline-primary" href="#" id="profileLink">Profile</a>
            </li>
            ${currentUser.isAdmin ? `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-warning me-2" href="#" id="adminLink">Administrator Management</a>
            </li>
            ` : ''}
            <li class="nav-item">
                <a class="nav-link btn btn-outline-danger" href="#" id="logoutLink">Log out</a>
            </li>
        `;
        
        document.getElementById('logoutLink')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const { logout } = await import('./api');
            try {
                await logout();
                currentUser = null;
                (window as any).currentUser = null;
                window.location.href = '/';
            } catch (error: any) {
                const { showAlert } = await import('./utils');
                showAlert('Failed to log out: ' + error.message);
            }
        });
        
        document.getElementById('profileLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#profile';
        });
        
        if (currentUser.isAdmin) {
            document.getElementById('adminLink')?.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/#admin';
            });
        }
    } else {
        navLinks.innerHTML = `
            <li class="nav-item">
                <a class="nav-link btn btn-outline-primary me-2" href="#" id="createAccountLink">Create account</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-success" href="#" id="loginLink">Log in</a>
            </li>
        `;
        
        document.getElementById('createAccountLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#create-account';
        });
        
        document.getElementById('loginLink')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/#login';
        });
    }
}

/**
 * @function loadPage
 * @brief Loads the appropriate page based on the hash in the URL
 */
async function loadPage(): Promise<void> {
    const hash = window.location.hash.substring(1);
    
    switch (hash) {
        case 'login':
            await initLoginPage();
            break;
        case 'create-account':
            await initCreateAccountPage();
            break;
        case 'create-thread':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initCreateThreadPage();
            break;
        case 'profile':
            if (!currentUser) {
                window.location.href = '/#login';
                return;
            }
            await initProfilePage();
            break;
        case 'admin':
            if (!currentUser || !currentUser.isAdmin) {
                window.location.href = '/';
                return;
            }
            await initAdminPage();
            break;
        default:
            await initForumPage();
            break;
    }
    
    // Update currentUser reference after page load
    (window as any).currentUser = currentUser;
}

/**
 * @function init
 * @brief Initializes the application
 */
async function init(): Promise<void> {
    try {
        const session = await getSession();
        if (session.authenticated && session.username) {
            currentUser = {
                username: session.username,
                isAdmin: session.isAdmin || false
            };
        } else {
            currentUser = null;
        }
    } catch (error) {
        currentUser = null;
    }
    
    // Expose currentUser to window for other modules
    (window as any).currentUser = currentUser;
    
    updateNavigation();
    await loadPage();
    
    // Listen for hash changes
    window.addEventListener('hashchange', loadPage);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

