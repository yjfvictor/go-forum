/**
 * @file api.ts
 * @brief API client for communicating with the backend server
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @interface ApiResponse
 * @brief Generic API response structure
 * @var success boolean - Whether the request was successful
 */
interface ApiResponse {
    success: boolean;
}

/**
 * @interface LoginResponse
 * @brief Response structure for login requests
 * @var success boolean - Whether login was successful
 * @var username string - Username of the logged-in user
 * @var isAdmin boolean - Whether the user is an administrator
 */
interface LoginResponse extends ApiResponse {
    username: string;
    isAdmin: boolean;
}

/**
 * @interface SessionResponse
 * @brief Response structure for session information
 * @var authenticated boolean - Whether user is authenticated
 * @var username string - Username if authenticated
 * @var isAdmin boolean - Whether user is admin if authenticated
 */
interface SessionResponse {
    authenticated: boolean;
    username?: string;
    isAdmin?: boolean;
}

/**
 * @interface Post
 * @brief Structure representing a forum post
 * @var id number - Unique post identifier
 * @var author string - Username of the post author
 * @var content string - Content of the post
 * @var timestamp number - Unix timestamp of when post was created
 */
export interface Post {
    id: number;
    author: string;
    content: string;
    timestamp: number;
}

/**
 * @interface Thread
 * @brief Structure representing a forum thread
 * @var id number - Unique thread identifier
 * @var title string - Title of the thread
 * @var author string - Username of the thread creator
 * @var posts Post[] - Array of posts in the thread
 * @var createdAt number - Unix timestamp of when thread was created
 */
export interface Thread {
    id: number;
    title: string;
    author: string;
    posts: Post[];
    createdAt: number;
}

/**
 * @interface User
 * @brief Structure representing a user
 * @var username string - Username of the user
 * @var isAdmin boolean - Whether the user is an administrator
 */
export interface User {
    username: string;
    isAdmin: boolean;
}

/**
 * @function apiRequest
 * @brief Makes an API request to the backend
 * @param endpoint string - API endpoint path
 * @param method string - HTTP method (GET, POST, DELETE, etc.)
 * @param body any - Request body object (will be JSON stringified)
 * @return Promise<any> - Promise that resolves to the response data
 */
function apiRequest(endpoint: string, method: string = 'GET', body?: any): Promise<any> {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(method, '/api' + endpoint, true);
        xhr.setRequestHeader('Content-Type', 'application/json');

        xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    resolve(response);
                } catch (e) {
                    resolve(xhr.responseText);
                }
            } else {
                try {
                    const error = JSON.parse(xhr.responseText);
                    reject(new Error(error.message || xhr.statusText));
                } catch (e) {
                    reject(new Error(xhr.statusText));
                }
            }
        };

        xhr.onerror = function() {
            reject(new Error('Network error'));
        };

        if (body) {
            xhr.send(JSON.stringify(body));
        } else {
            xhr.send();
        }
    });
}

/**
 * @function login
 * @brief Logs in a user
 * @param username string - Username
 * @param password string - Password
 * @return Promise<LoginResponse> - Promise that resolves to login response
 */
export function login(username: string, password: string): Promise<LoginResponse> {
    return apiRequest('/login', 'POST', { username, password });
}

/**
 * @function logout
 * @brief Logs out the current user
 * @return Promise<ApiResponse> - Promise that resolves to logout response
 */
export function logout(): Promise<ApiResponse> {
    return apiRequest('/logout', 'POST');
}

/**
 * @function createAccount
 * @brief Creates a new user account
 * @param username string - Desired username
 * @param password string - Desired password
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function createAccount(username: string, password: string): Promise<ApiResponse> {
    return apiRequest('/create-account', 'POST', { username, password });
}

/**
 * @function getSession
 * @brief Gets current session information
 * @return Promise<SessionResponse> - Promise that resolves to session information
 */
export function getSession(): Promise<SessionResponse> {
    return apiRequest('/session', 'GET');
}

/**
 * @function getThreads
 * @brief Gets all forum threads
 * @return Promise<Thread[]> - Promise that resolves to array of threads
 */
export function getThreads(): Promise<Thread[]> {
    return apiRequest('/threads', 'GET');
}

/**
 * @function getThread
 * @brief Gets a specific thread by ID
 * @param threadId number - Thread ID
 * @return Promise<Thread> - Promise that resolves to thread data
 */
export function getThread(threadId: number): Promise<Thread> {
    return apiRequest('/thread?id=' + threadId, 'GET');
}

/**
 * @function createThread
 * @brief Creates a new forum thread
 * @param title string - Thread title
 * @param content string - Initial post content
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function createThread(title: string, content: string): Promise<ApiResponse> {
    return apiRequest('/create-thread', 'POST', { title, content });
}

/**
 * @function addPost
 * @brief Adds a reply post to a thread
 * @param threadId number - Thread ID
 * @param content string - Post content
 * @return Promise<ApiResponse> - Promise that resolves to creation response
 */
export function addPost(threadId: number, content: string): Promise<ApiResponse> {
    return apiRequest('/add-post', 'POST', { threadId, content });
}

/**
 * @function deletePost
 * @brief Deletes a post from a thread
 * @param threadId number - Thread ID
 * @param postId number - Post ID
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deletePost(threadId: number, postId: number): Promise<ApiResponse> {
    return apiRequest('/delete-post', 'DELETE', { threadId, postId });
}

/**
 * @function deleteThread
 * @brief Deletes an entire thread (admin only)
 * @param threadId number - Thread ID
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deleteThread(threadId: number): Promise<ApiResponse> {
    return apiRequest('/delete-thread', 'DELETE', { threadId });
}

/**
 * @function getUsers
 * @brief Gets all users (admin only)
 * @return Promise<User[]> - Promise that resolves to array of users
 */
export function getUsers(): Promise<User[]> {
    return apiRequest('/users', 'GET');
}

/**
 * @function deleteUser
 * @brief Deletes a user (admin only)
 * @param username string - Username to delete
 * @return Promise<ApiResponse> - Promise that resolves to deletion response
 */
export function deleteUser(username: string): Promise<ApiResponse> {
    return apiRequest('/delete-user', 'DELETE', { username });
}

/**
 * @function resetPassword
 * @brief Resets a user's password
 * @param username string - Username whose password to reset
 * @param newPassword string - New password
 * @return Promise<ApiResponse> - Promise that resolves to reset response
 */
export function resetPassword(username: string, newPassword: string): Promise<ApiResponse> {
    return apiRequest('/reset-password', 'POST', { username, newPassword });
}

/**
 * @function updateUserAdmin
 * @brief Updates a user's admin status (admin only)
 * @param username string - Username to update
 * @param isAdmin boolean - New admin status
 * @return Promise<ApiResponse> - Promise that resolves to update response
 */
export function updateUserAdmin(username: string, isAdmin: boolean): Promise<ApiResponse> {
    return apiRequest('/update-user-admin', 'POST', { username, isAdmin });
}

