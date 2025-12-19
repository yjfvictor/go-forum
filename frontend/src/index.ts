/**
 * @file index.ts
 * @brief Main forum page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { getThreads, deleteThread, deletePost } from './api';
import { formatTimestamp, showAlert, showConfirmModal } from './utils';
import { Thread, Post } from './api';

/**
 * @function renderThreads
 * @brief Renders all threads on the forum page
 * @param threads Thread[] - Array of threads to render
 */
function renderThreads(threads: Thread[]): void {
    const container = document.getElementById('threadsContainer');
    if (!container) return;
    
    if (threads.length === 0) {
        container.innerHTML = '<p class="text-muted">No threads yet. Be the first to create one!</p>';
        return;
    }
    
    container.innerHTML = '';
    
    threads.forEach(thread => {
        const threadDiv = document.createElement('div');
        threadDiv.className = 'card mb-3';
        threadDiv.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <a href="#thread-${thread.id}" class="text-decoration-none">${escapeHtml(thread.title)}</a>
                </h5>
                <div>
                    <small class="text-muted">Created by ${escapeHtml(thread.author)} on ${formatTimestamp(thread.createdAt)}</small>
                    <button class="btn btn-sm btn-danger ms-2 delete-thread-btn" data-thread-id="${thread.id}" style="display: none;">
                        Delete Thread
                    </button>
                </div>
            </div>
            <div class="card-body">
                ${renderPosts(thread.posts, thread.id)}
                <div class="mt-3">
                    <button class="btn btn-primary reply-btn" data-thread-id="${thread.id}">Reply</button>
                </div>
            </div>
        `;
        
        container.appendChild(threadDiv);
        
        // Add reply functionality
        threadDiv.querySelector('.reply-btn')?.addEventListener('click', () => {
            showReplyForm(thread.id);
        });
        
        // Add delete thread button (admin only)
        const deleteThreadBtn = threadDiv.querySelector('.delete-thread-btn') as HTMLButtonElement;
        if (deleteThreadBtn) {
            const session = (window as any).currentUser;
            if (session && session.isAdmin) {
                deleteThreadBtn.style.display = 'inline-block';
                deleteThreadBtn.addEventListener('click', async () => {
                    const confirmed = await showConfirmModal(
                        'Delete Thread',
                        'Are you sure you want to delete this entire thread? This action cannot be undone.'
                    );
                    if (confirmed) {
                        try {
                            await deleteThread(thread.id);
                            showAlert('Thread deleted successfully', 'success');
                            loadThreads();
                        } catch (error: any) {
                            showAlert('Failed to delete thread: ' + error.message);
                        }
                    }
                });
            }
        }
        
        // Attach delete post handlers for this thread
        threadDiv.querySelectorAll('.delete-post-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const target = e.target as HTMLButtonElement;
                const threadId = parseInt(target.getAttribute('data-thread-id') || '0');
                const postId = parseInt(target.getAttribute('data-post-id') || '0');
                
                const confirmed = await showConfirmModal(
                    'Delete Post',
                    'Are you sure you want to delete this post? This action cannot be undone.'
                );
                
                if (confirmed) {
                    try {
                        await deletePost(threadId, postId);
                        showAlert('Post deleted successfully', 'success');
                        loadThreads();
                    } catch (error: any) {
                        showAlert('Failed to delete post: ' + error.message);
                    }
                }
            });
        });
    });
}

/**
 * @function renderPosts
 * @brief Renders posts in a thread
 * @param posts Post[] - Array of posts to render
 * @param threadId number - ID of the thread
 * @return string - HTML string for the posts
 */
function renderPosts(posts: Post[], threadId: number): string {
    return posts.map((post, index) => {
        const session = (window as any).currentUser;
        const canDelete = session && (session.isAdmin || session.username === post.author);
        const deleteBtn = canDelete ? `
            <button class="btn btn-sm btn-danger delete-post-btn" data-thread-id="${threadId}" data-post-id="${post.id}">
                Delete
            </button>
        ` : '';
        
        return `
            <div class="post mb-3 p-3 border rounded">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <strong>${escapeHtml(post.author)}</strong>
                        <small class="text-muted ms-2">${formatTimestamp(post.timestamp)}</small>
                        ${index === 0 ? ' <span class="badge bg-primary">Original Post</span>' : ''}
                    </div>
                    ${deleteBtn}
                </div>
                <div class="mt-2">${escapeHtml(post.content).replace(/\n/g, '<br>')}</div>
            </div>
        `;
    }).join('');
}

/**
 * @function showReplyForm
 * @brief Shows a form to reply to a thread
 * @param threadId number - ID of the thread to reply to
 */
function showReplyForm(threadId: number): void {
    const modalDiv = document.createElement('div');
    modalDiv.id = 'replyModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Reply to Thread</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <textarea class="form-control" id="replyContent" rows="5" placeholder="Enter your reply..."></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="submitReply">Submit</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    
    document.getElementById('submitReply')?.addEventListener('click', async () => {
        const content = (document.getElementById('replyContent') as HTMLTextAreaElement)?.value;
        if (!content || content.trim() === '') {
            showAlert('Please enter a reply', 'warning');
            return;
        }
        
        try {
            const { addPost } = await import('./api');
            await addPost(threadId, content);
            modal.hide();
            showAlert('Reply posted successfully', 'success');
            loadThreads();
        } catch (error: any) {
            showAlert('Failed to post reply: ' + error.message);
        }
    });
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        modalDiv.remove();
    });
    
    modal.show();
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
 * @function initForumPage
 * @brief Initializes the forum page
 */
export async function initForumPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    const session = (window as any).currentUser;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1>Forum</h1>
                ${session ? `
                    <a href="#create-thread" class="btn btn-primary">Create Thread</a>
                ` : `
                    <a href="#login" class="btn btn-primary">Log in to Create Thread</a>
                `}
            </div>
            <div id="threadsContainer"></div>
        </div>
    `;
    
    await loadThreads();
}

