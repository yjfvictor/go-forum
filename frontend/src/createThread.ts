/**
 * @file createThread.ts
 * @brief Thread creation page implementation
 * @date 2025-12-19
 * @author Victor Yeh
 */

import { createThread } from './api';
import { showAlert } from './utils';

/**
 * @function initCreateThreadPage
 * @brief Initializes the create thread page
 */
export async function initCreateThreadPage(): Promise<void> {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;
    
    mainContent.innerHTML = `
        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="mb-0">Create Thread</h3>
                        </div>
                        <div class="card-body">
                            <form id="createThreadForm">
                                <div class="mb-3">
                                    <label for="threadTitle" class="form-label">Title</label>
                                    <input type="text" class="form-control" id="threadTitle" required>
                                </div>
                                <div class="mb-3">
                                    <label for="threadContent" class="form-label">Content</label>
                                    <textarea class="form-control" id="threadContent" rows="10" required></textarea>
                                </div>
                                <div class="d-flex gap-2">
                                    <button type="submit" class="btn btn-primary">Create Thread</button>
                                    <a href="/" class="btn btn-secondary">Cancel</a>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const form = document.getElementById('createThreadForm') as HTMLFormElement;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const title = (document.getElementById('threadTitle') as HTMLInputElement).value;
        const content = (document.getElementById('threadContent') as HTMLTextAreaElement).value;
        
        if (!title || title.trim() === '') {
            showAlert('Please enter a title', 'warning');
            return;
        }
        
        if (!content || content.trim() === '') {
            showAlert('Please enter content', 'warning');
            return;
        }
        
        try {
            const response = await createThread(title, content);
            if (response.success) {
                showAlert('Thread created successfully!', 'success');
                setTimeout(() => {
                    window.location.href = '/';
                }, 1500);
            }
        } catch (error: any) {
            showAlert('Failed to create thread: ' + error.message);
        }
    });
}

