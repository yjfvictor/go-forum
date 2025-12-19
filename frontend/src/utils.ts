/**
 * @file utils.ts
 * @brief Utility functions for the frontend
 * @date 2025-12-19
 * @author Victor Yeh
 */

/**
 * @function formatTimestamp
 * @brief Formats a Unix timestamp to "YYYY-MM-DD HH:mm:ss" format in local timezone
 * @param timestamp number - Unix timestamp
 * @return string - Formatted date string with timezone name
 */
export function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp * 1000);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    const timezoneName = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${timezoneName}`;
}

/**
 * @function showAlert
 * @brief Shows a Bootstrap alert message
 * @param message string - Alert message to display
 * @param type string - Alert type (success, danger, warning, info)
 * @param container HTMLElement - Container element to append alert to
 */
export function showAlert(message: string, type: string = 'danger', container?: HTMLElement): void {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const targetContainer = container || document.body;
    targetContainer.insertBefore(alertDiv, targetContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * @function showConfirmModal
 * @brief Shows a Bootstrap confirmation modal
 * @param title string - Modal title
 * @param message string - Modal message
 * @return Promise<boolean> - Promise that resolves to true if confirmed, false if cancelled
 */
export function showConfirmModal(title: string, message: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
        // Remove existing modal if any
        const existingModal = document.getElementById('confirmModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const modalDiv = document.createElement('div');
        modalDiv.id = 'confirmModal';
        modalDiv.className = 'modal fade';
        modalDiv.setAttribute('tabindex', '-1');
        modalDiv.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>${message}</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="confirmButton">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modalDiv);
        
        const BootstrapModal = (window as any).bootstrap?.Modal;
        if (!BootstrapModal) {
            reject(new Error('Bootstrap Modal not available'));
            return;
        }
        const modal = new BootstrapModal(modalDiv);
        
        const confirmButton = modalDiv.querySelector('#confirmButton');
        if (confirmButton) {
            confirmButton.addEventListener('click', () => {
                modal.hide();
                resolve(true);
            });
        }
        
        modalDiv.addEventListener('hidden.bs.modal', () => {
            if (modalDiv.parentNode) {
                modalDiv.remove();
            }
            resolve(false);
        });
        
        modal.show();
    });
}

