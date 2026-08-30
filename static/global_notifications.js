(function () {
    if (window.GLOBAL_NOTIFICATIONS_LOADED) return;
    window.GLOBAL_NOTIFICATIONS_LOADED = true;

    // --- Configuration ---
    const STORAGE_KEY = 'email_triage_notifications';

    // --- 1. Inject CSS (Idempotent) ---
    if (!document.getElementById('global-toast-styles')) {
        const style = document.createElement('style');
        style.id = 'global-toast-styles';
        style.innerHTML = `
            /* Toast Container */
            #toast-container {
                position: fixed; top: 20px; left: 50%; transform: translateX(-50%); z-index: 9999;
                display: flex; flex-direction: column; gap: 15px;
                pointer-events: none; /* Let clicks pass through empty space */
                width: 90%; max-width: 800px;
            }
            .global-toast {
                width: 100%; padding: 16px 20px;
                background: #fff; border: 1px solid #d1d5db; border-left: 6px solid #ccc;
                border-radius: 4px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
                font-family: "Inter", "Segoe UI", sans-serif; font-size: 0.95rem; color: #333;
                opacity: 0; transform: translateY(-20px);
                transition: all 0.3s ease-out;
                cursor: pointer; pointer-events: auto;
                display: flex; align-items: center;
            }
            .global-toast.show { opacity: 1; transform: translateY(0); }
            .global-toast.success { border-left-color: #28a745; }
            .global-toast.success::before { content: "✓"; color: #28a745; font-weight: bold; margin-right: 10px; font-size: 1.2em; }
            .global-toast.error { border-left-color: #dc3545; }
            .global-toast.error::before { content: "⚠"; color: #dc3545; font-weight: bold; margin-right: 10px; font-size: 1.2em; }
            .global-toast.failed { border-left-color: #EAB308; }
            .global-toast.failed::before { content: "⚠"; color: #EAB308; font-weight: bold; margin-right: 10px; font-size: 1.2em; }

            /* --- Notification Bell --- */
            #notification-bell {
                position: fixed; top: 20px; right: 30px; z-index: 10001;
                width: 45px; height: 45px; background: #fff;
                border-radius: 50%; box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                display: flex; align-items: center; justify-content: center;
                cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;
            }
            #notification-bell:hover { transform: scale(1.05); box-shadow: 0 6px 16px rgba(0,0,0,0.2); }
            #notification-bell img { width: 24px; height: 24px; display: block; }
            
            .bell-badge {
                position: absolute; top: -2px; right: -2px;
                background: #dc3545; color: #fff; font-size: 0.7rem;
                padding: 3px 6px; border-radius: 10px; border: 2px solid #fff;
                font-weight: bold; min-width: 18px; text-align: center;
                display: none;
            }
            .bell-badge.show { display: block; }

            /* --- Notification Panel --- */
            #notification-panel {
                position: fixed; top: 75px; right: 30px; z-index: 10001;
                width: 450px; max-height: 500px; background: #fff;
                border-radius: 12px; box-shadow: 0 15px 40px rgba(0,0,0,0.2);
                display: flex; flex-direction: column;
                opacity: 0; visibility: hidden; transform: translateY(-10px) scale(0.98);
                transition: all 0.25s cubic-bezier(0.25, 0.8, 0.25, 1);
                font-family: "Inter", "Segoe UI", sans-serif;
                border: 1px solid rgba(0,0,0,0.08);
                overflow: hidden;
            }
            #notification-panel.open {
                opacity: 1; visibility: visible; transform: translateY(0) scale(1);
            }
            
            .panel-header {
                padding: 16px 20px; border-bottom: 1px solid #f0f0f0;
                display: flex; justify-content: space-between; align-items: center;
                background: #fafafa; border-radius: 12px 12px 0 0;
            }
            .panel-header h3 { margin: 0; font-size: 1rem; font-weight: 600; color: #333; }
            
            .header-actions { display: flex; gap: 8px; }
            .action-btn {
                background: none; border: none; color: #666;
                font-size: 0.8rem; cursor: pointer; font-weight: 500;
                padding: 4px 8px; border-radius: 4px; transition: background 0.2s;
            }
            .action-btn:hover { background: rgba(0,0,0,0.05); color: #333; }
            .action-btn.delete:hover { background: rgba(220, 53, 69, 0.1); color: #dc3545; }

            .panel-body {
                overflow-y: auto; flex: 1; padding: 0; max-height: 400px;
            }
            .panel-body::-webkit-scrollbar { width: 6px; }
            .panel-body::-webkit-scrollbar-track { background: #f1f1f1; }
            .panel-body::-webkit-scrollbar-thumb { background: #ccc; border-radius: 3px; }

            .empty-state {
                padding: 40px 20px; text-align: center; color: #999; font-size: 0.9rem;
                display: flex; flex-direction: column; align-items: center; gap: 10px;
            }

            .notification-item {
                padding: 16px 20px; border-bottom: 1px solid #f5f5f5;
                cursor: pointer; transition: background 0.2s;
                display: flex; align-items: start; gap: 14px; position: relative;
            }
            .notification-item.unread { background: #f8fbff; }
            .notification-item:hover { background: #f8f9fa; }
            .notification-item:last-child { border-bottom: none; }
            
            .notification-item .icon-box {
                width: 32px; height: 32px; border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                flex-shrink: 0; font-size: 1rem;
            }
            .notification-item.success .icon-box { background: rgba(40, 167, 69, 0.1); color: #28a745; }
            .notification-item.error .icon-box { background: rgba(220, 53, 69, 0.1); color: #dc3545; }
            .notification-item.failed .icon-box { background: rgba(234, 179, 8, 0.1); color: #EAB308; }

            .notification-item .content { flex: 1; }
            .notification-item .msg { font-size: 0.9rem; color: #333; line-height: 1.4; margin-bottom: 4px; }
            .notification-item .time { font-size: 0.75rem; color: #999; }
            
            .notification-item .delete-note {
                opacity: 0; position: absolute; top: 10px; right: 10px;
                background: none; border: none; color: #ccc; cursor: pointer;
                font-size: 1.1rem; padding: 0 5px;
            }
            .notification-item:hover .delete-note { opacity: 1; }
            .notification-item .delete-note:hover { color: #dc3545; }
        `;
        document.head.appendChild(style);
    }

    // --- 2. Elements ---

    // Toast Container
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    // Bell Icon
    let bell = document.getElementById('notification-bell');
    if (!bell) {
        bell = document.createElement('div');
        bell.id = 'notification-bell';
        bell.innerHTML = `
            <img src="https://img.icons8.com/ios/50/appointment-reminders.png" alt="Notifications">
            <span class="bell-badge" id="bell-badge">0</span>
        `;
        document.body.appendChild(bell);
    }

    // Notification Panel
    let panel = document.getElementById('notification-panel');
    if (!panel) {
        panel = document.createElement('div');
        panel.id = 'notification-panel';
        panel.innerHTML = `
            <div class="panel-header">
                <h3>Notifications</h3>
                <div class="header-actions" id="panel-actions">
                    <button class="action-btn" id="mark-read-btn">Mark all read</button>
                    <button class="action-btn delete" id="clear-notifications">Delete All</button>
                </div>
            </div>
            <div class="panel-body" id="notification-list"></div>
        `;
        document.body.appendChild(panel);
    }

    // --- 3. Logic & State ---

    let pendingIds = new Set();
    const badge = document.getElementById('bell-badge');
    const listContainer = document.getElementById('notification-list');
    const clearBtn = document.getElementById('clear-notifications');
    const markReadBtn = document.getElementById('mark-read-btn');
    const panelActions = document.getElementById('panel-actions');

    // Storage Helpers
    function getNotifications() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
        catch (e) { return []; }
    }

    function saveNotifications(notes) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(notes));
        updateBadge();
        renderPanel();
    }

    function addNotification(msg, type, url) {
        const notes = getNotifications();
        // Prevent duplicates from multiple open tabs
        if (notes.some(n => n.msg === msg)) return;

        notes.unshift({
            id: Date.now(),
            msg, type, url,
            read: false,
            timestamp: new Date().toISOString()
        });
        saveNotifications(notes);
    }

    function updateBadge() {
        const count = getNotifications().filter(n => !n.read).length;
        badge.textContent = count > 99 ? '99+' : count;
        badge.classList.toggle('show', count > 0);
    }

    function formatTime(isoString) {
        const diffMins = Math.floor((new Date() - new Date(isoString)) / 60000);
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        return new Date(isoString).toLocaleDateString();
    }

    function renderPanel() {
        const notes = getNotifications();
        listContainer.innerHTML = '';

        if (notes.length === 0) {
            if (panelActions) panelActions.style.display = 'none';
            listContainer.innerHTML = `
                <div class="empty-state">
                    <img src="https://img.icons8.com/ios/50/nothing-found.png" style="opacity:0.3; width:40px;">
                    <span>No notifications</span>
                </div>`;
            return;
        }

        if (panelActions) panelActions.style.display = 'flex';

        notes.forEach(note => {
            const item = document.createElement('div');
            item.className = `notification-item ${note.type} ${!note.read ? 'unread' : ''}`;
            item.innerHTML = `
                <div class="icon-box">${note.type === 'success' ? '✓' : '⚠'}</div>
                <div class="content">
                    <div class="msg">${note.msg}</div>
                    <span class="time">${formatTime(note.timestamp)}</span>
                </div>
                <button class="delete-note" title="Delete">×</button>
            `;

            item.addEventListener('click', (e) => {
                if (e.target.classList.contains('delete-note')) {
                    e.stopPropagation();
                    saveNotifications(getNotifications().filter(n => n.id !== note.id));
                } else if (note.url) {
                    window.location.href = note.url;
                }
            });
            listContainer.appendChild(item);
        });
    }

    // Event Listeners
    bell.addEventListener('click', (e) => {
        e.stopPropagation();
        panel.classList.toggle('open');
        renderPanel();
    });

    clearBtn.addEventListener('click', () => saveNotifications([]));

    if (markReadBtn) {
        markReadBtn.addEventListener('click', () => {
            const notes = getNotifications();
            notes.forEach(n => n.read = true);
            saveNotifications(notes);
        });
    }

    document.addEventListener('click', (e) => {
        if (!panel.contains(e.target) && !bell.contains(e.target)) {
            panel.classList.remove('open');
        }
    });

    // Sync across tabs
    window.addEventListener('storage', (e) => {
        if (e.key === STORAGE_KEY) {
            updateBadge();
            renderPanel();
        }
    });

    // --- 4. Polling Logic ---
    function pollStatus() {
        fetch('/api/analysis_status')
            .then(res => res.json())
            .then(data => {
                data.forEach(item => {
                    // If item is currently analyzing, track it
                    if (item.status === 'ANALYZING_VT') {
                        pendingIds.add(item.id);
                    }
                    // If item WAS analyzing and is now done
                    else if (pendingIds.has(item.id)) {
                        pendingIds.delete(item.id);

                        // Determine message based on status
                        let type = 'success';
                        if (item.status === 'MALICIOUS_DETECTED') type = 'error';
                        else if (item.status === 'FAILED') type = 'failed';

                        const msg = `Analysis complete for ID ${item.id}: ${item.status.replace('_', ' ')}`;
                        const url = `/detail/${item.id}`;

                        showToast(msg, type, url);
                        addNotification(msg, type, url);

                        // Dispatch event to notify other components (like analyze.html) to refresh
                        window.dispatchEvent(new CustomEvent('analysisCompleted', { detail: { id: item.id, status: item.status } }));
                    }
                });
            })
            .catch(err => console.error("Background poll error:", err));
    }

    function showToast(msg, type = 'success', targetUrl = null) {
        const toast = document.createElement('div');
        toast.className = `global-toast ${type}`;
        toast.textContent = msg;

        if (targetUrl) {
            toast.title = "Click to view details";
        }
        container.appendChild(toast);

        // Trigger reflow for animation
        void toast.offsetWidth;
        toast.classList.add('show');

        // Auto remove
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 400);
        }, 6000);

        toast.onclick = () => {
            if (targetUrl) window.location.href = targetUrl;
            toast.remove();
        };
    }

    // Initialize
    updateBadge();
    setInterval(pollStatus, 5000);
    pollStatus(); // Initial check
})();