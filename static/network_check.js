// static/network_check.js

(function () {
    // 1. Inject the CSS Styles programmatically
    const style = document.createElement('style');
    style.innerHTML = `
        .connection-badge {
            position: fixed;
            top: 25px;   /* Position: Top with breathing room */
            left: 50%;   /* Position: Center Horizontally */
            
            /* Combine centering (X) with hidden slide position (Y) */
            transform: translateX(-50%) translateY(-150%);
            
            padding: 12px 30px;
            border-radius: 50px;
            font-family: "Inter", "Segoe UI", Arial, sans-serif;
            font-weight: 600;
            font-size: 0.95rem;
            letter-spacing: 0.3px;
            
            /* Modern styling */
            z-index: 10000;
            align-items: center;
            gap: 10px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(8px);
            
            /* Hidden by default with transition for smooth fade */
            opacity: 0;
            visibility: hidden;
            
            /* Smooth Bouncy Animation */
            transition: all 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            display: flex; 
        }

        /* State: Visible */
        .connection-badge.show {
            opacity: 1;
            visibility: visible;
            /* Reset Y to 0 to slide in, keep X centered */
            transform: translateX(-50%) translateY(0);
        }

        /* Style: Offline (Modern Red) */
        .connection-badge.offline {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            box-shadow: 0 8px 20px rgba(220, 53, 69, 0.4);
        }

        /* Style: Online (Modern Green) */
        .connection-badge.online {
            background: linear-gradient(135deg, #28a745, #218838);
            color: white;
            box-shadow: 0 8px 20px rgba(40, 167, 69, 0.4);
        }
    `;
    document.head.appendChild(style);

    // 2. Inject the HTML Badge into the body
    const badge = document.createElement('div');
    badge.id = 'connectionBadge';
    badge.className = 'connection-badge'; // Base class
    document.body.appendChild(badge);

    // 3. Logic variables
    let hideTimeout;

    // Function to handle Online state
    function showOnline() {
        clearTimeout(hideTimeout); // Clear existing timer if any

        // Update style and text
        badge.className = 'connection-badge online show';
        badge.innerHTML = '✅ You are back online';

        // Fade out after 3 seconds
        hideTimeout = setTimeout(() => {
            badge.classList.remove('show');
        }, 3000);
    }

    // Function to handle Offline state
    function showOffline() {
        clearTimeout(hideTimeout); // Don't hide while offline

        // Update style and text 
        badge.className = 'connection-badge offline show';
        badge.innerHTML = '⚠️ No Connection';
    }

    // 4. Event Listeners
    window.addEventListener('online', showOnline);
    window.addEventListener('offline', showOffline);

    // Initial Check on Load
    if (!navigator.onLine) {
        showOffline();
    }
})();