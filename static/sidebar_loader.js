// static/sidebar_loader.js

(function () {
    const menuItems = [
        {
            text: "New Submission",
            url: "/",
            icon: "https://img.icons8.com/ios/50/submit-document.png"
        },
        {
            text: "Triage Table",
            url: "/table_view",
            icon: "https://img.icons8.com/ios/50/year-view.png"
        },
        {
            text: "Analyze",
            url: "/analyze_dashboard",
            icon: "https://img.icons8.com/ios/50/fine-print--v1.png"
        },
        {
            text: "Info",
            url: "/info",
            icon: "https://img.icons8.com/ios/50/info--v1.png"
        }
    ];

    const style = document.createElement('style');
    style.innerHTML = `
        /* Add padding to body so content isn't hidden behind sidebar */
        body {
            padding-left: 60px; 
        }

        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            width: 50px;
            height: 100vh;
            background: #ffffff;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding-top: 40px;
            overflow: visible;
            z-index: 9999; /* High z-index to stay on top */
            font-family: "Segoe UI", Arial, sans-serif;
        }

        .menu-item {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px; /* Adjusted slightly to fit container */
            height: 40px;
            color: #6d9bff;
            text-decoration: none;
            transition: background 0.25s ease;
            border-radius: 4px;
            margin-bottom: 15px; /* Spacing between icons */
        }

        .menu-item:hover {
            background-color: rgba(0, 0, 0, 0.05); 
        }

        .menu-item.active {
            background-color: #6d9bff;
        }

        .menu-item.active img {
            filter: invert(1) brightness(200%);
        }

        .menu-item img {
            width: 30px;
            height: 30px;
            display: block;
        }

        /* The Tooltip (Span) */
        .menu-item span {
            position: absolute;
            left: 55px; 
            top: 50%;
            transform: translateY(-50%) translateX(10px);
            background: #fff;
            color: #333;
            font-size: 0.9rem;
            padding: 6px 14px;
            border-radius: 8px;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: all 0.25s ease;
            z-index: 10000;
        }

        /* Tooltip Arrow */
        .menu-item span::before {
            content: "";
            position: absolute;
            left: -6px;
            top: 50%;
            transform: translateY(-50%);
            border-width: 6px;
            border-style: solid;
            border-color: transparent #fff transparent transparent;
        }

        /* Hover Effect */
        .menu-item:hover span {
            opacity: 1;
            transform: translateY(-50%) translateX(0);
        }
    `;
    document.head.appendChild(style);

    const sidebar = document.createElement('div');
    sidebar.className = 'sidebar';

    menuItems.forEach(item => {
        const link = document.createElement('a');
        link.href = item.url;
        link.className = 'menu-item';

        if (window.location.pathname === item.url ||
            (window.location.pathname.startsWith('/detail/') && item.url === '/table_view')) {
            link.classList.add('active');
        }

        const img = document.createElement('img');
        img.src = item.icon;
        img.alt = item.text;

        const span = document.createElement('span');
        span.textContent = item.text;

        link.appendChild(img);
        link.appendChild(span);
        sidebar.appendChild(link);
    });

    document.body.appendChild(sidebar);

})();