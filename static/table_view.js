// --- Utility function to format the status badge ---
function formatStatus(status) {
    const displayStatus = status.replace('_', ' ');
    return `<span class="status-badge ${status}">${displayStatus}</span>`;
}

// --- Utility function to format the VT score ---
function formatScore(vtScoreJson) {
}

// --- Main function to fetch and draw the table ---
function updateDashboard() {
    const apiUrl = '/analysis_status';
    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector('#analysisTable tbody');
            tbody.innerHTML = '';

            data.forEach(email => {
                const row = tbody.insertRow();

                const detailUrlBase = document.getElementById('detail-url-base').value;

                // Action Cell: View Details and Delete Button
                const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
                const actionCell = row.insertCell();
                actionCell.innerHTML = `
                    <a href="${detailUrlBase.replace('0', email.id)}">View Details</a>
                    
                    <form method="POST" action="/delete/${email.id}" style="display:inline; margin-left: 10px;">
                        <input type="hidden" name="csrf_token" value="${csrfToken}"/>
                        <button type="submit" style="background: none; border: none; color: #dc3545; cursor: pointer; font-size: 1.2em;" 
                                title="Delete Record"
                                onclick="return confirm('Are you sure you want to delete analysis ID ${email.id}?');">
                            🗑️
                        </button>
                    </form>
                `;
            });
        })
        .catch(error => console.error('Error fetching analysis status:', error));
}

document.addEventListener('DOMContentLoaded', () => {
    const messageElement = document.querySelector('.message');
    if (messageElement) {
        setTimeout(() => {
            messageElement.classList.add('fade-out');

            // ✅ After fade completes, fully remove the element
            setTimeout(() => {
                messageElement.remove();
            }, 1000); // matches transition duration
        }, 4000); // delay before fading (4 seconds)
    }
});