document.addEventListener('DOMContentLoaded', () => {
    let refreshInterval;

    function getStatusClasses(status) {
        if (status === 'MALICIOUS_DETECTED') return 'bg-red-500 text-white';
        if (status === 'CLEAN_NO_IOCS') return 'bg-green-500 text-white';
        if (status === 'CLEAN_ANALYZED') return 'bg-gradient-to-r from-yellow-400 to-green-500 text-white';
        return 'bg-yellow-500 text-gray-800';
    }

    function updateTableFromAPI() {
        fetch('/api/analysis_status')
            .then(res => res.json())
            .then(data => {
                let stillAnalyzing = false;
                const rows = document.querySelectorAll('#emailTable tbody tr');

                data.forEach(session => {
                    const row = Array.from(rows).find(r => r.cells[0].innerText == session.id);
                    if (!row) return;

                    const oldStatusCell = row.cells[7];
                    const statusSpan = oldStatusCell.querySelector('[data-status]');
                    const oldStatus = statusSpan ? statusSpan.getAttribute('data-status') : '';
                    const newStatus = session.status;

                    if (newStatus === 'ANALYZING_VT') {
                        stillAnalyzing = true;
                    }

                    if (oldStatus === 'ANALYZING_VT' && newStatus !== 'ANALYZING_VT') {
                        // Status changed: Update row and notify

                        // Update Sender (Cell 3), Receiver (Cell 4), and Subject (Cell 5)
                        if (session.sender) row.cells[3].innerText = session.sender;
                        if (session.receiver) {
                            const recs = session.receiver.split(',');
                            row.cells[4].innerText = recs.length > 1 ? recs[0].trim() + '...' : session.receiver;
                            row.cells[4].title = session.receiver;
                        }
                        if (session.subject) row.cells[5].innerText = session.subject;

                        // Update Status with Tailwind classes
                        // Update data attributes for search/filter
                        row.setAttribute('data-url-flags', session.vt_score?.url_flags || 0);
                        row.setAttribute('data-file-flags', session.vt_score?.file_flags || 0);
                        row.setAttribute('data-ip-flags', session.vt_score?.ip_flags || 0);

                        const statusClasses = getStatusClasses(newStatus);
                        oldStatusCell.innerHTML = `<span data-status="${newStatus}" class="px-3 py-1 rounded-full text-xs font-bold ${statusClasses}">${newStatus.replace(/_/g, ' ')}</span>`;

                        const scoreCell = row.cells[6];
                        const totalFlags = session.total_flags ?? 0;

                        // Update Score with Tailwind classes
                        scoreCell.innerHTML = `<div class="text-lg font-bold ${totalFlags > 0 ? 'text-red-600' : 'text-teal-500'}">${totalFlags}</div>`;
                    }
                });

                if (!stillAnalyzing) clearInterval(refreshInterval);
            })
            .catch(() => clearInterval(refreshInterval)); // Stop on error
    }

    // Start polling if there are items being analyzed on page load
    if (document.querySelector('[data-status="ANALYZING_VT"]')) {
        refreshInterval = setInterval(updateTableFromAPI, 5000); // Poll every 5 seconds
    }
});