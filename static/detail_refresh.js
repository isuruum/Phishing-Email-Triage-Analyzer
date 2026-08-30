document.addEventListener('DOMContentLoaded', () => {
    const analysisId = document.getElementById('analysis-id').value;
    let refreshInterval;

    // Helper to determine status styling
    function getStatusClasses(status) {
        if (status === 'MALICIOUS_DETECTED') return 'bg-red-500 text-white';
        if (status === 'CLEAN_NO_IOCS') return 'bg-green-500 text-white';
        if (status === 'CLEAN_ANALYZED') return 'bg-gradient-to-r from-yellow-400 to-green-500 text-white';
        return 'bg-yellow-500 text-gray-800';
    }

    function updateDetailView() {
        fetch(`/api/detail_data/${analysisId}`)
            .then(res => res.json())
            .then(data => {
                const currentStatus = document.getElementById('status-badge').getAttribute('data-status');

                // 1. Update Status Badge
                const receiverEl = document.getElementById('detail-receiver');
                if (receiverEl && data.receiver) {
                    const recs = data.receiver.split(',');
                    if (recs.length > 1) {
                        receiverEl.innerHTML = `${recs[0]} <span class="text-gray-400">... (+${recs.length - 1} more)</span>`;
                    } else {
                        receiverEl.innerText = data.receiver;
                    }
                    receiverEl.title = data.receiver;
                }

                const statusBadge = document.getElementById('status-badge');
                if (statusBadge && data.status !== currentStatus) {
                    statusBadge.className = `px-3 py-1 rounded-full text-xs font-bold ${getStatusClasses(data.status)}`;
                    statusBadge.innerText = data.status.replace(/_/g, ' ');
                    statusBadge.setAttribute('data-status', data.status);
                }

                // 2. Update Score
                const scoreVal = document.getElementById('score-value');
                if (scoreVal) {
                    scoreVal.innerText = data.total_flags;
                    scoreVal.className = `text-6xl font-bold ${data.total_flags > 0 ? 'text-red-600' : 'text-teal-500'}`;
                }

                // 3. Update VT Stats
                const vtStats = document.getElementById('vt-stats');
                if (vtStats) {
                    const uFlags = data.vt_score.url_flags || 0;
                    const fFlags = data.vt_score.file_flags || 0;
                    const iFlags = data.vt_score.ip_flags || 0;
                    vtStats.innerHTML = `
                        URL Flags: <span class="font-bold ${uFlags > 0 ? 'text-red-500' : ''}">${uFlags}</span> |
                        File Flags: <span class="font-bold ${fFlags > 0 ? 'text-red-500' : ''}">${fFlags}</span> |
                        IP Flags: <span class="font-bold ${iFlags > 0 ? 'text-red-500' : ''}">${iFlags}</span>
                    `;
                }

                // 4. Update URL Table
                const urlTbody = document.getElementById('url-tbody');
                if (urlTbody && data.malicious_urls.length > 0) {
                    document.getElementById('url-section').classList.remove('hidden');
                    document.getElementById('no-url-msg').classList.add('hidden');

                    urlTbody.innerHTML = data.malicious_urls.map(u => {
                        const isMal = u.vt_result.toString().split(' ')[0] !== '0';
                        const vtInfo = u.vt_info || {};
                        return `
                        <tr class="${isMal ? 'bg-red-50' : ''}">
                            <td class="max-w-md truncate" title="${u.url}">${u.url}</td>
                            <td>
                                <span class="${isMal ? 'text-red-600 font-bold' : 'text-green-600 font-medium'}">
                                    ${u.vt_result}
                                </span>
                            </td>
                            <td class="text-xs text-gray-500">
                                ${vtInfo.first_seen ? `First Seen: ${vtInfo.first_seen}<br>` : ''}
                                ${vtInfo.reputation ? `Reputation: ${vtInfo.reputation}<br>` : ''}
                                ${vtInfo.category ? `Category: ${vtInfo.category}` : ''}
                            </td>
                            <td>
                                <a href="/full_vt_report/url/${encodeURIComponent(u.url)}" target="_blank" class="text-blue-600 hover:underline text-xs font-bold">View Report ↗</a>
                            </td>
                        </tr>`;
                    }).join('');
                }

                // 5. Update File Table
                const fileTbody = document.getElementById('file-tbody');
                if (fileTbody && data.attachment_hashes.length > 0) {
                    document.getElementById('file-section').classList.remove('hidden');
                    document.getElementById('no-file-msg').classList.add('hidden');

                    fileTbody.innerHTML = data.attachment_hashes.map(f => {
                        const isMal = f.vt_result.toString().split(' ')[0] !== '0';
                        return `
                        <tr class="${isMal ? 'bg-red-50' : ''}">
                            <td class="font-medium">${f.filename}</td>
                            <td><code class="font-medium text-gray-800">${f.hash}</code></td>
                            <td>
                                <span class="${isMal ? 'text-red-600 font-bold' : 'text-green-600 font-medium'}">
                                    ${f.vt_result}
                                </span>
                            </td>
                            <td>
                                <a href="/full_vt_report/file/${f.hash}" target="_blank" class="text-blue-600 hover:underline text-xs font-bold">View Report ↗</a>
                            </td>
                        </tr>`;
                    }).join('');
                }

                // 6. Update IPs
                const ipContainer = document.getElementById('ip-container');
                if (ipContainer && data.received_ips.length > 0) {
                    document.getElementById('no-ip-msg').classList.add('hidden');
                    ipContainer.innerHTML = data.received_ips.map(ipObj => {
                        const ip = ipObj.value;
                        const vtResult = ipObj.vt_result;
                        const isMalicious = vtResult && vtResult.toString().split(' ')[0] !== '0';

                        return `
                        <div class="flex items-center bg-white border ${isMalicious ? 'border-red-300 bg-red-50' : 'border-gray-200'} rounded px-3 py-2 shadow-sm">
                            <code class="mr-2">${ip}</code>
                            ${vtResult ? `<span class="text-xs font-bold mr-2 ${isMalicious ? 'text-red-600' : 'text-green-600'}">${vtResult}</span>` : ''}
                            <a href="/full_vt_report/ip_address/${ip}" target="_blank" class="text-blue-600 hover:text-blue-800 text-xs">↗</a>
                        </div>
                    `}).join('');
                }

                // Stop polling if analysis is complete
                if (data.status !== 'ANALYZING_VT' && data.status !== 'PENDING') {
                    clearInterval(refreshInterval);
                }
            })
            .catch(err => console.error("Polling error:", err));
    }

    // Start polling if currently analyzing
    const initialStatus = document.getElementById('status-badge').getAttribute('data-status');
    if (initialStatus === 'ANALYZING_VT' || initialStatus === 'PENDING') {
        refreshInterval = setInterval(updateDetailView, 3000); // Poll every 3 seconds
    }
});