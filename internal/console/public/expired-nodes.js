// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const EXPIRED_NODES_PAGE_SIZE = 50;

// Where the expired-nodes list resumes, and which opening of the section a
// fetch belongs to, so a slow page never lands in a list reset since.
let expiredNodesPageToken = '';
let expiredNodesGeneration = 0;

document.addEventListener('DOMContentLoaded', () => {
    const expiredNodes = document.getElementById('expired-nodes');
    expiredNodes.addEventListener('toggle', () => {
        if (expiredNodes.open) {
            loadExpiredNodes(true);
        }
    });
    document.getElementById('expired-nodes-more').addEventListener('click', () => loadExpiredNodes(false));
    document.getElementById('table-expired-nodes').addEventListener('click', (e) => {
        const button = e.target.closest('button[data-peer-id]');
        if (button) {
            revokeExpiredNode(button);
        }
    });
});

// Fetched on demand, never by the background refresh: expired rows stay for
// the retention period, and listing them all would slow every refresh.
async function loadExpiredNodes(reset) {
    const more = document.getElementById('expired-nodes-more');
    if (reset) {
        expiredNodesGeneration++;
        expiredNodesPageToken = '';
        more.hidden = true;
        setTableMessage('table-expired-nodes', 5, 'Loading...');
    }
    const generation = expiredNodesGeneration;
    let url = `api/user/nodes?state=expired&page_size=${EXPIRED_NODES_PAGE_SIZE}`;
    if (expiredNodesPageToken) {
        url += `&page_token=${encodeURIComponent(expiredNodesPageToken)}`;
    }

    more.disabled = true;
    try {
        const response = await fetch(url);
        if (response.status === 401 || response.status === 403) {
            showLandingPage();
            throw new Error('Unauthorized. Please login again.');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        if (generation !== expiredNodesGeneration) {
            return;
        }

        const tbody = document.getElementById('table-expired-nodes');
        const rows = (data.nodes || []).map(expiredNodeRow).join('');
        if (reset) {
            tbody.innerHTML = rows;
        } else {
            tbody.insertAdjacentHTML('beforeend', rows);
        }
        if (!tbody.querySelector('tr')) {
            setTableMessage('table-expired-nodes', 5, 'No expired nodes');
        }
        expiredNodesPageToken = data.next_page_token || '';
        more.hidden = !expiredNodesPageToken;
        applySearchFilter();
    } catch (error) {
        if (generation !== expiredNodesGeneration) {
            return;
        }
        console.error('Failed to load expired nodes:', error);
        // A failed "Load more" keeps the rows already shown and the button to retry.
        if (reset) {
            setTableMessage('table-expired-nodes', 5, `Error loading expired nodes: ${error.message}`, true);
        } else {
            showToast(`Failed to load more expired nodes: ${error.message}`, 'error');
        }
    } finally {
        more.disabled = false;
    }
}

// The Revoke button carries the peer ID as data, not inside an inline handler,
// where an HTML-escaped quote would be decoded back into the script.
function expiredNodeRow(node) {
    const expired = node.expire_time ? new Date(node.expire_time).toLocaleString() : '';
    return `
        <tr>
            <td>${peerCell(node.peer_id, node.labels)}</td>
            <td>${escapeHTML(node.role)}</td>
            <td>${escapeHTML(node.owner_id || '')}</td>
            <td>${escapeHTML(expired)}</td>
            <td><button class="btn btn-sm btn-danger" type="button" data-peer-id="${escapeHTML(node.peer_id)}">Revoke</button></td>
        </tr>
    `;
}

// Paging resumes after the last row served, so dropping a revoked row never
// shifts the next page.
async function revokeExpiredNode(button) {
    if (!confirm('Revoke this node? It can no longer renew its expired session or rejoin the mesh.')) {
        return;
    }
    button.disabled = true;
    try {
        await actionRequest(`api/user/revoke?id=${encodeURIComponent(button.dataset.peerId)}`);
    } catch (error) {
        // actionRequest already reported the failure.
        button.disabled = false;
        return;
    }
    const tbody = document.getElementById('table-expired-nodes');
    button.closest('tr').remove();
    if (!tbody.querySelector('tr:not([data-filter-empty])')) {
        loadExpiredNodes(true);
    }
}

// The landing page hides the app without a reload, so the next identity to log
// in must not inherit rows, or an in-flight page, fetched for this one.
function resetExpiredNodes() {
    expiredNodesGeneration++;
    expiredNodesPageToken = '';
    document.getElementById('expired-nodes').open = false;
    document.getElementById('table-expired-nodes').innerHTML = '';
    document.getElementById('expired-nodes-more').hidden = true;
}
