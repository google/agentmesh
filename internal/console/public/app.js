const DEFAULT_TAB = 'overview';
const REFRESH_INTERVAL_MS = 15000;
const TOAST_TIMEOUT_MS = 5000;

let refreshTimer = null;
let refreshInFlight = false;
// Last policy the server confirmed, so an edit is never silently overwritten by
// a background refresh or thrown away by a stray click.
let policyBaseline = '';

document.addEventListener('DOMContentLoaded', () => {
    // Each nav item is a real link to its view's hash, so the browser handles the
    // routing and hashchange drives switchTab. This only dismisses the drawer,
    // which is an overlay on mobile.
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => closeSidebar());
    });

    window.addEventListener('hashchange', () => switchTab(tabFromHash()));
    switchTab(tabFromHash());

    document.getElementById('resource-search').addEventListener('input', applySearchFilter);

    const policyEditor = document.getElementById('policy-yaml');
    policyEditor.addEventListener('input', validatePolicyEditor);
    policyEditor.addEventListener('keydown', handlePolicyEditorKeydown);

    // Warn before a reload or a close discards an in-progress policy edit.
    window.addEventListener('beforeunload', (e) => {
        if (policyIsDirty()) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    // Check auth status on load
    checkAuthAndLoad();
});

// Filters every rendered table and router card, so the result stays consistent
// when the operator switches views or a background refresh re-renders a table.
function applySearchFilter() {
    const input = document.getElementById('resource-search');
    const raw = input.value.trim();
    const query = raw.toLowerCase();

    document.querySelectorAll('.data-table tbody').forEach(tbody => {
        tbody.querySelectorAll('tr[data-filter-empty]').forEach(tr => tr.remove());

        const rows = Array.from(tbody.querySelectorAll('tr'));
        const matches = rows.filter(tr => {
            const match = !query || tr.textContent.toLowerCase().includes(query);
            tr.hidden = !match;
            return match;
        });

        if (query && rows.length > 0 && matches.length === 0) {
            const table = tbody.closest('table');
            const tr = document.createElement('tr');
            tr.dataset.filterEmpty = 'true';
            const td = document.createElement('td');
            td.colSpan = table.querySelectorAll('thead th').length || 1;
            td.className = 'text-center';
            td.textContent = `No rows match "${raw}"`;
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
    });

    document.querySelectorAll('.router-item-card').forEach(card => {
        card.hidden = query !== '' && !card.textContent.toLowerCase().includes(query);
    });
}

function tabFromHash() {
    const raw = window.location.hash.replace(/^#/, '');
    let target = raw;
    try {
        target = decodeURIComponent(raw);
    } catch (e) {
        // A malformed escape sequence is just an unknown tab.
    }
    return document.getElementById(`view-${target}`) ? target : DEFAULT_TAB;
}

function startAutoRefresh() {
    if (refreshTimer !== null) {
        return;
    }
    refreshTimer = setInterval(() => {
        // Polling a backgrounded tab only burns control-plane calls.
        if (document.visibilityState !== 'visible' || refreshInFlight) {
            return;
        }
        refreshInFlight = true;
        loadData()
            .catch(() => {})
            .finally(() => { refreshInFlight = false; });
    }, REFRESH_INTERVAL_MS);
}

function stopAutoRefresh() {
    if (refreshTimer !== null) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

window.toggleSidebar = function() {
    document.querySelector('.sidebar').classList.toggle('open');
    document.getElementById('sidebar-scrim').classList.toggle('active');
};

window.closeSidebar = function() {
    document.querySelector('.sidebar').classList.remove('open');
    document.getElementById('sidebar-scrim').classList.remove('active');
};

async function checkAuthAndLoad() {
    try {
        const infoResp = await fetch('info');
        if (infoResp.ok) {
            const info = await infoResp.json();
            const ssoGroup = document.getElementById('sso-login-group');
            if (ssoGroup) {
                ssoGroup.style.display = info.oidc_enabled ? 'block' : 'none';
            }
        }
    } catch (e) {
        console.error("Failed to load console auth info:", e);
    }

    try {
        await loadData();
        showApp();
    } catch (error) {
        showLandingPage();
    }
}

function showApp() {
    document.getElementById('landing-page').classList.remove('active');
    document.getElementById('app-container').style.display = 'flex';
    startAutoRefresh();
}

function showLandingPage() {
    stopAutoRefresh();
    document.getElementById('landing-page').classList.add('active');
    document.getElementById('app-container').style.display = 'none';
}

window.redirectToSSO = function() {
    window.location.href = 'auth/login';
};

// Hands the token to the server, which stores it in an httpOnly cookie and
// attaches it to proxied API calls. Keeping it out of JS reach means an XSS in
// the console cannot read or exfiltrate mesh credentials.
async function startSession(token) {
    const response = await fetch('auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });
    if (!response.ok) {
        throw new Error((await response.text()).trim() || `HTTP ${response.status}`);
    }
}

async function loginWithToken(inputId) {
    const input = document.getElementById(inputId);
    const token = input.value.trim();
    if (!token) {
        return;
    }
    try {
        await startSession(token);
        input.value = '';
        await loadData();
        showApp();
    } catch (error) {
        showToast('Login failed: ' + error.message, 'error');
    }
}

window.loginOIDC = function() {
    loginWithToken('oidc-token-input');
};

window.saveAdminToken = function() {
    loginWithToken('admin-token-input');
};

async function loadData() {
    try {
        // 1. Fetch user-scoped status
        const response = await fetch('api/user/status');
        if (response.status === 401 || response.status === 403) {
            showLandingPage();
            throw new Error('Unauthorized. Please login again.');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        let data = await response.json();
        
        const role = data.user ? data.user.role : 'user';
        const userId = data.user ? data.user.id : '';
        
        // Update UI components depending on Role
        updateUIForRole(role, userId);

        // 2. If user is admin, fetch full unfiltered admin status
        if (role === 'admin') {
            const adminResp = await fetch('api/admin/status');
            if (adminResp.ok) {
                data = await adminResp.json();
            }
        }
        
        // A revoked node is banned, not deleted: the record survives for restore
        // and audit, but it is out of the mesh, so only the admins' revoked list shows it.
        const enrolledNodes = (data.enrolled_nodes || []).filter(node => !node.banned);

        // Update Stats
        const usersCount = (data.users && data.users.length) || 0;
        const nodesCount = enrolledNodes.length;
        const routersCount = (data.active_routers && data.active_routers.length) || 0;
        const reqsCount = (data.enrollment_requests && data.enrollment_requests.length) || 0;
        
        document.getElementById('stat-users').innerText = usersCount;
        document.getElementById('stat-nodes').innerText = nodesCount;
        document.getElementById('stat-routers').innerText = routersCount;
        
        // Count pending
        const pendingCount = (data.enrollment_requests || []).filter(r => r.status === 'ENROLLMENT_STATUS_PENDING').length;
        document.getElementById('stat-pending').innerText = pendingCount;

        // Render Tables & Grid
        if (role === 'admin') {
            renderUsersTable(data.users || []);
            renderEnrollmentsTable(data.enrollment_requests || []);
        } else {
            // Their nav entries are hidden, but clear the placeholders anyway so a
            // stale "Loading..." can never be observed.
            setTableMessage('table-users', 4, 'Restricted to administrators.');
            setTableMessage('table-enrollments', 4, 'Restricted to administrators.');
        }
        renderNodesTable(enrolledNodes, role);
        renderRevokedNodesTable(role === 'admin' ? (data.enrolled_nodes || []).filter(node => node.banned) : []);
        renderServicesTable(data.node_catalog || {}, buildLabelsByPeer(enrolledNodes));
        renderRoutersTable(data.active_routers || []);
        renderRouterTopography(data.active_routers || []);
        renderBootstrapTokensTable(data.bootstrap_tokens || []);

        const policyArea = document.getElementById('policy-yaml');
        if (policyArea && role === 'admin' && !policyIsDirty()) {
            policyArea.value = renderPolicyYAML(data.policy || {});
            policyBaseline = policyArea.value;
            validatePolicyEditor();
        }

        applySearchFilter();
        announce(`${nodesCount} nodes, ${routersCount} routers, ${reqsCount} enrollment requests.`);

    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        const errMsg = `Error loading data: ${error.message}`;
        setTableMessage('table-users', 4, errMsg, true);
        setTableMessage('table-nodes', 5, errMsg, true);
        setTableMessage('table-enrollments', 4, errMsg, true);
        setTableMessage('table-routers', 3, errMsg, true);
        setTableMessage('table-bootstrap', 5, errMsg, true);
        announce(errMsg);
        throw error;
    }
}

// Table renders replace rows wholesale, which a screen reader would otherwise
// never hear about.
function announce(message) {
    const region = document.getElementById('live-status');
    if (region) {
        region.textContent = message;
    }
}

// alert() blocks the event loop, so it also stalls the refresh timer, and it is
// unusable on the mobile layout.
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const text = document.createElement('span');
    text.textContent = message;
    toast.appendChild(text);

    const dismiss = document.createElement('button');
    dismiss.className = 'toast-dismiss';
    dismiss.type = 'button';
    dismiss.setAttribute('aria-label', 'Dismiss notification');
    dismiss.textContent = '\u00d7';
    dismiss.addEventListener('click', () => toast.remove());
    toast.appendChild(dismiss);

    container.appendChild(toast);
    // Errors stay until dismissed; the operator usually needs to act on them.
    if (type !== 'error') {
        setTimeout(() => toast.remove(), TOAST_TIMEOUT_MS);
    }
}

function setTableMessage(tbodyID, colspan, message, isError = false) {
    const tbody = document.getElementById(tbodyID);
    if (!tbody) return;
    const style = isError ? ' style="color: var(--danger)"' : '';
    tbody.innerHTML = `<tr><td colspan="${colspan}" class="text-center"${style}>${escapeHTML(message)}</td></tr>`;
}

function renderUsersTable(users) {
    const tbody = document.getElementById('table-users');
    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center">No users found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr>
            <td><code>${escapeHTML(user.id)}</code></td>
            <td>${escapeHTML(user.role)}</td>
            <td>${escapeHTML(user.email)}</td>
            <td>${user.create_time ? new Date(user.create_time).toLocaleString() : '-'}</td>
        </tr>
    `).join('');
}

// Renders an operator-declared labels map (e.g. {component: "stvv", role:
// "producer"}, from agentmesh-node.yaml's labels: key) as a compact key=value
// list - the closest thing to a node mnemonic that exists today, since Agent Mesh
// has no dedicated name/alias field. Returns '' if there are none.
function formatLabels(labels) {
    const entries = Object.entries(labels || {});
    if (entries.length === 0) {
        return '';
    }
    return entries.map(([k, v]) => `${k}=${v}`).join(', ');
}

// A peer ID cell: the raw ID (still the real, authoritative identifier)
// with its operator-declared labels shown underneath when present.
function peerCell(peerID, labels) {
    const labelText = formatLabels(labels);
    const sub = labelText
        ? `<div class="cell-subtext">${escapeHTML(labelText)}</div>`
        : '';
    return `<code>${escapeHTML(peerID)}</code>${sub}`;
}

// Builds a peer ID -> labels lookup from the enrolled_nodes list, so other
// tables (e.g. Services) can show the same labels next to a bare peer ID
// without a second fetch.
function buildLabelsByPeer(nodes) {
    const byPeer = {};
    for (const node of nodes || []) {
        byPeer[node.peer_id] = node.labels || {};
    }
    return byPeer;
}

function renderNodesTable(nodes, role) {
    const tbody = document.getElementById('table-nodes');
    if (nodes.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center">No enrolled nodes found</td></tr>`;
        return;
    }

    tbody.innerHTML = nodes.map(node => {
        const recovery = !!node.autonomous_recovery;
        const recoveryBadge = recovery
            ? `<span class="badge badge-approved" title="May refresh its credential after the signing key that issued it is retired">Autonomous</span>`
            : `<span class="badge badge-pending" title="Needs a new bootstrap token if offline past the key grace period">Manual</span>`;
        // The flag decides whether a lost device can rejoin on its own key, so
        // only admins get the toggle; owners just see the state.
        const toggle = role === 'admin'
            ? `<button class="btn btn-sm" onclick="setAutonomousRecovery('${escapeHTML(node.peer_id)}', ${recovery ? 'false' : 'true'})">${recovery ? 'Disable recovery' : 'Enable recovery'}</button>`
            : '';
        return `
        <tr>
            <td>${peerCell(node.peer_id, node.labels)}</td>
            <td>${escapeHTML(node.role)}</td>
            <td>${escapeHTML(node.owner_id || '')}</td>
            <td>${recoveryBadge}</td>
            <td>
                <div class="actions-cell">
                    ${toggle}
                    <button class="btn btn-sm btn-danger" onclick="revokeDevice('${escapeHTML(node.peer_id)}')">Revoke</button>
                </div>
            </td>
        </tr>
    `;
    }).join('');
}

window.setAutonomousRecovery = function(peerID, enabled) {
    const prompt = enabled
        ? 'Allow this node to refresh its credential on its own key even after the signing key that issued it is retired? A lost or stolen device with this flag can rejoin the mesh until it is revoked.'
        : 'Disable autonomous recovery? If this node is offline past the key grace period it will need a new bootstrap token to rejoin.';
    if (confirm(prompt)) {
        actionRequest(`api/admin/nodes/${peerID}/autonomous-recovery`, 'POST', { enabled }).catch(() => {});
    }
};

function renderRevokedNodesTable(nodes) {
    document.getElementById('revoked-nodes').hidden = nodes.length === 0;
    document.getElementById('table-revoked-nodes').innerHTML = nodes.map(node => `
        <tr>
            <td>${peerCell(node.peer_id, node.labels)}</td>
            <td>${escapeHTML(node.role)}</td>
            <td>${escapeHTML(node.owner_id || '')}</td>
            <td><button class="btn btn-sm" onclick="restoreNode('${escapeHTML(node.peer_id)}')">Restore</button></td>
        </tr>
    `).join('');
}

window.restoreNode = function(peerID) {
    if (confirm('Restore this node? Its key and the identity behind it may join the mesh again.')) {
        actionRequest(`api/admin/nodes/${peerID}/unban`).catch(() => {});
    }
};

// node_catalog is {peerID: {services: [{name, type, description}], report_time}},
// already restricted server-side to nodes that are still admitted; type is
// the ServiceType enum name ("SERVICE_TYPE_MCP"), shown as its short form.
function serviceTypeLabel(type) {
    return String(type || '').replace(/^SERVICE_TYPE_/, '').toLowerCase() || 'unknown';
}

function renderServicesTable(nodeCatalog, labelsByPeer) {
    const tbody = document.getElementById('table-services');
    const peerIDs = Object.keys(nodeCatalog || {});
    const rows = [];
    for (const peerID of peerIDs) {
        const entry = nodeCatalog[peerID] || {};
        const services = entry.services || [];
        for (const svc of services) {
            if (svc) {
                rows.push({ peerID, reportedAt: entry.report_time, svc });
            }
        }
    }

    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center">No nodes have reported any services yet</td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(({ peerID, reportedAt, svc }) => `
        <tr>
            <td>${escapeHTML(svc.name || '')}</td>
            <td>${escapeHTML(serviceTypeLabel(svc.type))}</td>
            <td>${escapeHTML(svc.description || '')}</td>
            <td>${peerCell(peerID, (labelsByPeer || {})[peerID])}</td>
            <td>${reportedAt ? escapeHTML(new Date(reportedAt).toLocaleString()) : '-'}</td>
        </tr>
    `).join('');
}

function getStatusBadge(status) {
    if (status === 'ENROLLMENT_STATUS_PENDING') {
        return `<span class="badge badge-pending">Pending</span>`;
    } else if (status === 'ENROLLMENT_STATUS_APPROVED') {
        return `<span class="badge badge-approved">Approved</span>`;
    } else if (status === 'ENROLLMENT_STATUS_REJECTED') {
        return `<span class="badge badge-rejected">Rejected</span>`;
    }
    return `<span class="badge">Unknown</span>`;
}

function renderEnrollmentsTable(reqs) {
    const tbody = document.getElementById('table-enrollments');
    if (reqs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center">No enrollment requests found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = reqs.map(req => {
        const isPending = req.status === 'ENROLLMENT_STATUS_PENDING';
        let actions = '';
        if (isPending) {
            actions = `
                <div class="actions-cell">
                    <button class="btn btn-sm btn-success" onclick="approveEnrollment('${escapeHTML(req.id)}')">Approve</button>
                    <button class="btn btn-sm btn-danger" onclick="rejectEnrollment('${escapeHTML(req.id)}')">Reject</button>
                </div>
            `;
        }
        return `
        <tr>
            <td><code>${escapeHTML(req.id)}</code></td>
            <td>${getStatusBadge(req.status)}</td>
            <td>${escapeHTML(req.create_time || '')}</td>
            <td>${actions}</td>
        </tr>
        `;
    }).join('');
}

function renderRoutersTable(routers) {
    const tbody = document.getElementById('table-routers');
    if (routers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="text-center">No active routers found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = routers.map(router => `
        <tr>
            <td><code>${escapeHTML(router.peer_id)}</code></td>
            <td>${router.addresses ? router.addresses.map(addr => escapeHTML(addr)).join('<br>') : '-'}</td>
            <td>${escapeHTML(router.expire_time || '')}</td>
        </tr>
    `).join('');
}

async function actionRequest(url, method = 'POST', body = null) {
    try {
        const options = {
            method,
            headers: {}
        };
        if (body) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(url, options);
        if (response.status === 401 || response.status === 403) {
            showLandingPage();
            throw new Error('Unauthorized. Please login again.');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        // Return JSON if present, otherwise just true
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        }
        
        // Refresh data
        loadData();
        return true;
    } catch (error) {
        showToast('Action failed: ' + error.message, 'error');
        throw error;
    }
}

function approveEnrollment(id) {
    if (confirm('Are you sure you want to approve this enrollment?')) {
        actionRequest(`api/admin/enrollments/${id}/approve`);
    }
}

function rejectEnrollment(id) {
    if (confirm('Are you sure you want to reject this enrollment?')) {
        actionRequest(`api/admin/enrollments/${id}/reject`);
    }
}

function revokeDevice(id) {
    if (confirm('Are you sure you want to revoke this device? This will terminate its connection.')) {
        actionRequest(`api/user/revoke?id=${id}`);
    }
}

window.logout = function() {
    stopAutoRefresh();
    window.location.href = 'auth/logout';
};

function updateUIForRole(role, userId) {
    // 1. Update Profile Display
    const profileSpan = document.querySelector('.user-profile span');
    if (profileSpan) {
        profileSpan.innerText = role === 'admin' ? 'Admin' : (userId ? userId.substring(0, 15) + '...' : 'User');
    }
    const avatarDiv = document.querySelector('.user-profile .avatar');
    if (avatarDiv) {
        avatarDiv.innerText = role === 'admin' ? 'A' : 'U';
    }

    // 2. Hide/Show Navigation Options
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        const target = item.getAttribute('data-target');
        if (target === 'users' || target === 'enrollments' || target === 'policy') {
            if (role === 'admin') {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
                if (item.classList.contains('active')) {
                    switchTab('overview');
                }
            }
        }
    });

    // 3. Hide/Show Form Owner ID input
    const ownerInput = document.getElementById('token-owner');
    if (ownerInput) {
        const group = ownerInput.closest('.input-group');
        if (group) {
            // Only admins may set an owner; for everyone else the server infers it
            // from the session, so the field is hidden and left empty.
            group.style.display = role === 'admin' ? 'flex' : 'none';
            if (role !== 'admin') {
                ownerInput.value = '';
            }
        }
    }
    // Same for autonomous recovery: the server refuses it from non-admins.
    const recoveryGroup = document.getElementById('token-recovery-group');
    if (recoveryGroup) {
        recoveryGroup.style.display = role === 'admin' ? 'flex' : 'none';
        if (role !== 'admin') {
            document.getElementById('token-recovery').checked = false;
        }
    }
    
    // 4. Hide users/pending sections from stats grid for normal users
    const usersCard = document.getElementById('stat-users').closest('.stat-card');
    const pendingCard = document.getElementById('stat-pending').closest('.stat-card');
    if (usersCard && pendingCard) {
        if (role === 'admin') {
            usersCard.style.display = 'block';
            pendingCard.style.display = 'block';
        } else {
            usersCard.style.display = 'none';
            pendingCard.style.display = 'none';
        }
    }
}

function policyIsDirty() {
    const area = document.getElementById('policy-yaml');
    return area !== null && area.value !== policyBaseline;
}

// The control plane sends the policy as protojson. Showing it as YAML keeps the
// document readable without either side hand-maintaining a second field list.
function renderPolicyYAML(policy) {
    if (!policy) {
        return '';
    }
    try {
        return jsyaml.dump(policy, { indent: 2, lineWidth: -1, noRefs: true });
    } catch (err) {
        // Better to show the operator the raw document than an empty editor.
        return JSON.stringify(policy, null, 2);
    }
}

function switchTab(target) {
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    let activeNav = Array.from(navItems).find(n => n.getAttribute('data-target') === target);
    // A shared or stale link can point at a view this role is not allowed to see.
    if (!activeNav || activeNav.style.display === 'none') {
        target = DEFAULT_TAB;
        activeNav = Array.from(navItems).find(n => n.getAttribute('data-target') === target);
    }

    const onPolicy = document.getElementById('view-policy').classList.contains('active');
    if (onPolicy && target !== 'policy' && policyIsDirty()) {
        if (!confirm('You have unsaved policy changes. Leave without saving?')) {
            // The hash may already have moved, e.g. via the back button.
            if (tabFromHash() !== 'policy') {
                window.location.hash = 'policy';
            }
            return;
        }
    }

    navItems.forEach(n => n.classList.remove('active'));
    viewSections.forEach(v => v.classList.remove('active'));

    if (activeNav) {
        activeNav.classList.add('active');
        activeNav.setAttribute('aria-current', 'page');
    }
    navItems.forEach(n => {
        if (n !== activeNav) n.removeAttribute('aria-current');
    });

    const activeView = document.getElementById(`view-${target}`);
    if (activeView) activeView.classList.add('active');

    // Guarded so the resulting hashchange does not re-enter this function.
    if (tabFromHash() !== target) {
        window.location.hash = target;
    }
}

function renderRouterTopography(routers) {
    const topoList = document.getElementById('router-topography-list');
    if (routers.length === 0) {
        topoList.innerHTML = '<div style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 2rem;">No active routers online in the mesh.</div>';
        return;
    }

    topoList.innerHTML = routers.map(r => {
        const conns = r.connected_peers || [];
        const dhtSize = r.dht_size || 0;
        const peerID = String(r.peer_id || '');

        let remaining = 0;
        if (r.expire_time) {
            remaining = Math.max(0, Math.floor((new Date(r.expire_time) - new Date()) / 1000));
        }
        const leaseClass = remaining === 0 ? 'badge-rejected' : 'badge-approved';
        const leaseLabel = remaining === 0 ? 'Lease expired' : `Lease: ${formatDuration(remaining)}`;

        const peersHTML = conns.length === 0
            ? '<li>No connected peers</li>'
            : conns.map(p => `<li>${escapeHTML(String(p).substring(0, 15))}... (${escapeHTML(String(p).slice(-8))})</li>`).join('');

        return `
            <div class="router-item-card">
                <div class="router-header">
                    <span class="router-peer-id" title="${escapeHTML(peerID)}">${escapeHTML(peerID.substring(0, 12))}...${escapeHTML(peerID.slice(-8))}</span>
                    <span class="badge ${leaseClass}">${escapeHTML(leaseLabel)}</span>
                </div>
                <div class="router-metrics">
                    <div class="router-metric-item">
                        <div class="router-metric-val">${conns.length}</div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary)">Connections</div>
                    </div>
                    <div class="router-metric-item" style="border-left: 1px solid var(--border-color)">
                        <div class="router-metric-val">${escapeHTML(String(dhtSize))}</div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary)">DHT Size</div>
                    </div>
                </div>
                <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-secondary)">Connected Peers:</div>
                <ul class="router-peers-list">${peersHTML}</ul>
            </div>
        `;
    }).join('');
}

function renderBootstrapTokensTable(tokens) {
    const tbody = document.getElementById('table-bootstrap');
    if (tokens.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center">No active bootstrap tokens found</td></tr>`;
        return;
    }

    tbody.innerHTML = tokens.map(token => {
        const expiresAt = token.expire_time ? new Date(token.expire_time).toLocaleString() : 'Never';
        const revoked = !!token.revoke_time;
        const status = revoked
            ? `<span class="badge badge-rejected">Revoked</span>`
            : `<span class="badge badge-approved">Active</span>`;
        const recovery = token.autonomous_recovery ? 'Autonomous' : 'Manual';
        const action = revoked
            ? '-'
            : `<button class="btn btn-sm btn-danger" onclick="revokeBootstrapToken('${escapeHTML(token.id)}')">Revoke</button>`;
        return `
            <tr>
                <td><code>${escapeHTML(String(token.id || '').substring(0, 8))}...</code></td>
                <td>${escapeHTML(token.role)}</td>
                <td><code>${escapeHTML(token.owner_id || '-')}</code></td>
                <td>${escapeHTML(String(token.usages_count || 0))} / ${escapeHTML(String(token.max_usages || 0))}</td>
                <td>${escapeHTML(expiresAt)}</td>
                <td>${recovery}</td>
                <td>${status}</td>
                <td>${action}</td>
            </tr>
        `;
    }).join('');
}

window.revokeBootstrapToken = function(id) {
    if (confirm('Revoke this bootstrap token? It will no longer be usable to enroll or re-enroll any node.')) {
        actionRequest(`api/admin/bootstrap-tokens/${id}`, 'DELETE').catch(() => {});
    }
};

window.generateBootstrapToken = async function() {
    const role = document.getElementById('token-role').value;
    const owner_id = document.getElementById('token-owner').value.trim();
    const max_usages = parseInt(document.getElementById('token-usages').value, 10);
    const ttl_hours = parseInt(document.getElementById('token-ttl').value, 10) || 24;
    const description = document.getElementById('token-desc').value;
    const autonomous_recovery = document.getElementById('token-recovery').checked;

    const payload = {
        role,
        max_usages,
        ttl_hours,
        description
    };
    // Omitted entirely so the server falls back to the authenticated session.
    if (owner_id) {
        payload.owner_id = owner_id;
    }
    if (autonomous_recovery) {
        payload.autonomous_recovery = true;
    }

    try {
        const res = await actionRequest('api/user/bootstrap-tokens', 'POST', payload);
        if (res && res.token) {
            showGeneratedToken(res);
            document.getElementById('form-generate-token').reset();
            loadData();
        }
    } catch (err) {
        // actionRequest already alerts on failure
    }
};

function showGeneratedToken(res) {
    const panel = document.getElementById('token-result');
    const input = document.getElementById('token-result-value');
    input.value = res.token;
    document.getElementById('token-result-owner').textContent = res.owner_id || 'none';
    document.getElementById('token-result-cmd').textContent =
        'agentmesh-node join --bootstrap-token ' + res.token + ' <control-plane-url>';
    panel.hidden = false;
    input.focus();
    input.select();
}

window.copyGeneratedToken = async function() {
    const input = document.getElementById('token-result-value');
    const btn = document.getElementById('token-copy-btn');
    input.select();
    try {
        // Only available on secure origins; execCommand covers plain-HTTP deployments.
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(input.value);
        } else if (!document.execCommand('copy')) {
            throw new Error('copy command rejected');
        }
        btn.textContent = 'Copied';
    } catch (err) {
        btn.textContent = 'Press Ctrl+C';
    }
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
};

window.savePolicy = async function() {
    const yamlContent = document.getElementById('policy-yaml').value;

    let policy;
    try {
        policy = parsePolicyDocument(yamlContent);
    } catch (err) {
        setPolicyError(err.message);
        showToast('Policy is not valid YAML. Fix the reported error first.', 'error');
        return;
    }

    try {
        // The policy API speaks protojson; YAML is only the editing surface, so the
        // document goes over the wire in the shape the API documents.
        const response = await fetch('api/policies', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(policy)
        });
        if (response.ok) {
            policyBaseline = yamlContent;
            updatePolicyDirtyIndicator();
            showToast('Mesh policy updated and applied.', 'success');
            loadData();
        } else {
            const text = await response.text();
            showToast('Failed to save policy: ' + text.trim(), 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    }
};

// Throws with js-yaml's line and column detail so the editor can show it verbatim.
function parsePolicyDocument(text) {
    if (text.trim() === '') {
        return {};
    }
    const parsed = jsyaml.load(text);
    if (parsed === null || parsed === undefined) {
        return {};
    }
    if (typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('The policy must be a mapping of fields, not a list or a single value.');
    }
    return parsed;
}

function setPolicyError(message) {
    const box = document.getElementById('policy-error');
    const editor = document.getElementById('policy-yaml');
    const save = document.getElementById('policy-save');
    if (!box || !editor) return;

    box.textContent = message || '';
    box.hidden = !message;
    editor.classList.toggle('is-invalid', Boolean(message));
    editor.setAttribute('aria-invalid', message ? 'true' : 'false');
    if (save) {
        save.disabled = Boolean(message);
    }
}

function validatePolicyEditor() {
    const editor = document.getElementById('policy-yaml');
    if (!editor) return;
    try {
        parsePolicyDocument(editor.value);
        setPolicyError('');
    } catch (err) {
        setPolicyError(err.message);
    }
    updatePolicyDirtyIndicator();
}

function updatePolicyDirtyIndicator() {
    const indicator = document.getElementById('policy-dirty');
    if (indicator) {
        indicator.hidden = !policyIsDirty();
    }
}

// YAML forbids tabs for indentation, so Tab has to insert spaces or the document
// becomes unparseable the moment someone reaches for it.
function handlePolicyEditorKeydown(e) {
    if (e.key !== 'Tab' || e.ctrlKey || e.altKey || e.metaKey) {
        return;
    }
    e.preventDefault();
    const editor = e.currentTarget;
    const start = editor.selectionStart;
    editor.value = editor.value.slice(0, start) + '  ' + editor.value.slice(editor.selectionEnd);
    editor.selectionStart = editor.selectionEnd = start + 2;
    validatePolicyEditor();
}

function escapeHTML(str) {
    if (!str) return '-';
    return String(str).replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}

function formatDuration(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    }
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
        return `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const rest = minutes % 60;
    return rest === 0 ? `${hours}h` : `${hours}h ${rest}m`;
}
