<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

require_login();

if (current_user_role() !== 'admin') {
    log_event('ADMIN_ACCESS_DENIED', 'Non-admin opened the monitoring dashboard.', (int)$_SESSION['user_id']);
    http_response_code(403);
    page_start('Access denied');
    echo '<section class="card"><h1>Access denied</h1><p>This page is for administrators only.</p></section>';
    page_end();
    exit;
}

// Watching the logs is itself logged (accountability).
log_event('ADMIN_VIEWED_DASHBOARD', 'Admin opened the monitoring dashboard.', (int)$_SESSION['user_id']);

page_start('Security Monitoring', ['barchart.js', 'dashboard.js']);
?>
<section class="dashboard-wrap" id="monitor" data-feed="php/dashboard_data">
    <h1>Security Monitoring Dashboard</h1>
    <p class="muted">Read-only. Refreshes every 60 seconds. Last update: <span id="updated">-</span></p>

    <div class="cards" id="summary-cards"></div>

    <div class="card">
        <h2>Failed log-ins per hour (last 24 hours)</h2>
        <canvas id="hour-chart" width="900" height="260" aria-label="Failed log-ins per hour"></canvas>
    </div>

    <div class="two-col">
        <div class="card">
            <h2>Top IP addresses (24 hours)</h2>
            <div class="table-scroll"><table id="top-ips"><thead><tr><th>IP address</th><th>Failures</th><th>Blocked now</th></tr></thead><tbody></tbody></table></div>
        </div>
        <div class="card">
            <h2>Flags from the monitoring script</h2>
            <div class="table-scroll"><table id="flags"><thead><tr><th>Severity</th><th>Pattern</th><th>Target</th><th>Details</th><th>When</th></tr></thead><tbody></tbody></table></div>
        </div>
    </div>

    <div class="card">
        <h2>Recent events (latest 50)</h2>
        <form id="filters" class="filter-row" novalidate>
            <div><label for="f-from">From</label><input type="date" id="f-from"></div>
            <div><label for="f-to">To</label><input type="date" id="f-to"></div>
            <div><label for="f-type">Event type</label><select id="f-type"><option value="">All</option></select></div>
            <div><label for="f-username">Username</label><input type="text" id="f-username" maxlength="100"></div>
            <div><label for="f-ip">IP address</label><input type="text" id="f-ip" maxlength="45"></div>
            <div><button type="submit" class="btn">Filter</button></div>
        </form>
        <div class="table-scroll"><table id="events"><thead><tr><th>Time</th><th>Event</th><th>Username typed</th><th>IP</th><th>Browser</th><th>Details</th></tr></thead><tbody></tbody></table></div>
    </div>
</section>
<?php page_end();
