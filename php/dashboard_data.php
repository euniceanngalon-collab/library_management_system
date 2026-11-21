<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

/*
| JSON feed for the monitoring dashboard. READ-ONLY: this file only runs SELECT.
| Opened while logged out, or by a non-admin, it returns nothing (S5).
*/
if (empty($_SESSION['user_id']) || idle_seconds_left() <= 0 || current_user_role() !== 'admin') {
    json_response(['error' => 'forbidden'], 403);
}
// Polling must NOT extend the idle timer, so last_activity is not touched here.

$summary = [];
$counts = [
    'login_success' => "event_type = 'LOGIN_SUCCESS'",
    'login_failed'  => "event_type = 'LOGIN_FAILED'",
    'otp_sent'      => "event_type = 'OTP_SENT'",
    'otp_failed'    => "event_type = 'OTP_FAILED'",
    'alerts_sent'   => "event_type = 'ALERT_EMAIL_SENT'",
];
foreach ($counts as $key => $where) {
    $summary[$key] = (int)$pdo->query(
        "SELECT COUNT(*) FROM activity_logs WHERE $where AND DATE(created_at) = CURDATE()"
    )->fetchColumn();
}
$summary['accounts_locked'] = (int)$pdo->query(
    'SELECT COUNT(*) FROM login_throttle WHERE locked_until > NOW()'
)->fetchColumn();
$summary['ips_blocked'] = (int)$pdo->query(
    'SELECT COUNT(*) FROM ip_blocks WHERE blocked_until > NOW()'
)->fetchColumn();

/* Failed log-ins per hour, last 24 hours (index 0 = 23 hours ago, 23 = this hour). */
$hours = array_fill(0, 24, 0);
$labels = [];
$rows = $pdo->query(
    "SELECT TIMESTAMPDIFF(HOUR, DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00'),
                                DATE_FORMAT(NOW(), '%Y-%m-%d %H:00:00')) AS ago, COUNT(*) AS c
     FROM activity_logs
     WHERE event_type = 'LOGIN_FAILED' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY ago"
)->fetchAll();
foreach ($rows as $r) {
    $ago = (int)$r['ago'];
    if ($ago >= 0 && $ago < 24) {
        $hours[23 - $ago] = (int)$r['c'];
    }
}
for ($i = 23; $i >= 0; $i--) {
    $labels[] = date('gA', time() - $i * 3600);
}

/* Top 5 IPs by failures in 24 hours, and whether each is blocked now. */
$topIps = $pdo->query(
    "SELECT a.ip_address, COUNT(*) AS failures,
            (SELECT COUNT(*) FROM ip_blocks b WHERE b.ip_address = a.ip_address AND b.blocked_until > NOW()) AS blocked
     FROM activity_logs a
     WHERE a.event_type = 'LOGIN_FAILED' AND a.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY a.ip_address ORDER BY failures DESC LIMIT 5"
)->fetchAll();

$flags = $pdo->query(
    'SELECT severity, pattern, target, description, created_at
     FROM security_flags ORDER BY id DESC LIMIT 20'
)->fetchAll();

/* Recent events with filters. Every value is a bound parameter (protection 1). */
$where = [];
$params = [];

$from = (string)($_GET['from'] ?? '');
$to = (string)($_GET['to'] ?? '');
if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) {
    $where[] = 'created_at >= ?';
    $params[] = $from . ' 00:00:00';
}
if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) {
    $where[] = 'created_at <= ?';
    $params[] = $to . ' 23:59:59';
}
$type = (string)($_GET['type'] ?? '');
if ($type !== '' && preg_match('/^[A-Z_0-9]{1,60}$/', $type)) {
    $where[] = 'event_type = ?';
    $params[] = $type;
}
$uname = trim((string)($_GET['username'] ?? ''));
if ($uname !== '') {
    $where[] = 'username_typed LIKE ?';
    $params[] = '%' . addcslashes(substr($uname, 0, 100), '%_\\') . '%';
}
$ip = trim((string)($_GET['ip'] ?? ''));
if ($ip !== '') {
    $where[] = 'ip_address = ?';
    $params[] = substr($ip, 0, 45);
}

$sql = 'SELECT id, event_type, username_typed, user_id, ip_address, user_agent, details, created_at
        FROM activity_logs' . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
        . ' ORDER BY id DESC LIMIT 50';
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$events = $stmt->fetchAll();

$types = $pdo->query('SELECT DISTINCT event_type FROM activity_logs ORDER BY event_type')->fetchAll(PDO::FETCH_COLUMN);

// Values are sent as raw data; js/dashboard.js displays them with textContent (never innerHTML).
json_response([
    'summary' => $summary,
    'hours'   => ['labels' => $labels, 'values' => $hours],
    'top_ips' => $topIps,
    'flags'   => $flags,
    'events'  => $events,
    'types'   => $types,
    'updated' => date('g:i:s A') . ' PHT',
]);
