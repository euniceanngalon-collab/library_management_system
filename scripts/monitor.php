<?php
declare(strict_types=1);

/*
| Monitoring script (handout section 14). Run:  php scripts/monitor.php
| Reads the last 24 hours of the activity log, looks for four attack patterns,
| writes flags to security_flags (no duplicate per pattern + target + day)
| and prints a report. It only SELECTs from activity_logs.
*/
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Page Not Found');
}

require_once __DIR__ . '/../php/bootstrap.php';

$findings = [];   // each: [severity, pattern, target, console text, description]

/* Pattern 1: one IP at or above the IP block threshold, across any usernames. */
$stmt = $pdo->prepare(
    "SELECT ip_address, COUNT(*) AS failures, COUNT(DISTINCT username_typed) AS names
     FROM activity_logs
     WHERE event_type = 'LOGIN_FAILED' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY ip_address HAVING COUNT(*) >= ?"
);
$stmt->execute([IP_BLOCK_THRESHOLD]);
foreach ($stmt->fetchAll() as $r) {
    $findings[] = ['HIGH', 'IP over threshold', $r['ip_address'],
        "{$r['failures']} failures, {$r['names']} usernames",
        "{$r['failures']} failed log-ins from one IP using {$r['names']} usernames."];
}

/* Pattern 2: one username with failures from 3 or more different IPs. */
$stmt = $pdo->query(
    "SELECT LOWER(username_typed) AS uname, COUNT(DISTINCT ip_address) AS ips
     FROM activity_logs
     WHERE event_type = 'LOGIN_FAILED' AND username_typed IS NOT NULL AND username_typed <> ''
       AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY LOWER(username_typed) HAVING COUNT(DISTINCT ip_address) >= 3"
);
foreach ($stmt->fetchAll() as $r) {
    $findings[] = ['MED', 'Account targeted', $r['uname'],
        "failures from {$r['ips']} IPs", "Failures against this username came from {$r['ips']} different IPs."];
}

/* Pattern 3: 5 or more OTP_FAILED for one account within 10 minutes (sliding window). */
$rows = $pdo->query(
    "SELECT user_id, username_typed, UNIX_TIMESTAMP(created_at) AS t
     FROM activity_logs
     WHERE event_type = 'OTP_FAILED' AND user_id IS NOT NULL
       AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     ORDER BY user_id, created_at"
)->fetchAll();
$byUser = [];
foreach ($rows as $r) {
    $byUser[$r['user_id']]['name'] = $r['username_typed'] ?: ('user #' . $r['user_id']);
    $byUser[$r['user_id']]['times'][] = (int)$r['t'];
}
foreach ($byUser as $info) {
    $times = $info['times'];
    for ($i = 0, $n = count($times); $i + 4 < $n; $i++) {
        if ($times[$i + 4] - $times[$i] <= 600) {
            $findings[] = ['MED', 'OTP guessing', $info['name'],
                '5 wrong OTPs in 10 min', '5 or more wrong OTP entries within 10 minutes.'];
            break;
        }
    }
}

/* Pattern 4: LOGIN_SUCCESS between 12:00 AM and 5:00 AM Philippine time. */
$stmt = $pdo->query(
    "SELECT COALESCE(username_typed, CONCAT('user #', user_id)) AS who, COUNT(*) AS c
     FROM activity_logs
     WHERE event_type = 'LOGIN_SUCCESS' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
       AND HOUR(created_at) < 5
     GROUP BY who"
);
foreach ($stmt->fetchAll() as $r) {
    $findings[] = ['LOW', 'Off-hours log-in', $r['who'],
        "{$r['c']} log-in(s) between 12-5 AM", 'Successful log-in during off-hours (12:00 AM - 5:00 AM PHT).'];
}

$scanned = (int)$pdo->query(
    "SELECT COUNT(*) FROM activity_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
)->fetchColumn();

/* INSERT IGNORE + UNIQUE(pattern, target, flag_date) = no duplicate on the same day. */
$insert = $pdo->prepare(
    'INSERT IGNORE INTO security_flags (severity, pattern, target, description, flag_date)
     VALUES (?, ?, ?, ?, CURDATE())'
);

$new = 0;
$already = 0;
$lines = [];
foreach ($findings as [$sev, $pattern, $target, $text, $desc]) {
    $insert->execute([$sev, $pattern, substr((string)$target, 0, 150), $desc]);
    if ($insert->rowCount() > 0) {
        $new++;
    } else {
        $already++;
    }
    $lines[] = sprintf('[%-4s] %-18s %-15s %s', $sev, $pattern, $target, $text);
}

echo 'IT 107 Monitoring Report  -  ' . date('Y-m-d H:i') . " PHT\n\n";
echo 'Scanned: ' . number_format($scanned) . " events (last 24 hours)\n\n";
echo $lines ? implode("\n", $lines) . "\n\n" : "No suspicious patterns found.\n\n";
echo "New flags written: {$new}      Already flagged today: {$already}\n";
