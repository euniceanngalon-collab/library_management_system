<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

/* Live "is this username taken?" check for the Register page. */
header('Content-Type: application/json; charset=utf-8');

// Small per-session limit so this cannot be used to scan for usernames quickly.
$now = time();
$hits = array_filter($_SESSION['uname_hits'] ?? [], static fn($t) => $t > $now - 60);
if (count($hits) >= 30) {
    json_response(['available' => false, 'message' => 'Too many checks. Please wait a moment.'], 429);
}
$hits[] = $now;
$_SESSION['uname_hits'] = array_values($hits);

$name = trim((string)($_GET['u'] ?? ''));
$formatError = validate_username($name);

if ($formatError !== null) {
    json_response(['available' => false, 'message' => $formatError]);
}

$stmt = $pdo->prepare('SELECT 1 FROM users WHERE username = ? LIMIT 1');
$stmt->execute([$name]);
$taken = (bool)$stmt->fetchColumn();

json_response([
    'available' => !$taken,
    'message'   => $taken ? 'This username is already taken.' : 'Username is available.',
]);
