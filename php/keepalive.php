<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

/* Called by js/idle.js when the user is active or clicks "Stay logged in". */
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !verify_csrf()) {
    json_response(['ok' => false], 403);
}
if (empty($_SESSION['user_id']) || idle_seconds_left() <= 0) {
    json_response(['ok' => false, 'expired' => true], 401);
}

$_SESSION['last_activity'] = time();
json_response(['ok' => true, 'left' => idle_seconds_left()]);
