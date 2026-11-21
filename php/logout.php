<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

$wasLoggedIn = !empty($_SESSION['user_id']);

if ($wasLoggedIn) {
    log_event('LOGOUT', 'User logged out.', (int)$_SESSION['user_id']);
}

// Log-out destroys the session completely.
destroy_session();

redirect(isset($_GET['timeout']) ? 'login?timeout=1' : 'index');
