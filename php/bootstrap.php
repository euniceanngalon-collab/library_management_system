<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Shared bootstrap - every page and script loads this first.
|--------------------------------------------------------------------------
| 1. Loads the seed and the PRIVATE config (outside the web root).
| 2. Hides PHP errors from visitors and writes them to a log file.
| 3. Sends security headers and starts a hardened session.
| 4. Connects to MySQL (PDO, real prepared statements).
| 5. Provides CSRF, logging, login and role helpers.
*/

require_once __DIR__ . '/seed.php';

/* ---------- 1. Private config (protection 11) ---------- */
/*
| The real config.php (passwords, keys) lives OUTSIDE the web root and is never committed.
| Looked for, in this order:
|   1. the LIBRARY_CONFIG environment variable (full path to the file)
|   2. C:\xampp\library_private\config.php   (two levels above htdocs)
|   3. one level higher than that
| The paths that were tried are written to the PHP/Apache error log if nothing is found.
*/
function private_config_candidates(): array
{
    $candidates = [];

    $fromEnv = getenv('LIBRARY_CONFIG');
    if (is_string($fromEnv) && $fromEnv !== '') {
        $candidates[] = $fromEnv;
    }

    // XAMPP: C:\xampp\htdocs\library_management\php  ->  C:\xampp\library_private\config.php
    $candidates[] = dirname(__DIR__, 3) . DIRECTORY_SEPARATOR . 'library_private' . DIRECTORY_SEPARATOR . 'config.php';
    $candidates[] = dirname(__DIR__, 4) . DIRECTORY_SEPARATOR . 'library_private' . DIRECTORY_SEPARATOR . 'config.php';

    return array_values(array_unique($candidates));
}

function locate_private_config(): ?string
{
    foreach (private_config_candidates() as $path) {
        if (is_file($path)) {
            return $path;
        }
    }

    return null;
}

$privateConfig = locate_private_config();

if ($privateConfig === null) {
    // Visitors see a plain message; the real reason goes to the server error log only.
    error_log('LIBRARY CONFIG NOT FOUND. config.php must be named exactly "config.php" (not error.log) '
        . 'and be in one of: ' . implode(' | ', private_config_candidates()));
    http_response_code(500);
    exit('The system is not configured yet. Please contact the administrator.');
}

require_once $privateConfig;

/* ---------- 2. Error handling (protection 10) ---------- */
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

if (defined('ERROR_LOG_FILE')) {
    ini_set('error_log', ERROR_LOG_FILE);
}

set_exception_handler(static function (Throwable $e): void {
    error_log('Uncaught: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());

    if (PHP_SAPI !== 'cli') {
        if (!headers_sent()) {
            http_response_code(500);
        }
        echo 'Something went wrong. Please try again later.';
    } else {
        fwrite(STDERR, "An error occurred. Check the error log.\n");
    }

    exit(1);
});

date_default_timezone_set('Asia/Manila');

/* ---------- 3. Security headers and session (protections 6, 12) ---------- */
if (PHP_SAPI !== 'cli') {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    // no-store also stops the browser back button from showing protected pages.
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');

    if (session_status() !== PHP_SESSION_ACTIVE) {
        $isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

        session_name('LIBSESSID');
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isHttps,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }
}

/* ---------- 4. Database ---------- */
try {
    $pdo = new PDO(
        'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
    // MySQL NOW() must agree with PHP time (Philippine time).
    $pdo->exec("SET time_zone = '+08:00'");
} catch (Throwable $e) {
    error_log('Database connection error: ' . $e->getMessage());
    http_response_code(500);
    exit('Service temporarily unavailable.');
}

require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/layout.php';
require_once __DIR__ . '/mailer.php';

/* ---------- Output escaping (protection 2) ---------- */
function e(mixed $value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* ---------- Client information ---------- */
function client_ip(): string
{
    // Forwarded headers can be faked by the visitor, so they are not trusted.
    return substr($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN', 0, 45);
}

function client_user_agent(): string
{
    return substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);
}

function redirect(string $to): never
{
    header('Location: ' . $to);
    exit;
}

function json_response(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/* ---------- CSRF (protection 3) ---------- */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function verify_csrf(): bool
{
    $submitted = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    $stored = $_SESSION['csrf_token'] ?? '';

    return is_string($submitted) && is_string($stored)
        && $stored !== '' && hash_equals($stored, $submitted);
}

/* Call at the top of every page that accepts a POST. */
function require_csrf(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return;
    }

    if (!verify_csrf()) {
        log_event('CSRF_REJECTED', 'Missing or invalid CSRF token on ' . basename($_SERVER['PHP_SELF'] ?? ''));
        http_response_code(403);
        exit('Request rejected. Please go back, refresh the page and try again.');
    }
}

/* ---------- Activity log (protection 9) - append only, INSERT only ---------- */
function log_event(
    string $eventType,
    string $details = '',
    ?int $userId = null,
    ?string $usernameTyped = null
): bool {
    global $pdo;

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO activity_logs
             (user_id, event_type, details, ip_address, user_agent, username_typed, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())'
        );

        return $stmt->execute([
            $userId,
            substr($eventType, 0, 60),
            substr($details, 0, 1000),
            PHP_SAPI === 'cli' ? 'CLI' : client_ip(),
            PHP_SAPI === 'cli' ? 'CLI' : client_user_agent(),
            $usernameTyped !== null ? substr($usernameTyped, 0, 100) : null,
        ]);
    } catch (Throwable $e) {
        error_log('Activity logging failed: ' . $e->getMessage());
        return false;
    }
}

/* ---------- Sessions ---------- */
function destroy_session(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => 'Strict',
        ]);
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

/* Seconds left before the idle timeout fires. */
function idle_seconds_left(): int
{
    $last = (int)($_SESSION['last_activity'] ?? time());
    return max(0, (IDLE_TIMEOUT_MINUTES * 60) - (time() - $last));
}

/*
| Every protected page calls this BEFORE it shows anything.
| $touch = false is used by background polling so it cannot keep an idle
| session alive forever.
*/
function require_login(bool $touch = true): void
{
    if (empty($_SESSION['user_id'])) {
        redirect('login');
    }

    if (idle_seconds_left() <= 0) {
        log_event('SESSION_TIMEOUT', 'Logged out after the idle timeout.', (int)$_SESSION['user_id']);
        destroy_session();
        redirect('login?timeout=1');
    }

    if ($touch) {
        $_SESSION['last_activity'] = time();
    }
}

function current_user_role(): ?string
{
    global $pdo;

    if (empty($_SESSION['user_id'])) {
        return null;
    }

    $stmt = $pdo->prepare('SELECT role FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([(int)$_SESSION['user_id']]);
    $role = $stmt->fetchColumn();

    return $role === false ? null : (string)$role;
}

function require_role(string $requiredRole): void
{
    require_login();

    if (current_user_role() !== $requiredRole) {
        log_event('ACCESS_DENIED', 'Required role: ' . $requiredRole, (int)$_SESSION['user_id']);
        http_response_code(403);
        exit('Access denied.');
    }
}

/* Flash messages survive exactly one redirect. */
function flash_set(string $type, string $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function flash_get(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return is_array($flash) ? $flash : null;
}
