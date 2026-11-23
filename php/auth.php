<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Authentication helpers: hashing, encryption, CAPTCHA, lockout,
| IP blocking and one-time passwords.
|--------------------------------------------------------------------------
*/

/* ---------- Hashing (YOUR CALL - explain in Design Decisions) ---------- */
function hash_secret(string $plain): string
{
    // Argon2id resists GPUs because it needs a lot of memory; bcrypt is the fallback.
    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash($plain, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 1,
        ]);
    }
    return password_hash($plain, PASSWORD_BCRYPT, ['cost' => 12]);
}

function normalize_answer(string $answer): string
{
    return mb_strtolower(trim($answer));
}

/* ---------- Encryption at rest, AES-256 (protection 13) ---------- */
function encryption_key(): string
{
    return hash('sha256', APP_KEY, true); // 32 bytes = 256 bits
}

function encrypt_field(string $plain): array
{
    $iv = random_bytes(16);
    $cipher = openssl_encrypt($plain, 'aes-256-cbc', encryption_key(), OPENSSL_RAW_DATA, $iv);

    if ($cipher === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return [base64_encode($cipher), base64_encode($iv)];
}

function decrypt_field(string $cipherB64, string $ivB64): ?string
{
    $plain = openssl_decrypt(
        (string)base64_decode($cipherB64, true),
        'aes-256-cbc',
        encryption_key(),
        OPENSSL_RAW_DATA,
        (string)base64_decode($ivB64, true)
    );
    return $plain === false ? null : $plain;
}

/* ---------- CAPTCHA: verified on the SERVER ---------- */
function captcha_verify(): bool
{
    $token = $_POST['g-recaptcha-response'] ?? '';

    if (!is_string($token) || $token === '' || !defined('RECAPTCHA_SECRET_KEY') || RECAPTCHA_SECRET_KEY === '') {
        return false; // no token = refuse (deleting the widget must not help)
    }

    $body = http_build_query([
        'secret'   => RECAPTCHA_SECRET_KEY,
        'response' => $token,
        'remoteip' => client_ip(),
    ]);
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $response = false;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $body,
            'timeout' => 10,
        ]]);
        $response = @file_get_contents($url, false, $ctx);
    }

    if ($response === false) {
        return false;
    }
    $result = json_decode($response, true);
    return is_array($result) && !empty($result['success']);
}

/*
| YOUR CALL (section 7): a failed CAPTCHA is logged (CAPTCHA_FAILED) but does
| NOT count as a failed log-in. Otherwise a bot could lock out real users
| without ever knowing a password.
*/
function captcha_fail(string $typed = ''): void
{
    log_event('CAPTCHA_FAILED', 'CAPTCHA check failed on ' . basename($_SERVER['PHP_SELF'] ?? ''), null, $typed);
}

/* ---------- Honeypot (protection 8) ---------- */
function honeypot_triggered(): bool
{
    return isset($_POST['website']) && $_POST['website'] !== '';
}

/* ---------- IP blocking (protection 5) ---------- */
function ip_block_remaining(string $ip): int
{
    global $pdo;

    $stmt = $pdo->prepare('SELECT blocked_until FROM ip_blocks WHERE ip_address = ? LIMIT 1');
    $stmt->execute([$ip]);
    $until = $stmt->fetchColumn();

    return $until ? max(0, strtotime((string)$until) - time()) : 0;
}

/* Failed log-ins from this IP, across ANY usernames, in the last 10 minutes. */
function ip_recent_failures(string $ip): int
{
    global $pdo;

    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM activity_logs
         WHERE event_type = 'LOGIN_FAILED' AND ip_address = ?
           AND created_at >= DATE_SUB(NOW(), INTERVAL " . (int)IP_BLOCK_WINDOW_MINUTES . " MINUTE)"
    );
    $stmt->execute([$ip]);
    return (int)$stmt->fetchColumn();
}

/* Blocks the IP when it passes the IP block threshold. Returns true if blocked. */
function ip_check_and_block(string $ip, ?string $typed = null, ?int $userId = null): bool
{
    global $pdo;

    if (ip_block_remaining($ip) > 0) {
        return true;
    }
    if (ip_recent_failures($ip) < IP_BLOCK_THRESHOLD) {
        return false;
    }

    $until = date('Y-m-d H:i:s', time() + IP_BLOCK_DURATION_MINUTES * 60);
    $stmt = $pdo->prepare(
        'INSERT INTO ip_blocks (ip_address, blocked_until, reason)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE blocked_until = VALUES(blocked_until), reason = VALUES(reason)'
    );
    $stmt->execute([$ip, $until, 'Too many failed log-ins']);
    log_event('IP_BLOCKED', 'IP passed the threshold of ' . IP_BLOCK_THRESHOLD . ' failures.', $userId, $typed);

    return true;
}

/* ---------- Progressive lockout (server side, keyed by typed username) ---------- */
/*
| The counter is keyed by the username AS TYPED, in its own table, so an
| unknown username behaves exactly like a real one (no enumeration, S9).
*/
function throttle_key(string $username): string
{
    return mb_strtolower(substr(trim($username), 0, 100));
}

function throttle_state(string $username): array
{
    global $pdo;

    $stmt = $pdo->prepare('SELECT failures, locked_until FROM login_throttle WHERE username_key = ? LIMIT 1');
    $stmt->execute([throttle_key($username)]);
    $row = $stmt->fetch();

    if (!$row) {
        return ['failures' => 0, 'remaining' => 0];
    }
    $remaining = $row['locked_until'] ? max(0, strtotime((string)$row['locked_until']) - time()) : 0;

    return ['failures' => (int)$row['failures'], 'remaining' => $remaining];
}

function throttle_reset(string $username): void
{
    global $pdo;
    $stmt = $pdo->prepare('DELETE FROM login_throttle WHERE username_key = ?');
    $stmt->execute([throttle_key($username)]);
}

/*
| Records one failure. Locks at 3, 6, 9 (and every 3rd after) failures.
| Returns ['failures' => n, 'tier' => 0-3, 'locked_for' => seconds].
*/
function throttle_add_failure(string $username): array
{
    global $pdo;

    $key = throttle_key($username);
    $pdo->prepare(
        'INSERT INTO login_throttle (username_key, failures) VALUES (?, 1)
         ON DUPLICATE KEY UPDATE failures = failures + 1'
    )->execute([$key]);

    $stmt = $pdo->prepare('SELECT failures FROM login_throttle WHERE username_key = ?');
    $stmt->execute([$key]);
    $failures = (int)$stmt->fetchColumn();

    $tier = 0;
    $lockFor = 0;
    if ($failures % 3 === 0) {
        $tier = min(3, intdiv($failures, 3));
        $lockFor = [1 => LOCKOUT_TIER_1, 2 => LOCKOUT_TIER_2, 3 => LOCKOUT_TIER_3][$tier];
        // The lock itself is started by throttle_apply_lock(), AFTER the slow work
        // (the alert email) is done, so the countdown shown starts at the exact seconds.
    }

    return ['failures' => $failures, 'tier' => $tier, 'locked_for' => $lockFor];
}

/* Starts the lockout clock now: locked_until = now + $seconds. */
function throttle_apply_lock(string $username, int $seconds): void
{
    global $pdo;
    $pdo->prepare('UPDATE login_throttle SET locked_until = ? WHERE username_key = ?')
        ->execute([date('Y-m-d H:i:s', time() + $seconds), throttle_key($username)]);
}

/*
| One place that handles EVERY failed attempt (log-in and forgot-password
| answer): log it, count it, lock, alert the real owner once per tier, and
| check the IP threshold. $user is the account row or null if it does not exist.
| Returns the lockout seconds to show (0 if none).
*/
function handle_failed_attempt(string $typed, ?array $user, string $reason): int
{
    $userId = $user ? (int)$user['id'] : null;

    log_event('LOGIN_FAILED', $reason, $userId, $typed);

    $result = throttle_add_failure($typed);

    if ($result['tier'] > 0) {
        log_event('LOCKOUT_TIER_' . $result['tier'], 'Failures: ' . $result['failures'], $userId, $typed);

        // Alert once per tier (3, 6, 9 failures), only for a real account.
        if ($user && in_array($result['failures'], [3, 6, 9], true)) {
            if (send_lockout_alert_email($user, $result['failures'])) {
                log_event('ALERT_EMAIL_SENT', 'Lockout tier ' . $result['tier'] . ' alert.', $userId, $typed);
            }
        }
    }

    ip_check_and_block(client_ip(), $typed, $userId);

    // Start the clock last: sending the email can take several seconds, and the
    // person must see (and be locked for) exactly the tier's seconds.
    if ($result['locked_for'] > 0) {
        throttle_apply_lock($typed, $result['locked_for']);
    }

    return $result['locked_for'];
}

/* ---------- One-time passwords (section 6) ---------- */
function otp_hash(string $otp): string
{
    // Keyed hash: a stolen database alone cannot be brute-forced offline.
    return hash_hmac('sha256', $otp, APP_KEY);
}

function otp_purpose_label(string $purpose): string
{
    return [
        'register' => 'Verify your account',
        'login'    => 'Your log-in code',
        'reset'    => 'Password reset code',
    ][$purpose] ?? 'Verification code';
}

/* How many seconds until the user may press "Resend", and how many resends are left. */
function otp_resend_state(int $userId, string $purpose): array
{
    global $pdo;

    $stmt = $pdo->prepare(
        'SELECT UNIX_TIMESTAMP(MAX(created_at)) AS last_sent, COUNT(*) AS total
         FROM otp_codes
         WHERE user_id = ? AND purpose = ?
           AND created_at >= DATE_SUB(NOW(), INTERVAL ' . (int)OTP_RESEND_WINDOW_MINUTES . ' MINUTE)'
    );
    $stmt->execute([$userId, $purpose]);
    $row = $stmt->fetch();

    $total = (int)($row['total'] ?? 0);
    $last = (int)($row['last_sent'] ?? 0);

    return [
        'cooldown'  => $last ? max(0, OTP_RESEND_COOLDOWN - (time() - $last)) : 0,
        'remaining' => max(0, (OTP_MAX_RESENDS + 1) - $total), // first send + 3 resends
    ];
}

/* Creates a new OTP (cancelling the old one) and emails it. Returns an error string or null. */
function otp_issue(array $user, string $purpose): ?string
{
    global $pdo;

    $userId = (int)$user['id'];
    $state = otp_resend_state($userId, $purpose);

    if ($state['cooldown'] > 0) {
        return 'Please wait ' . $state['cooldown'] . ' seconds before requesting a new code.';
    }
    if ($state['remaining'] <= 0) {
        return 'Too many codes requested. Please try again in a few minutes.';
    }

    // Single use: a new OTP cancels the previous one.
    $pdo->prepare('UPDATE otp_codes SET used_at = NOW() WHERE user_id = ? AND purpose = ? AND used_at IS NULL')
        ->execute([$userId, $purpose]);

    $otp = sprintf('%06d', random_int(0, 999999)); // random_int, never rand()
    $expires = date('Y-m-d H:i:s', time() + OTP_EXPIRY_MINUTES * 60);

    $pdo->prepare(
        'INSERT INTO otp_codes (user_id, otp_hash, purpose, expires_at, created_at)
         VALUES (?, ?, ?, ?, NOW())'
    )->execute([$userId, otp_hash($otp), $purpose, $expires]);
    $otpId = (int)$pdo->lastInsertId();

    if (!send_otp_email((string)$user['email'], $otp, $purpose, $expires)) {
        $pdo->prepare('UPDATE otp_codes SET used_at = NOW() WHERE id = ?')->execute([$otpId]);
        log_event('OTP_FAILED', 'OTP email could not be sent (' . $purpose . ').', $userId, (string)$user['username']);
        return 'We could not send the code. Please try again later.';
    }

    log_event('OTP_SENT', 'OTP emailed (' . $purpose . ').', $userId, (string)$user['username']);
    return null;
}

/*
| Checks a code. Returns one of: ok, invalid, expired, locked, none.
| Three wrong tries cancel the OTP, so even the right code fails afterwards.
*/
function otp_verify(array $user, string $purpose, string $code): string
{
    global $pdo;

    $userId = (int)$user['id'];
    $typed = (string)$user['username'];

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'SELECT id, otp_hash, expires_at, attempts FROM otp_codes
             WHERE user_id = ? AND purpose = ? AND used_at IS NULL
             ORDER BY id DESC LIMIT 1 FOR UPDATE'
        );
        $stmt->execute([$userId, $purpose]);
        $row = $stmt->fetch();

        if (!$row) {
            $pdo->commit();
            log_event('OTP_FAILED', 'No active OTP (' . $purpose . ').', $userId, $typed);
            return 'none';
        }

        $cancel = $pdo->prepare('UPDATE otp_codes SET used_at = NOW() WHERE id = ?');

        if (strtotime((string)$row['expires_at']) <= time()) {
            $cancel->execute([$row['id']]);
            $pdo->commit();
            log_event('OTP_FAILED', 'Expired OTP (' . $purpose . ').', $userId, $typed);
            return 'expired';
        }

        if (!hash_equals((string)$row['otp_hash'], otp_hash($code))) {
            $attempts = (int)$row['attempts'] + 1;
            $pdo->prepare('UPDATE otp_codes SET attempts = ? WHERE id = ?')->execute([$attempts, $row['id']]);

            $status = 'invalid';
            if ($attempts >= OTP_MAX_ATTEMPTS) {
                $cancel->execute([$row['id']]);
                $status = 'locked';
            }
            $pdo->commit();
            log_event('OTP_FAILED', 'Wrong OTP (' . $purpose . '), attempt ' . $attempts . '.', $userId, $typed);
            return $status;
        }

        $cancel->execute([$row['id']]); // used up
        $pdo->commit();
        return 'ok';
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

/* ---------- OTP step state kept on the server ---------- */
function otp_flow_start(array $user, string $purpose): void
{
    // No session user exists yet: only this "pending" record.
    $_SESSION['otp_flow'] = [
        'user_id'  => (int)$user['id'],
        'purpose'  => $purpose,
        'started'  => time(),
    ];
}

function otp_flow_get(): ?array
{
    $flow = $_SESSION['otp_flow'] ?? null;

    if (!is_array($flow) || (time() - (int)$flow['started']) > 900) {
        unset($_SESSION['otp_flow']);
        return null;
    }
    return $flow;
}

function find_user_by_id(int $id): ?array
{
    global $pdo;
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function find_user_by_username(string $username): ?array
{
    global $pdo;
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    return $row ?: null;
}

/*
| The three questions shown on Forgot Password.
| A real user sees the questions they picked at registration. For a username that does
| not exist we show three questions picked from the username itself, so the same name
| always gets the same list and nobody can tell the two cases apart (no enumeration).
*/
function forgot_question_codes(string $username, ?array $user): array
{
    global $pdo;

    if ($user !== null) {
        $stmt = $pdo->prepare('SELECT question_code FROM security_answers WHERE user_id = ? ORDER BY id');
        $stmt->execute([$user['id']]);
        $codes = $stmt->fetchAll(PDO::FETCH_COLUMN);
        if (count($codes) === REQUIRED_QUESTIONS) {
            return array_map('strval', $codes);
        }
    }

    $all = array_keys(QUESTION_BANK);
    $start = hexdec(substr(hash('sha256', strtolower($username)), 0, 6)) % count($all);
    $step = [1, 3, 5][hexdec(substr(hash('sha256', strtolower($username)), 6, 2)) % 3];   // 1, 3, 5 are coprime with 8
    $codes = [];
    for ($i = 0; $i < REQUIRED_QUESTIONS; $i++) {
        $codes[] = $all[($start + $i * $step) % count($all)];
    }
    return $codes;
}

function mask_email(string $email): string
{
    [$name, $domain] = array_pad(explode('@', $email, 2), 2, '');
    return mb_substr($name, 0, 1) . str_repeat('*', max(2, mb_strlen($name) - 1)) . '@' . $domain;
}
