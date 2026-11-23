<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

if (!empty($_SESSION['user_id'])) {
    redirect('dashboard');
}

const GENERIC_LOGIN_ERROR = 'Invalid username or password.';

$username = '';
$error = '';
$lockSeconds = 0;        // account lockout countdown
$ipLockSeconds = 0;      // IP block countdown
$showForgot = false;

/*
| Show the waiting time even on a plain page load or refresh, not only after a POST.
| The IP block is known from the IP alone. The account lock is looked up for the
| username that was last typed in this browser session.
*/
$ip = client_ip();
$ipLockSeconds = ip_block_remaining($ip);
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && !empty($_SESSION['login_username'])) {
    $lockSeconds = throttle_state((string)$_SESSION['login_username'])['remaining'];
    if ($lockSeconds > 0) {
        $username = (string)$_SESSION['login_username'];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $_SESSION['login_username'] = substr($username, 0, 100);

    $ipLockSeconds = ip_block_remaining($ip);
    $state = throttle_state($username);

    if ($ipLockSeconds > 0) {
        $error = 'Too many failed attempts from your network. Please wait.';
    } elseif ($state['remaining'] > 0) {
        // The lockout lives in the database: reloading or clearing cookies cannot skip it.
        $lockSeconds = $state['remaining'];
        $error = 'Too many failed attempts. Please wait for the countdown to finish.';
    } elseif (!captcha_verify()) {
        captcha_fail($username);
        $error = 'Please complete the CAPTCHA and try again.';
    } else {
        $user = null;
        $passwordOk = false;
        $formatOk = ($username !== '' && $password !== ''
            && validate_username($username) === null
            && strlen($password) <= MAX_PASSWORD_LENGTH);

        if ($formatOk) {
            $user = find_user_by_username($username);
        }

        // Always run a hash check so a missing user takes about as long as a real one.
        $hashToCheck = $user ? (string)$user['password_hash'] : hash_secret('dummy-password-for-timing');
        $passwordOk = $formatOk && password_verify($password, $hashToCheck) && $user !== null;

        if (!$passwordOk) {
            $lockSeconds = handle_failed_attempt($username, $user, 'Wrong username or password.');
            $error = GENERIC_LOGIN_ERROR;
            if (ip_block_remaining($ip) > 0) {
                $ipLockSeconds = ip_block_remaining($ip);
            }
        } elseif (empty($user['email_verified_at'])) {
            // Correct password but the account was never verified: resend the verification code.
            $err = otp_issue($user, 'register');
            otp_flow_start($user, 'register');
            if ($err !== null) {
                flash_set('error', $err);
            }
            redirect('verify_otp');
        } elseif ($user['role'] === 'student' && $user['student_status'] !== ENROLLED_STATUS) {
            log_event('LOGIN_BLOCKED_STATUS', 'Student is not currently enrolled.', (int)$user['id'], $username);
            $error = 'Your account is not currently enrolled. Please contact the library.';
        } else {
            // Password correct: send the log-in OTP. NO session exists yet.
            $err = otp_issue($user, 'login');
            otp_flow_start($user, 'login');
            if ($err !== null) {
                flash_set('error', $err);
            }
            redirect('verify_otp');
        }
    }

    // Same rule for real and unknown usernames, so nothing is revealed.
    $showForgot = throttle_state($username)['failures'] >= FORGOT_PASSWORD_AFTER;
    if ($lockSeconds === 0) {
        $lockSeconds = throttle_state($username)['remaining'];
    }
}

$locked = ($lockSeconds > 0 || $ipLockSeconds > 0);
$countdown = max($lockSeconds, $ipLockSeconds);

page_start('Log-in', ['login.js'], true);
?>
<section class="card form-card narrow">
    <h1>Log-in</h1>

    <?php if (isset($_GET['timeout'])): ?>
        <div class="notice notice-info">You were logged out because of inactivity. Please log in again.</div>
    <?php endif; ?>
    <?php if (isset($_GET['changed'])): ?>
        <div class="notice notice-success">Successfully Change Password</div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="notice notice-error" role="alert"><?= e($error) ?></div>
    <?php endif; ?>

    <?php if ($ipLockSeconds > 0 && $ipLockSeconds >= $lockSeconds): ?>
        <div class="notice notice-warning" role="status">
            This network is blocked for 10 minutes because of too many failed log-ins.
            Try again in <strong id="lock-count" data-seconds="<?= (int)$ipLockSeconds ?>" data-format="clock"><?= e(gmdate('i:s', $ipLockSeconds)) ?></strong>.
        </div>
    <?php elseif ($locked): ?>
        <div class="notice notice-warning" role="status">
            Account temporarily locked. Try again in <strong id="lock-count" data-seconds="<?= (int)$lockSeconds ?>"><?= (int)$lockSeconds ?></strong> seconds.
        </div>
    <?php endif; ?>

    <form method="post" id="login-form" novalidate>
        <?= csrf_field() ?>
        <div class="form-group">
            <?= field_label('username', 'Username', true) ?>
            <input type="text" id="username" name="username" value="<?= e($username) ?>" maxlength="100" autocomplete="username">
        </div>
        <div class="form-group">
            <?= field_label('password', 'Password', true) ?>
            <input type="password" id="password" name="password" maxlength="<?= MAX_PASSWORD_LENGTH ?>" autocomplete="current-password">
            <label class="inline-check"><input type="checkbox" id="show-password"> Show Password</label>
        </div>

        <div class="form-group"><?= captcha_widget() ?></div>

        <button type="submit" id="login-btn" class="btn" <?= $locked ? 'disabled' : '' ?>>Log-in</button>
    </form>

    <?php if ($showForgot): ?>
        <p class="forgot-link"><a href="forgot_password">Forgot Password? Reset Here</a></p>
    <?php endif; ?>

    <p class="muted">No account yet?
        <a id="register-link" data-href="register"
           <?php if ($locked): ?>class="link-disabled" aria-disabled="true" tabindex="-1"<?php else: ?>href="register"<?php endif; ?>>Please register here</a>
    </p>
</section>
<?php page_end();