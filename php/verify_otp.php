<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

/*
| The OTP step cannot be skipped: without a pending flow in the SERVER
| session, this page sends the visitor back to the log-in page.
*/
$flow = otp_flow_get();
$user = $flow ? find_user_by_id((int)$flow['user_id']) : null;

if (!$flow || !$user || !in_array($flow['purpose'], ['register', 'login', 'reset'], true)) {
    unset($_SESSION['otp_flow']);
    redirect('login');
}

$purpose = $flow['purpose'];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    $action = (string)($_POST['action'] ?? 'verify');

    if ($action === 'cancel') {
        unset($_SESSION['otp_flow']);
        redirect('login');
    }

    if ($action === 'resend') {
        $err = otp_issue($user, $purpose);
        if ($err === null) {
            flash_set('success', 'A new code was sent. The previous code no longer works.');
        } else {
            flash_set('error', $err);
        }
        redirect('verify_otp');
    }

    $code = trim((string)($_POST['otp'] ?? ''));

    if (!preg_match('/^\d{6}$/', $code)) {
        $error = 'Please enter the 6-digit code.';
    } else {
        $result = otp_verify($user, $purpose, $code);

        if ($result === 'ok') {
            unset($_SESSION['otp_flow']);

            if ($purpose === 'register') {
                $pdo->prepare('UPDATE users SET email_verified_at = NOW() WHERE id = ?')->execute([$user['id']]);
                log_event('ACCOUNT_VERIFIED', 'Registration OTP accepted.', (int)$user['id'], (string)$user['username']);
                flash_set('success', 'Your account is verified. You can now log in.');
                redirect('login');
            }

            if ($purpose === 'login') {
                // Only now does a session exist: regenerate the ID first.
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int)$user['id'];
                $_SESSION['last_activity'] = time();
                throttle_reset((string)$user['username']);
                log_event('LOGIN_SUCCESS', 'Password and OTP correct.', (int)$user['id'], (string)$user['username']);
                redirect('dashboard');
            }

            // purpose === 'reset': allow the Change Password page, once.
            session_regenerate_id(true);
            $_SESSION['reset_auth'] = [
                'user_id' => (int)$user['id'],
                'expires' => time() + RESET_AUTH_SECONDS,
            ];
            redirect('reset_password');
        }

        $error = match ($result) {
            'expired' => 'This code has expired. Please request a new one.',
            'locked'  => 'Too many wrong codes. This code is cancelled - please request a new one.',
            'none'    => 'There is no active code. Please request a new one.',
            default   => 'Incorrect code. Please try again.',
        };
    }
}

$state = otp_resend_state((int)$user['id'], $purpose);
$title = otp_purpose_label($purpose);

page_start($title, ['otp.js']);
?>
<section class="card form-card narrow">
    <h1><?= e($title) ?></h1>
    <p class="muted">
        We sent a 6-digit code to <strong><?= e(mask_email((string)$user['email'])) ?></strong>.
        It expires in <?= OTP_EXPIRY_MINUTES ?> minutes.
    </p>

    <?php if ($error !== ''): ?>
        <div class="notice notice-error" role="alert"><?= e($error) ?></div>
    <?php endif; ?>

    <form method="post" novalidate autocomplete="off">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="verify">
        <div class="form-group">
            <?= field_label('otp', 'Verification Code', true) ?>
            <input type="text" id="otp" name="otp" class="otp-input" inputmode="numeric" maxlength="6" autocomplete="one-time-code" autofocus>
        </div>
        <button type="submit" class="btn">Verify</button>
    </form>

    <form method="post" class="inline-form">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="resend">
        <button type="submit" id="resend-btn" class="btn btn-secondary"
                data-cooldown="<?= (int)$state['cooldown'] ?>"
                <?= ($state['cooldown'] > 0 || $state['remaining'] <= 0) ? 'disabled' : '' ?>>
            Resend OTP<span id="resend-count"></span>
        </button>
        <small class="hint"><?= (int)max(0, $state['remaining'] - 0) ?> code(s) left in this 15-minute window.</small>
    </form>

    <form method="post" class="inline-form">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="cancel">
        <button type="submit" class="link-button">Cancel</button>
    </form>
</section>
<?php page_end();
