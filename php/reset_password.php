<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

/*
| Change Password can only be opened after the reset OTP was accepted.
| The server remembers that in $_SESSION['reset_auth'] (set in verify_otp.php),
| and this page USES IT UP when the password is changed.
*/
$auth = $_SESSION['reset_auth'] ?? null;

if (!is_array($auth) || (int)$auth['expires'] < time()) {
    unset($_SESSION['reset_auth']);
    redirect('login');
}

$user = find_user_by_id((int)$auth['user_id']);
if (!$user) {
    unset($_SESSION['reset_auth']);
    redirect('login');
}

$errors = [];
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    $new = (string)($_POST['password'] ?? '');
    $again = (string)($_POST['confirm_password'] ?? '');

    if ($new !== $again) {
        $errors['confirm_password'] = 'Mismatch Password';
    } elseif (($m = validate_password($new)) !== null) {
        $errors['password'] = $m;
    } else {
        // None of the last 3 passwords (and not the current one) may be reused.
        $stmt = $pdo->prepare('SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ' . (int)PASSWORD_HISTORY_LIMIT);
        $stmt->execute([$user['id']]);
        $old = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $old[] = (string)$user['password_hash'];

        $reused = false;
        foreach ($old as $hash) {
            if (password_verify($new, (string)$hash)) {
                $reused = true;
                break;
            }
        }

        if ($reused) {
            $errors['password'] = 'You cannot reuse a recent password.';
        } else {
            $newHash = hash_secret($new);

            $pdo->beginTransaction();
            $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([$newHash, $user['id']]);
            $pdo->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)')->execute([$user['id'], $newHash]);
            $pdo->commit();

            // The reset is used up: reloading or pressing Back cannot repeat it.
            unset($_SESSION['reset_auth']);
            session_regenerate_id(true);
            throttle_reset((string)$user['username']);

            log_event('PASSWORD_CHANGED', 'Password changed through Forgot Password.', (int)$user['id'], (string)$user['username']);

            if (send_password_changed_email($user)) {
                log_event('ALERT_EMAIL_SENT', 'Password changed alert.', (int)$user['id'], (string)$user['username']);
            }

            redirect('login?changed=1');
        }
    }
}

page_start('Change Password', ['validate.js', 'password.js']);
?>
<section class="card form-card narrow">
    <h1>Change Password</h1>

    <form method="post" novalidate autocomplete="off" id="change-form"
          data-min-pass="<?= MIN_PASSWORD_LENGTH ?>" data-max-pass="<?= MAX_PASSWORD_LENGTH ?>">
        <?= csrf_field() ?>
        <div class="form-group">
            <?= field_label('password', 'Enter Password', true) ?>
            <input type="password" id="password" name="password" maxlength="<?= MAX_PASSWORD_LENGTH ?>" autocomplete="new-password">
            <div class="strength" id="strength-box"><div class="strength-bar" id="strength-bar"></div></div>
            <small class="hint" id="strength-label">Strength: -</small>
            <?= field_error($errors, 'password') ?>
        </div>
        <div class="form-group">
            <?= field_label('confirm_password', 'Re-enter Password', true) ?>
            <input type="password" id="confirm_password" name="confirm_password" maxlength="<?= MAX_PASSWORD_LENGTH ?>" autocomplete="new-password">
            <?= field_error($errors, 'confirm_password') ?>
        </div>
        <label class="inline-check"><input type="checkbox" id="show-password"> Show Password</label>
        <button type="submit" class="btn">Change Password</button>
    </form>
</section>
<?php page_end();
