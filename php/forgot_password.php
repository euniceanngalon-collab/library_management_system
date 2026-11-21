<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

if (!empty($_SESSION['user_id'])) {
    redirect('dashboard');
}

/*
| Steps are remembered in the SERVER session ($_SESSION['fp']):
|   step 1 = username + CAPTCHA, step 2 = security question.
| Every answer is treated the same whether the username exists or not.
*/
$fp = $_SESSION['fp'] ?? null;
$step = (is_array($fp) && (time() - (int)$fp['started']) < 900) ? 2 : 1;
if ($step === 1) {
    unset($_SESSION['fp']);
}

$error = '';
$errors = [];
$lockSeconds = 0;
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    $ip = client_ip();
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'restart') {
        unset($_SESSION['fp']);
        redirect('forgot_password');
    }

    if ($step === 1) {
        $username = trim((string)($_POST['username'] ?? ''));

        if (ip_block_remaining($ip) > 0) {
            $error = 'Too many failed attempts from your network. Please wait.';
        } elseif ($username === '') {
            $errors['username'] = 'Username is required.';
        } elseif (!captcha_verify()) {
            captcha_fail($username);
            $error = 'Please complete the CAPTCHA and try again.';
        } else {
            $known = find_user_by_username(substr($username, 0, 100));
            log_event('RESET_REQUESTED', 'Forgot Password started.', $known ? (int)$known['id'] : null, $username);
            $_SESSION['fp'] = ['username' => $username, 'started' => time()];
            redirect('forgot_password');
        }
    } else {
        $username = (string)$fp['username'];
        $state = throttle_state($username);
        $questionCodes = forgot_question_codes($username, find_user_by_username(substr($username, 0, 100)));

        if (ip_block_remaining($ip) > 0) {
            $error = 'Too many failed attempts from your network. Please wait.';
        } elseif ($state['remaining'] > 0) {
            $lockSeconds = $state['remaining'];
            $error = 'Too many failed attempts. Please wait for the countdown to finish.';
        } else {
            $code = (string)($_POST['question'] ?? '');
            $answer = trim((string)($_POST['answer'] ?? ''));
            $again = trim((string)($_POST['answer2'] ?? ''));

            if (!in_array($code, $questionCodes, true)) {
                $errors['question'] = 'Please choose one of the questions.';
            }
            if ($answer === '') {
                $errors['answer'] = 'Your Answer is required.';
            } elseif (($m = validate_security_answer($answer, 'Your Answer')) !== null) {
                $errors['answer'] = $m;
            }
            if ($answer !== $again) {
                // They must match before anything is checked.
                $errors['answer2'] = 'Answers do not match.';
            }

            if (!$errors) {
                $user = find_user_by_username(substr($username, 0, 100));
                $hash = null;

                if ($user) {
                    $stmt = $pdo->prepare('SELECT answer_hash FROM security_answers WHERE user_id = ? AND question_code = ?');
                    $stmt->execute([$user['id'], $code]);
                    $hash = $stmt->fetchColumn() ?: null;
                }

                // Dummy hash for unknown users keeps timing and behaviour the same.
                $ok = password_verify(normalize_answer($answer), $hash ?? hash_secret('dummy-answer')) && $hash !== null;

                if ($ok && (int)$user['id'] > 0 && !empty($user['email_verified_at'])) {
                    unset($_SESSION['fp']);
                    $err = otp_issue($user, 'reset');
                    otp_flow_start($user, 'reset');
                    if ($err !== null) {
                        flash_set('error', $err);
                    }
                    redirect('verify_otp');
                }

                // A wrong answer counts toward the SAME lockout as log-in.
                $lockSeconds = handle_failed_attempt($username, $user, 'Wrong security answer (Forgot Password).');
                $error = 'The answer is incorrect.';
            }
        }
    }
} elseif ($step === 2) {
    $username = (string)$fp['username'];
    $questionCodes = forgot_question_codes($username, find_user_by_username(substr($username, 0, 100)));
    $lockSeconds = throttle_state($username)['remaining'];
}

page_start('Forgot Password', ['login.js'], $step === 1);
?>
<section class="card form-card narrow">
    <h1>Forgot Password</h1>

    <?php if ($error !== ''): ?>
        <div class="notice notice-error" role="alert"><?= e($error) ?></div>
    <?php endif; ?>
    <?php if ($lockSeconds > 0): ?>
        <div class="notice notice-warning" role="status">
            Locked. Try again in <strong id="lock-count" data-seconds="<?= (int)$lockSeconds ?>"><?= (int)$lockSeconds ?></strong> seconds.
        </div>
    <?php endif; ?>

<?php if ($step === 1): ?>
    <form method="post" novalidate>
        <?= csrf_field() ?>
        <div class="form-group">
            <?= field_label('username', 'Username', true) ?>
            <input type="text" id="username" name="username" value="<?= e($username) ?>" maxlength="100" autocomplete="username">
            <?= field_error($errors, 'username') ?>
        </div>
        <div class="form-group"><?= captcha_widget() ?></div>
        <button type="submit" class="btn">Continue</button>
    </form>
<?php else: ?>
    <form method="post" novalidate autocomplete="off">
        <?= csrf_field() ?>
        <p><strong>Choose the following question</strong></p>
        <div class="form-group">
            <?php foreach ($questionCodes as $i => $code): ?>
                <label class="inline-check">
                    <input type="radio" name="question" value="<?= e($code) ?>" <?= (($_POST['question'] ?? '') === $code) ? 'checked' : '' ?>>
                    <?= e(QUESTION_BANK[$code]) ?>
                </label>
            <?php endforeach; ?>
            <?= field_error($errors, 'question') ?>
        </div>
        <div class="form-group">
            <?= field_label('answer', 'Your Answer', true) ?>
            <input type="password" id="answer" name="answer" maxlength="50">
            <?= field_error($errors, 'answer') ?>
        </div>
        <div class="form-group">
            <?= field_label('answer2', 'Re-enter Answer', true) ?>
            <input type="password" id="answer2" name="answer2" maxlength="50">
            <?= field_error($errors, 'answer2') ?>
        </div>
        <button type="submit" id="login-btn" class="btn" <?= $lockSeconds > 0 ? 'disabled' : '' ?>>Submit</button>
    </form>
    <form method="post" class="inline-form">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="restart">
        <button type="submit" class="link-button">Start over</button>
    </form>
<?php endif; ?>
</section>
<?php page_end();
