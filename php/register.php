<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

if (!empty($_SESSION['user_id'])) {
    redirect('dashboard');
}

const REG_FIELDS = [
    'student_id', 'first_name', 'middle_name', 'last_name', 'extension_choice',
    'other_extension', 'birthdate', 'street', 'barangay', 'city', 'province',
    'country', 'postal_code', 'email', 'username', 'academic_program',
    'year_level', 'student_status', 'emergency_contact', 'subject_interests',
    'question1', 'question2', 'question3', 'answer1', 'answer2', 'answer3',
];

$v = [];
foreach (REG_FIELDS as $f) {
    $v[$f] = trim((string)($_POST[$f] ?? ''));
}
$password = (string)($_POST['password'] ?? '');
$confirm  = (string)($_POST['confirm_password'] ?? '');
$errors = [];
$formError = '';
$ageDisplay = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    $ip = client_ip();

    if (honeypot_triggered()) {
        // A bot filled the hidden field: refuse silently.
        log_event('HONEYPOT_TRIGGERED', 'Hidden registration field was filled.', null, $v['username']);
        redirect('index');
    }

    if (ip_block_remaining($ip) > 0) {
        $formError = 'Too many failed attempts from your network. Please try again later.';
    } elseif (!captcha_verify()) {
        captcha_fail($v['username']);
        $formError = 'Please complete the CAPTCHA and try again.';
    } else {
        $errors['student_id'] = validate_id_number($v['student_id']);
        $errors['first_name'] = validate_name($v['first_name'], 'First Name', true);
        $errors['middle_name'] = validate_name($v['middle_name'], 'Middle Name', false);
        $errors['last_name'] = validate_name($v['last_name'], 'Family Name', true);
        [$extension, $errors['other_extension']] = validate_name_extension($v['extension_choice'], $v['other_extension']);

        [$errors['birthdate'], $age] = validate_birthdate($v['birthdate']);

        $errors['street'] = validate_street($v['street']);
        $errors['barangay'] = validate_title_case_place($v['barangay'], 'Barangay');
        $errors['city'] = validate_title_case_place($v['city'], 'Municipality / City');
        $errors['province'] = validate_title_case_place($v['province'], 'Province');
        $errors['country'] = validate_title_case_place($v['country'], 'Country');
        $errors['postal_code'] = validate_zip($v['postal_code']);

        $errors['email'] = validate_student_email($v['email']);
        $errors['username'] = validate_username($v['username']);
        $errors['password'] = validate_password($password);
        $errors['confirm_password'] = ($password !== $confirm) ? 'Passwords do not match.' : null;

        $errors['academic_program'] = validate_dropdown($v['academic_program'], PROGRAM_LIST, 'Please select a valid academic program.');
        $errors['year_level'] = validate_dropdown($v['year_level'], YEAR_LEVEL_LIST, 'Please select a valid year level.');
        $errors['student_status'] = validate_dropdown($v['student_status'], STUDENT_STATUS_LIST, 'Please select a valid student status.');
        $errors['emergency_contact'] = validate_emergency_contact($v['emergency_contact']);
        $errors['subject_interests'] = validate_subject_interests($v['subject_interests']);

        $chosen = [$v['question1'], $v['question2'], $v['question3']];
        foreach (validate_question_choices($chosen) as $i => $message) {
            $errors['question' . ($i + 1)] = $message;
        }
        foreach (['answer1', 'answer2', 'answer3'] as $i => $key) {
            $errors[$key] = validate_security_answer($v[$key], 'Answer ' . ($i + 1));
        }

        if (($_POST['consent'] ?? '') !== '1') {
            $errors['consent'] = 'You must agree to the Privacy Notice to register.';
        }

        $errors = array_filter($errors, static fn($m) => $m !== null && $m !== '');

        if (!$errors) {
            $emailLower = strtolower($v['email']);

            $dup = $pdo->prepare('SELECT student_id, email, username FROM users WHERE student_id = ? OR email = ? OR username = ?');
            $dup->execute([$v['student_id'], $emailLower, $v['username']]);
            foreach ($dup->fetchAll() as $row) {
                if ($row['student_id'] === $v['student_id']) {
                    $errors['student_id'] = 'This ID Number is already registered.';
                }
                if ($row['email'] === $emailLower) {
                    $errors['email'] = 'This email is already registered.';
                }
                if (strcasecmp($row['username'], $v['username']) === 0) {
                    $errors['username'] = 'This username is already taken.';
                }
            }
        }

        if (!$errors) {
            try {
                do {
                    $card = 'LIB-' . str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
                    $chk = $pdo->prepare('SELECT 1 FROM users WHERE library_card = ?');
                    $chk->execute([$card]);
                } while ($chk->fetchColumn());

                [$contactEnc, $contactIv] = encrypt_field($v['emergency_contact']);
                $passwordHash = hash_secret($password);

                $pdo->beginTransaction();

                $pdo->prepare(
                    'INSERT INTO users
                     (student_id, first_name, middle_name, last_name, name_extension,
                      birthdate, age, email, username, password_hash, library_card,
                      academic_program, year_level, student_status,
                      emergency_contact_enc, emergency_contact_iv, subject_interests,
                      privacy_consent_at, street, barangay, city, province, country, postal_code)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW(),?,?,?,?,?,?)'
                )->execute([
                    $v['student_id'], $v['first_name'], $v['middle_name'] ?: null, $v['last_name'], $extension,
                    $v['birthdate'], $age, $emailLower, $v['username'], $passwordHash, $card,
                    $v['academic_program'], $v['year_level'], $v['student_status'],
                    $contactEnc, $contactIv, $v['subject_interests'] ?: null,
                    $v['street'], $v['barangay'], $v['city'], $v['province'], $v['country'], $v['postal_code'],
                ]);
                $userId = (int)$pdo->lastInsertId();

                // Security answers are hashed (lowercase first), like passwords.
                $ins = $pdo->prepare('INSERT INTO security_answers (user_id, question_code, answer_hash) VALUES (?,?,?)');
                foreach ($chosen as $i => $code) {
                    $ins->execute([$userId, $code, hash_secret(normalize_answer($v['answer' . ($i + 1)]))]);
                }

                $pdo->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)')
                    ->execute([$userId, $passwordHash]);

                $pdo->commit();

                log_event('REGISTERED', 'New account saved (not yet verified).', $userId, $v['username']);

                $user = find_user_by_id($userId);
                if ($user === null) {
                    redirect('login');
                }
                flash_set('success', 'Registered successfully! Enter the code we sent to your email to verify your account.');
                $otpError = otp_issue($user, 'register');
                otp_flow_start($user, 'register');
                if ($otpError !== null) {
                    flash_set('error', $otpError);
                }
                redirect('verify_otp');
            } catch (Throwable $ex) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                error_log('Registration error: ' . $ex->getMessage());
                $formError = 'We could not complete your registration. Please try again later.';
            }
        }
    }
}

if ($v['birthdate'] !== '') {
    [$ignore, $calc] = validate_birthdate($v['birthdate']);
    $ageDisplay = $calc === null ? '' : (string)$calc;
}

function reg_input(string $name, string $label, bool $required, array $v, array $errors, array $attr = []): void
{
    $type = $attr['type'] ?? 'text';
    $extra = '';
    foreach ($attr as $k => $val) {
        if ($k !== 'type') {
            $extra .= ' ' . e($k) . '="' . e($val) . '"';
        }
    }
    echo '<div class="form-group">';
    echo field_label($name, $label, $required);
    echo '<input type="' . e($type) . '" id="' . e($name) . '" name="' . e($name) . '" value="' . old($v, $name) . '"' . $extra . '>';
    echo field_error($errors, $name);
    echo '</div>';
}

function reg_select(string $name, string $label, array $options, array $v, array $errors, bool $required = true): void
{
    echo '<div class="form-group">' . field_label($name, $label, $required);
    echo '<select id="' . e($name) . '" name="' . e($name) . '"><option value="">-- Select --</option>';
    foreach ($options as $opt) {
        $sel = ($v[$name] ?? '') === $opt ? ' selected' : '';
        echo '<option value="' . e($opt) . '"' . $sel . '>' . e($opt) . '</option>';
    }
    echo '</select>' . field_error($errors, $name) . '</div>';
}

page_start('Register', ['validate.js', 'register.js'], true);
?>
<section class="card form-card">
    <h1>Create an account</h1>
    <p class="muted">Fields marked <span class="req">*</span> are required.</p>

    <?php if ($formError !== ''): ?>
        <div class="notice notice-error" role="alert"><?= e($formError) ?></div>
    <?php endif; ?>

    <form method="post" id="register-form" novalidate autocomplete="off"
          data-min-user="<?= MIN_USERNAME_LENGTH ?>" data-max-user="<?= MAX_USERNAME_LENGTH ?>"
          data-min-pass="<?= MIN_PASSWORD_LENGTH ?>" data-max-pass="<?= MAX_PASSWORD_LENGTH ?>"
          data-max-name="<?= MAX_NAME_LENGTH ?>">
        <?= csrf_field() ?>
        <div class="hp-field" aria-hidden="true">
            <label for="website">Leave this field empty</label>
            <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
        </div>

        <h2>Personal information</h2>
        <?php reg_input('student_id', 'ID Number', true, $v, $errors, ['placeholder' => 'xxxx-xxxx', 'maxlength' => '9']); ?>
        <?php reg_input('first_name', 'First Name', true, $v, $errors, ['maxlength' => (string)MAX_NAME_LENGTH]); ?>
        <?php reg_input('middle_name', 'Middle Name', false, $v, $errors, ['maxlength' => (string)MAX_NAME_LENGTH]); ?>
        <?php reg_input('last_name', 'Family Name', true, $v, $errors, ['maxlength' => (string)MAX_NAME_LENGTH]); ?>

        <div class="form-group">
            <?= field_label('extension_choice', 'Name Extension', false) ?>
            <select id="extension_choice" name="extension_choice">
                <?php foreach (['' => 'None', 'Jr.' => 'Jr.', 'Sr.' => 'Sr.', 'Other' => 'Other'] as $val => $text): ?>
                    <option value="<?= e($val) ?>" <?= $v['extension_choice'] === $val ? 'selected' : '' ?>><?= e($text) ?></option>
                <?php endforeach; ?>
            </select>
            <input type="text" id="other_extension" name="other_extension" value="<?= old($v, 'other_extension') ?>"
                   placeholder="e.g. III" maxlength="10" class="<?= $v['extension_choice'] === 'Other' ? '' : 'hidden' ?>">
            <?= field_error($errors, 'other_extension') ?>
        </div>

        <div class="form-row">
            <?php reg_input('birthdate', 'Birthdate', true, $v, $errors, ['type' => 'date']); ?>
            <div class="form-group">
                <?= field_label('age', 'Age', true) ?>
                <input type="text" id="age" value="<?= e($ageDisplay) ?>" readonly tabindex="-1">
            </div>
        </div>

        <h2>Address</h2>
        <?php reg_input('street', 'Purok / Street', true, $v, $errors, ['maxlength' => '50']); ?>
        <?php reg_input('barangay', 'Barangay', true, $v, $errors, ['maxlength' => '50']); ?>
        <?php reg_input('city', 'Municipality / City', true, $v, $errors, ['maxlength' => '50']); ?>
        <?php reg_input('province', 'Province', true, $v, $errors, ['maxlength' => '50']); ?>
        <?php reg_input('country', 'Country', true, $v, $errors, ['maxlength' => '50']); ?>
        <?php reg_input('postal_code', 'ZIP Code', true, $v, $errors, ['maxlength' => '4', 'inputmode' => 'numeric']); ?>

        <h2>Library information</h2>
        <?php reg_select('academic_program', 'Academic Program', PROGRAM_LIST, $v, $errors); ?>
        <?php reg_select('year_level', 'Year Level', YEAR_LEVEL_LIST, $v, $errors); ?>
        <?php reg_select('student_status', 'Student Status', STUDENT_STATUS_LIST, $v, $errors); ?>
        <?php reg_input('emergency_contact', 'Emergency Contact Number', true, $v, $errors, ['placeholder' => '09xxxxxxxxx', 'maxlength' => '11', 'inputmode' => 'numeric']); ?>
        <?php reg_input('subject_interests', 'Subjects of Interest', false, $v, $errors, ['maxlength' => '100', 'placeholder' => 'e.g. Networking, Databases']); ?>

        <h2>Account</h2>
        <?php reg_input('email', 'Email', true, $v, $errors, ['type' => 'email', 'maxlength' => '100']); ?>
        <?php reg_input('username', 'Username', true, $v, $errors, ['maxlength' => (string)MAX_USERNAME_LENGTH]); ?>
        <small class="hint" id="username-status"></small>

        <div class="form-group">
            <?= field_label('password', 'Password', true) ?>
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

        <h2>Authentication questions</h2>
        <p class="muted">Choose three different questions and answer each one. You will be asked one of them if you forget your password.</p>
        <?php for ($n = 1; $n <= REQUIRED_QUESTIONS; $n++): ?>
            <div class="form-group">
                <?= field_label('question' . $n, 'Question ' . $n, true) ?>
                <select id="question<?= $n ?>" name="question<?= $n ?>">
                    <option value="">Select a question</option>
                    <?php foreach (QUESTION_BANK as $code => $text): ?>
                        <option value="<?= e($code) ?>" <?= ($v['question' . $n] === $code) ? 'selected' : '' ?>><?= e($text) ?></option>
                    <?php endforeach; ?>
                </select>
                <?= field_error($errors, 'question' . $n) ?>
            </div>
            <div class="form-group">
                <?= field_label('answer' . $n, 'Answer ' . $n, true) ?>
                <input type="text" id="answer<?= $n ?>" name="answer<?= $n ?>" value="<?= old($v, 'answer' . $n) ?>" maxlength="50" autocomplete="off">
                <?= field_error($errors, 'answer' . $n) ?>
            </div>
        <?php endfor; ?>

        <div class="form-group">
            <label class="inline-check">
                <input type="checkbox" id="consent" name="consent" value="1">
                I have read the <a href="privacy_notice" target="_blank" rel="noopener">Privacy Notice</a> and agree to the
                collection and processing of my personal data in accordance with the Data Privacy Act of 2012 (RA 10173).
            </label>
            <?= field_error($errors, 'consent') ?>
        </div>

        <div class="form-group"><?= captcha_widget() ?></div>

        <button type="submit" class="btn">Register</button>
    </form>
</section>
<?php page_end();