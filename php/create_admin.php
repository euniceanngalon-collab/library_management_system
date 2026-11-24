<?php
declare(strict_types=1);

/*
| Creates a verified account from the command line.
| Admins are NEVER created through the registration form.
|
| Usage:
| php php/create_admin.php <role> <username> <email> <ID xxxx-xxxx> <FirstName> <FamilyName>
*/

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Page Not Found');
}

require_once __DIR__ . '/bootstrap.php';

if ($argc < 7 || !in_array($argv[1], ['admin', 'librarian', 'student'], true)) {
    exit("Usage: php php/create_admin.php <admin|librarian|student> <username> <email> <ID xxxx-xxxx> <FirstName> <FamilyName>\n");
}

[, $role, $username, $email, $idNumber, $first, $family] = $argv;

foreach ([
    validate_username($username),
    validate_email($email),
    validate_id_number($idNumber),
    validate_name($first, 'First Name', true),
    validate_name($family, 'Family Name', true)
] as $err) {
    if ($err !== null) {
        exit("Error: $err\n");
    }
}

echo 'Password (shown while typing): ';
$password = trim((string)fgets(STDIN));

if (($err = validate_password($password)) !== null) {
    exit("Error: $err\n");
}

/* Ask for real security answers. */
$staffAnswers = [];

foreach (DEFAULT_STAFF_QUESTIONS as $code) {
    $question = QUESTION_BANK[$code];

    while (true) {
        echo $question . "\n";
        echo 'Your answer: ';

        $answer = trim((string)fgets(STDIN));

        $err = validate_security_answer(
            $answer,
            'Security answer'
        );

        if ($err !== null) {
            echo "Error: $err\n";
            continue;
        }

        $staffAnswers[$code] = hash_secret(
            normalize_answer($answer)
        );

        break;
    }

    echo "\n";
}

[$contactEnc, $contactIv] = encrypt_field('09000000000');
$hash = hash_secret($password);

$pdo->beginTransaction();

$pdo->prepare(
    "INSERT INTO users (
        student_id, first_name, last_name, birthdate, age,
        email, username, password_hash, library_card,
        academic_program, year_level, student_status,
        emergency_contact_enc, emergency_contact_iv,
        role, privacy_consent_at, email_verified_at,
        street, barangay, city, province, country, postal_code
    )
    VALUES (
        ?,?,?, '1990-01-01',36,?,?,?,?,
        'Other','1st Year','Currently Enrolled',
        ?,?,?,NOW(),NOW(),
        'Staff Office','Poblacion','Bislig City',
        'Surigao Del Sur','Philippines','8311'
    )"
)->execute([
    $idNumber,
    $first,
    $family,
    strtolower($email),
    $username,
    $hash,
    'LIB-' . str_pad(
        (string)random_int(0, 999999),
        6,
        '0',
        STR_PAD_LEFT
    ),
    $contactEnc,
    $contactIv,
    $role
]);

$id = (int)$pdo->lastInsertId();

$ins = $pdo->prepare(
    'INSERT INTO security_answers
    (user_id, question_code, answer_hash)
    VALUES (?,?,?)'
);

foreach ($staffAnswers as $code => $answerHash) {
    $ins->execute([$id, $code, $answerHash]);
}

$pdo->prepare(
    'INSERT INTO password_history (user_id, password_hash)
    VALUES (?, ?)'
)->execute([$id, $hash]);

$pdo->commit();

echo "Created $role '$username' (verified).\n";
echo "Security answers successfully saved.\n";
