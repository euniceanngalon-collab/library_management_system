<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Server-side validation (handout section 4)
|--------------------------------------------------------------------------
| Every function returns NULL when the value is valid, or the exact error
| message when it is not. js/validate.js repeats the same rules in the
| browser for quick feedback, but THIS file is the real protection (S3).
*/

function validate_name(string $v, string $label, bool $required): ?string
{
    if ($v === '') {
        return $required ? "$label is required." : null;
    }
    if (preg_match('/\d/u', $v)) {
        return "Numbers are not allowed in $label.";
    }
    if (preg_match('/[^\p{L} ]/u', $v)) {
        return "Special characters are not allowed in $label.";
    }
    if (str_contains($v, '  ')) {
        return 'Double space is not allowed.';
    }
    if ($v !== trim($v)) {
        return "$label must not start or end with a space.";
    }
    // /i makes the back-reference case-insensitive: Juaaan and JuAaan both fail.
    if (preg_match('/(\p{L})\1\1/iu', $v)) {
        return 'Three consecutive identical letters are not allowed.';
    }
    if (mb_strlen($v) < 2) {
        return "$label must be at least 2 characters.";
    }
    if (mb_strlen($v) > MAX_NAME_LENGTH) {
        return "$label must not exceed " . MAX_NAME_LENGTH . ' characters.';
    }

    $letters = preg_replace('/[^\p{L}]/u', '', $v);
    if (mb_strlen($letters) >= 2 && mb_strtoupper($letters) === $letters) {
        return 'Do not use all capital letters.';
    }

    foreach (explode(' ', $v) as $word) {
        $first = mb_substr($word, 0, 1);
        $rest  = mb_substr($word, 1);

        if ($first !== mb_strtoupper($first)) {
            return 'First letter of your name must be capital.';
        }
        if ($rest !== mb_strtolower($rest)) {
            return 'Only the first letter of each word may be capital.';
        }
    }

    return null;
}

function validate_name_extension(string $choice, string $other): array
{
    // Returns [value-to-save-or-null, error-or-null]
    if ($choice === '') {
        return [null, null];
    }
    if ($choice === 'Jr.' || $choice === 'Sr.') {
        return [$choice, null];
    }
    if ($choice !== 'Other') {
        return [null, 'Please select a valid name extension.'];
    }
    if ($other === '') {
        return [null, 'Please type your name extension.'];
    }
    // Roman numerals are saved exactly as typed. They are all capitals, so
    // they are checked against a list instead of the normal name rules.
    if (in_array($other, ROMAN_EXTENSIONS, true)) {
        return [$other, null];
    }
    $error = validate_name($other, 'Name Extension', true);
    return [$error === null ? $other : null, $error];
}

function validate_id_number(string $v): ?string
{
    return preg_match('/^\d{4}-\d{4}$/', $v) === 1
        ? null
        : 'ID Number must follow the format xxxx-xxxx.';
}

function validate_email(string $v): ?string
{
    if ($v === '' || strlen($v) > 100 || preg_match('/\s/', $v)
        || filter_var($v, FILTER_VALIDATE_EMAIL) === false) {
        return 'Please enter a valid email address.';
    }
    return null;
}

function validate_username(string $v): ?string
{
    if (!preg_match('/^[A-Za-z][A-Za-z0-9]*$/', $v)) {
        return 'Username must start with a letter and contain letters and digits only.';
    }
    $len = strlen($v);
    if ($len < MIN_USERNAME_LENGTH || $len > MAX_USERNAME_LENGTH) {
        return 'Username must be ' . MIN_USERNAME_LENGTH . '-' . MAX_USERNAME_LENGTH . ' characters.';
    }
    return null;
}

/*
| Password strength (my own definition - explain it in Design Decisions):
|   Weak   : shorter than the minimum length, or fewer than 3 character types
|   Medium : at least the minimum length and 3 character types
|   Strong : minimum length + 2 and all 4 types (lower, upper, digit, symbol)
*/
function password_strength(string $pw): string
{
    $types = 0;
    $types += preg_match('/[a-z]/', $pw) ? 1 : 0;
    $types += preg_match('/[A-Z]/', $pw) ? 1 : 0;
    $types += preg_match('/\d/', $pw) ? 1 : 0;
    $types += preg_match('/[^A-Za-z0-9]/', $pw) ? 1 : 0;
    $len = strlen($pw);

    if ($len < MIN_PASSWORD_LENGTH || $types < 3) {
        return 'Weak';
    }
    if ($len >= MIN_PASSWORD_LENGTH + 2 && $types === 4) {
        return 'Strong';
    }
    return 'Medium';
}

function validate_password(string $pw): ?string
{
    $len = strlen($pw);
    if ($len < MIN_PASSWORD_LENGTH || $len > MAX_PASSWORD_LENGTH) {
        return 'Password must be ' . MIN_PASSWORD_LENGTH . '-' . MAX_PASSWORD_LENGTH . ' characters.';
    }
    if (password_strength($pw) === 'Weak') {
        return 'Password is too weak. Use upper and lower case letters, digits and symbols.';
    }
    return null;
}

function calculate_age(DateTime $birth): int
{
    return $birth->diff(new DateTime('today'))->y;
}

/* Returns [error-or-null, age-or-null]. Age is ALWAYS recalculated here. */
function validate_birthdate(string $v): array
{
    $birth = DateTime::createFromFormat('!Y-m-d', $v);
    $errors = DateTime::getLastErrors();

    if ($birth === false || ($errors && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))) {
        return ['Please enter a valid birthdate.', null];
    }
    if ($birth > new DateTime('today')) {
        return ['Birthdate cannot be in the future.', null];
    }
    $age = calculate_age($birth);
    if ($age < 18) {
        return ['You must be at least 18 years old to register.', $age];
    }
    return [null, $age];
}

function validate_title_case_place(string $v, string $label): ?string
{
    if (!preg_match('/^[\p{L}]+( [\p{L}]+)*$/u', $v)) {
        return "$label must contain letters and single spaces only.";
    }
    if (!preg_match('/^\p{Lu}\p{Ll}*( \p{Lu}\p{Ll}*)*$/u', $v)) {
        return "$label must be in Title Case (for example: San Isidro).";
    }
    if (mb_strlen($v) < 2 || mb_strlen($v) > 50) {
        return "$label must be 2-50 characters.";
    }
    return null;
}

function validate_street(string $v): ?string
{
    if (!preg_match('/^[A-Za-z0-9]+( [A-Za-z0-9]+)*$/', $v)) {
        return 'Purok / Street may contain letters, digits and single spaces only.';
    }
    if (strlen($v) < 3 || strlen($v) > 50) {
        return 'Purok / Street must be 3-50 characters.';
    }
    return null;
}

function validate_zip(string $v): ?string
{
    return preg_match('/^\d{4}$/', $v) === 1 ? null : 'ZIP Code must be exactly 4 digits.';
}

function validate_security_answer(string $v, string $label): ?string
{
    if (!preg_match('/^[\p{L}]+( [\p{L}]+)*$/u', $v)) {
        return "$label may contain letters and single spaces only.";
    }
    if (mb_strlen($v) < 2 || mb_strlen($v) > 50) {
        return "$label must be 2-50 characters.";
    }
    return null;
}

/*
| The user picks 3 DIFFERENT questions from the bank (handout section 5).
| Returns one message per slot (null = fine). The server checks the list, because
| a dropdown can be edited with the browser tools.
*/
function validate_question_choices(array $codes): array
{
    $errors = [];
    foreach ($codes as $i => $code) {
        if (!array_key_exists($code, QUESTION_BANK)) {
            $errors[$i] = 'Please select a valid question.';
        } elseif (array_search($code, $codes, true) !== $i) {
            $errors[$i] = 'Please choose three different questions.';
        } else {
            $errors[$i] = null;
        }
    }
    return $errors;
}

/* ---- Library-specific fields ---- */
function validate_dropdown(string $v, array $allowed, string $message): ?string
{
    // Dropdowns can be faked with browser tools, so the server checks the list.
    return in_array($v, $allowed, true) ? null : $message;
}

function validate_emergency_contact(string $v): ?string
{
    return preg_match('/^09\d{9}$/', $v) === 1
        ? null
        : 'Contact number must be 11 digits and start with 09.';
}

function validate_subject_interests(string $v): ?string
{
    if ($v === '') {
        return null;
    }
    if (strlen($v) > 100 || !preg_match('/^[A-Za-z, ]+$/', $v)) {
        return 'Subjects of interest may contain letters, commas and spaces only (max 100 characters).';
    }
    return null;
}
