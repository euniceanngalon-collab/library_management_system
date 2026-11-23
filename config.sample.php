<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| config.sample.php  -  SAFE TO COMMIT (all values below are fake)
|--------------------------------------------------------------------------
| HOW TO USE
|  1. Create the folder   C:\xampp\library_private\      (OUTSIDE htdocs)
|  2. Copy THIS file there and rename the copy to exactly:   config.php
|     (not config.php.txt, not error.log - the file name must be config.php)
|  3. Replace every fake value with your real one.
|  4. NEVER commit the real config.php (it is listed in .gitignore).
|
| The app finds it at  C:\xampp\library_private\config.php  automatically.
| Different place? Set the Windows environment variable LIBRARY_CONFIG to the full path.
*/

/* ---------- Database ---------- */
// Use the limited 'library_app' user from the end of sql/database.sql (no DELETE on activity_logs).
// For quick local testing XAMPP's default is user 'root' with an empty password.
define('DB_HOST', 'localhost');
define('DB_NAME', 'library_management_db');
define('DB_USER', 'root');
define('DB_PASS', '');

/* ---------- Public URL (used for links inside emails) ---------- */
define('APP_URL', 'http://localhost/library_management');   // no trailing slash

/* ---------- Encryption / OTP key ---------- */
// Long random string. KEEP your old value if you already have encrypted emergency contacts,
// otherwise they can no longer be decrypted. Make a new one with:
//   php -r "echo bin2hex(random_bytes(32));"
define('APP_KEY', 'put-64-random-hex-characters-here');

/* ---------- Error log (outside the web root, never committed) ---------- */
// A DIFFERENT file from config.php. PHP errors are written here, never shown to visitors.
define('ERROR_LOG_FILE', 'C:\\xampp\\library_private\\error.log');

/* ---------- Email (PHPMailer + SMTP) ---------- */
// Gmail: turn on 2-Step Verification, then create an App Password (16 letters, no spaces).
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_AUTH', true);
define('SMTP_SECURE', 'tls');                      // 'tls' (587), 'ssl' (465) or '' (Mailpit)
define('SMTP_USER', 'your.address@gmail.com');
define('SMTP_PASS', 'xxxx xxxx xxxx xxxx');         // the App Password, NOT your Gmail password
define('MAIL_FROM', 'your.address@gmail.com');
define('MAIL_FROM_NAME', 'Library Management System');  // shown in the "From:" line of emails

/* Mailpit instead of Gmail (instructor-approved):
   SMTP_HOST '127.0.0.1', SMTP_PORT 1025, SMTP_AUTH false, SMTP_SECURE '' */

/* ---------- Google reCAPTCHA v2 ("I'm not a robot") ---------- */
// Get keys at https://www.google.com/recaptcha/admin (type: v2 checkbox, domain: localhost).
// Google's public TEST keys (always pass) are fine for development only:
define('RECAPTCHA_SITE_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI');
define('RECAPTCHA_SECRET_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe');
