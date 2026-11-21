<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Email (PHPMailer + SMTP). Credentials come from the private config.
| A local inbox such as Mailpit works too: SMTP_HOST=127.0.0.1,
| SMTP_PORT=1025, SMTP_AUTH=false, SMTP_SECURE=''.
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;

function send_mail(string $to, string $subject, string $html, string $text): bool
{
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->Port = SMTP_PORT;
        $mail->SMTPAuth = SMTP_AUTH;

        if (SMTP_AUTH) {
            $mail->Username = SMTP_USER;
            $mail->Password = SMTP_PASS;
        }
        if (SMTP_SECURE === 'tls') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        } elseif (SMTP_SECURE === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        } else {
            $mail->SMTPSecure = '';
            $mail->SMTPAutoTLS = false;
        }

        $mail->CharSet = 'UTF-8';
        $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME);
        $mail->addAddress($to);
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = $html;
        $mail->AltBody = $text;
        $mail->send();

        return true;
    } catch (Throwable $e) {
        error_log('Email failed: ' . $e->getMessage());
        return false;
    }
}

function mail_wrap(string $title, string $bodyHtml): string
{
    return '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;">'
        . '<h2>' . e(APP_NAME) . '</h2><h3>' . e($title) . '</h3>' . $bodyHtml . '</div>';
}

/* OTP email (6.3): system name, purpose, code, expiry time, ignore line. Never a password or login link. */
function send_otp_email(string $to, string $otp, string $purpose, string $expiresAt): bool
{
    $title = otp_purpose_label($purpose);
    $expiryClock = date('g:i A', strtotime($expiresAt)) . ' PHT';
    $ignore = 'If you did not request this code, ignore this email and consider changing your password.';

    $html = mail_wrap($title,
        '<p>Your 6-digit code is:</p>'
        . '<p style="font-size:32px;letter-spacing:8px;font-weight:bold;">' . e($otp) . '</p>'
        . '<p>This code expires at <strong>' . e($expiryClock) . '</strong> (in '
        . OTP_EXPIRY_MINUTES . ' minutes).</p><p>' . e($ignore) . '</p>');

    $text = APP_NAME . "\n" . $title . "\nYour code: {$otp}\n"
        . "Expires at {$expiryClock} (in " . OTP_EXPIRY_MINUTES . " minutes).\n" . $ignore;

    return send_mail($to, APP_NAME . ' - ' . $title, $html, $text);
}

function alert_details_html(): array
{
    $when = date('F j, Y g:i:s A') . ' PHT';
    return [$when, client_ip(), client_user_agent()];
}

/* Security alert to the REAL OWNER of the account (9.1 / 9.2). Never contains any password. */
function send_lockout_alert_email(array $user, int $failures): bool
{
    [$when, $ip, $agent] = alert_details_html();
    $link = APP_URL . '/forgot_password';

    $html = mail_wrap('Failed sign-in attempts on your account',
        '<p><strong>Failed attempts:</strong> ' . $failures . '</p>'
        . '<p><strong>Date and time:</strong> ' . e($when) . '</p>'
        . '<p><strong>IP address:</strong> ' . e($ip) . '</p>'
        . '<p><strong>Browser / device:</strong> ' . e($agent) . '</p>'
        . '<p>If this was not you, reset your password now: '
        . '<a href="' . e($link) . '">' . e($link) . '</a></p>');

    $text = "Failed sign-in attempts on your account\nFailed attempts: {$failures}\n"
        . "Date and time: {$when}\nIP address: {$ip}\nBrowser/device: {$agent}\n"
        . "If this was not you, reset your password now: {$link}";

    return send_mail((string)$user['email'], APP_NAME . ' - Failed sign-in attempts on your account', $html, $text);
}

function send_password_changed_email(array $user): bool
{
    [$when, $ip, $agent] = alert_details_html();
    $link = APP_URL . '/forgot_password';

    $html = mail_wrap('Your password was changed',
        '<p><strong>Date and time:</strong> ' . e($when) . '</p>'
        . '<p><strong>IP address:</strong> ' . e($ip) . '</p>'
        . '<p><strong>Browser / device:</strong> ' . e($agent) . '</p>'
        . '<p>If this was not you, reset your password now: '
        . '<a href="' . e($link) . '">' . e($link) . '</a></p>');

    $text = "Your password was changed\nDate and time: {$when}\nIP address: {$ip}\n"
        . "Browser/device: {$agent}\nIf this was not you, reset your password now: {$link}";

    return send_mail((string)$user['email'], APP_NAME . ' - Your password was changed', $html, $text);
}
