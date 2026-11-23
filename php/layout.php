<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Page layout (handout section 3): system name ABOVE the header, header
| links in the upper-right, copyright footer. No inline CSS or JavaScript.
|--------------------------------------------------------------------------
*/

/*
| $scripts: extra files from js/ to load (common.js is always loaded).
| $needCaptcha: loads the reCAPTCHA widget script.
*/
function page_start(string $title, array $scripts = [], bool $needCaptcha = false): void
{
    $loggedIn = !empty($_SESSION['user_id']);
    $page = basename($_SERVER['PHP_SELF'] ?? '', '.php');

    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">';
    echo '<title>' . e($title) . ' | ' . e(APP_NAME) . '</title>';
    echo '<link rel="stylesheet" href="css/style.css">';
    echo '<link rel="stylesheet" href="css/pages.css">';
    echo '</head>';

    $bodyAttrs = '';
    if ($loggedIn) {
        $bodyAttrs = ' data-idle-left="' . idle_seconds_left() . '"'
            . ' data-idle-warn="' . IDLE_WARNING_SECONDS . '"'
            . ' data-csrf="' . e(csrf_token()) . '"';
    }
    echo '<body' . $bodyAttrs . '>';

    // 1. Approved system name ABOVE the header.
    echo '<div class="site-name">' . e(APP_NAME) . '</div>';

    // 2. Header links, upper-right.
    echo '<header class="site-header"><nav class="main-nav">';
    if ($loggedIn) {
        echo '<a href="dashboard">Home</a>';
        echo '<a href="logout">Log-out</a>';          // only for logged-in users
    } elseif ($page === 'login') {
        echo '<a href="index">Home</a><a href="register">Register</a>';
    } elseif ($page === 'register') {
        echo '<a href="index">Home</a><a href="login">Log-in</a>';
    } else {
        echo '<a href="index">Home</a><a href="register">Register</a><a href="login">Log-in</a>';
    }
    echo '</nav></header>';

    echo '<main class="main-content">';

    $flash = flash_get();
    if ($flash && $flash['type'] === 'success') {
        // Success messages pop up as a snackbar and hide by themselves (see js/common.js).
        echo '<div id="snackbar" class="snackbar" role="status" aria-live="polite">' . e($flash['message']) . '</div>';
    } elseif ($flash) {
        echo '<div class="notice notice-' . e($flash['type']) . '" role="status">' . e($flash['message']) . '</div>';
    }

    // Scripts are queued and printed by page_end().
    $GLOBALS['page_scripts'] = $scripts;
    $GLOBALS['page_captcha'] = $needCaptcha;
}

function page_end(): void
{
    $loggedIn = !empty($_SESSION['user_id']);

    echo '</main>';
    echo '<footer class="site-footer">';
    echo '<p>&copy; ' . date('Y') . ' ' . e(OWNER_NAME) . '. All rights reserved.</p>';
    echo '<a href="privacy_notice">Privacy Notice</a>';
    echo '</footer>';

    if ($loggedIn) {
        echo '<div id="idle-modal" class="idle-modal hidden" role="alertdialog" aria-live="assertive">'
            . '<div class="idle-box"><h2>Are you still there?</h2>'
            . '<p>You will be logged out in <strong id="idle-count">60</strong> seconds because of inactivity.</p>'
            . '<button type="button" id="idle-stay" class="btn">Stay logged in</button></div></div>';
    }

    if (!empty($GLOBALS['page_captcha'])) {
        echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
    }
    echo '<script src="js/common.js"></script>';
    if ($loggedIn) {
        echo '<script src="js/idle.js"></script>';
    }
    foreach ($GLOBALS['page_scripts'] ?? [] as $file) {
        echo '<script src="js/' . e($file) . '"></script>';
    }
    echo '</body></html>';
}

/* Renders the field label with the red asterisk or the red "optional" tag (3.3). */
function field_label(string $for, string $text, bool $required): string
{
    $mark = $required
        ? '<span class="req">*</span>'
        : ' <span class="opt">optional</span>';
    return '<label for="' . e($for) . '">' . e($text) . $mark . '</label>';
}

/* Error text directly UNDER its own field. */
function field_error(array $errors, string $name): string
{
    return '<small class="field-error" data-error-for="' . e($name) . '">'
        . e($errors[$name] ?? '') . '</small>';
}

function old(array $values, string $name): string
{
    return e($values[$name] ?? '');
}

function captcha_widget(): string
{
    return '<div class="g-recaptcha" data-sitekey="' . e(RECAPTCHA_SITE_KEY) . '"></div>';
}