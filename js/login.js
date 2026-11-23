/* Log-in / Forgot Password: visible lockout countdown. The SERVER enforces the lock. */
(function () {
    'use strict';
    var counter = document.getElementById('lock-count');
    if (!counter) { return; }

    var seconds = parseInt(counter.getAttribute('data-seconds'), 10);
    var button = document.getElementById('login-btn');
    var registerLink = document.getElementById('register-link');
    var notice = counter.parentElement;

    // While locked the link has no href, but block Enter/click anyway.
    if (registerLink) {
        registerLink.addEventListener('click', function (ev) {
            if (registerLink.classList.contains('link-disabled')) { ev.preventDefault(); }
        });
    }

    // Count down against a fixed deadline, so a busy or background tab cannot make it drift.
    var deadline = Date.now() + seconds * 1000;

    // Long waits (the 10-minute IP block) are shown as m:ss, short ones as plain seconds.
    var clock = counter.getAttribute('data-format') === 'clock';
    function show(left) {
        left = Math.max(left, 0);
        if (!clock) { return String(left); }
        var m = Math.floor(left / 60), s = left % 60;
        return m + ':' + (s < 10 ? '0' : '') + s;
    }

    var timer = setInterval(function () {
        var left = Math.ceil((deadline - Date.now()) / 1000);
        counter.textContent = show(left);
        if (left <= 0) {
            clearInterval(timer);
            if (button) { button.disabled = false; }
            if (registerLink) {
                registerLink.classList.remove('link-disabled');
                registerLink.removeAttribute('aria-disabled');
                registerLink.removeAttribute('tabindex');
                registerLink.setAttribute('href', registerLink.getAttribute('data-href'));
            }
            if (notice) { notice.classList.add('hidden'); }
        }
    }, 250);
})();