/* Log-in / Forgot Password: visible lockout countdown. The SERVER enforces the lock. */
(function () {
    'use strict';
    var counter = document.getElementById('lock-count');
    if (!counter) { return; }

    var seconds = parseInt(counter.getAttribute('data-seconds'), 10);
    var button = document.getElementById('login-btn');
    var registerLink = document.getElementById('register-link');
    var notice = counter.parentElement;

    // Count down against a fixed deadline, so a busy or background tab cannot make it drift.
    var deadline = Date.now() + seconds * 1000;

    var timer = setInterval(function () {
        var left = Math.ceil((deadline - Date.now()) / 1000);
        counter.textContent = String(Math.max(left, 0));
        if (left <= 0) {
            clearInterval(timer);
            if (button) { button.disabled = false; }
            if (registerLink) { registerLink.classList.remove('link-disabled'); }
            if (notice) { notice.classList.add('hidden'); }
        }
    }, 250);
})();
