/* OTP page: Resend button with a visible 60-second countdown. */
(function () {
    'use strict';
    var button = document.getElementById('resend-btn');
    var label = document.getElementById('resend-count');
    if (!button) { return; }

    var seconds = parseInt(button.getAttribute('data-cooldown'), 10) || 0;

    function paint() {
        label.textContent = seconds > 0 ? ' (' + seconds + 's)' : '';
    }
    paint();
    if (seconds <= 0) { return; }

    var timer = setInterval(function () {
        seconds -= 1;
        paint();
        if (seconds <= 0) {
            clearInterval(timer);
            button.disabled = false;
        }
    }, 1000);
})();
