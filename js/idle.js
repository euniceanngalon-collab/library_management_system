/*
 * Idle timeout: warns 1 minute before, then logs out. The server keeps its own
 * clock (php/bootstrap.php require_login), so disabling this script gains nothing.
 */
(function () {
    'use strict';
    var body = document.body;
    var left = parseInt(body.getAttribute('data-idle-left'), 10);
    var warn = parseInt(body.getAttribute('data-idle-warn'), 10);
    var csrf = body.getAttribute('data-csrf');
    if (isNaN(left)) { return; }

    var modal = document.getElementById('idle-modal');
    var count = document.getElementById('idle-count');
    var stay = document.getElementById('idle-stay');
    var warning = false;
    var lastPing = Date.now();

    function ping() {
        lastPing = Date.now();
        return fetch('php/keepalive', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': csrf }
        }).then(function (r) { return r.json(); }).then(function (data) {
            if (data.ok) {
                left = data.left;
                warning = false;
                modal.classList.add('hidden');
            } else {
                window.location.href = 'logout?timeout=1';
            }
        }).catch(function () { /* the server clock still applies */ });
    }

    ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(function (name) {
        document.addEventListener(name, function () {
            // Passive activity extends the session (at most every 30 s), but not while the warning is shown.
            if (!warning && Date.now() - lastPing > 30000) { ping(); }
        }, { passive: true });
    });

    stay.addEventListener('click', ping);

    setInterval(function () {
        left -= 1;
        if (left <= warn && left > 0) {
            warning = true;
            modal.classList.remove('hidden');
            count.textContent = String(left);
        }
        if (left <= 0) {
            window.location.href = 'logout?timeout=1';
        }
    }, 1000);
})();
