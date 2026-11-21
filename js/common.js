/* Small helpers shared by every page. No inline scripts anywhere (handout 15). */
(function () {
    'use strict';

    // After Log-out, the Back button must not show a protected page.
    // no-store headers already stop the cache; this reloads if the browser restores one anyway.
    window.addEventListener('pageshow', function (event) {
        if (event.persisted) {
            window.location.reload();
        }
    });

    // "Show Password" checkbox: toggles every password field on the page.
    var toggle = document.getElementById('show-password');
    if (toggle) {
        toggle.addEventListener('change', function () {
            document.querySelectorAll('input[type="password"], input[data-was-password]').forEach(function (input) {
                if (toggle.checked) {
                    input.setAttribute('data-was-password', '1');
                    input.type = 'text';
                } else if (input.getAttribute('data-was-password')) {
                    input.type = 'password';
                }
            });
        });
    }
})();
