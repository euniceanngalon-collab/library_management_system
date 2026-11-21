/* Live Weak / Medium / Strong meter (Register and Change Password pages). */
(function () {
    'use strict';
    var form = document.getElementById('register-form') || document.getElementById('change-form');
    var input = document.getElementById('password');
    if (!form || !input) { return; }

    var min = parseInt(form.getAttribute('data-min-pass'), 10);
    var bar = document.getElementById('strength-bar');
    var label = document.getElementById('strength-label');

    input.addEventListener('input', function () {
        var level = input.value === '' ? '' : Validate.strength(input.value, min);
        bar.className = 'strength-bar' + (level ? ' s-' + level.toLowerCase() : '');
        label.textContent = 'Strength: ' + (level || '-');
    });
})();
