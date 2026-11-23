/* Register page: live validation, read-only Age, username check, strength meter. */
(function () {
    'use strict';
    var form = document.getElementById('register-form');
    if (!form) { return; }

    var minUser = parseInt(form.dataset.minUser, 10);
    var maxUser = parseInt(form.dataset.maxUser, 10);
    var minPass = parseInt(form.dataset.minPass, 10);
    var maxPass = parseInt(form.dataset.maxPass, 10);
    var maxName = parseInt(form.dataset.maxName, 10);

    function el(id) { return document.getElementById(id); }
    function val(id) { return el(id) ? el(id).value.trim() : ''; }

        // Live password strength indicator
    var passwordInput = el('password');
    var strengthBar = el('strength-bar');
    var strengthLabel = el('strength-label');

    function updatePasswordStrength() {
        var password = passwordInput.value;
        var level = password === '' ? '-' : Validate.strength(password, minPass);

        strengthLabel.textContent = 'Strength: ' + level;

        if (level === 'Weak') {
            strengthBar.style.width = '25%';
            strengthBar.style.backgroundColor = '#dc3545';
        } else if (level === 'Medium') {
            strengthBar.style.width = '65%';
            strengthBar.style.backgroundColor = '#ffc107';
        } else if (level === 'Strong') {
            strengthBar.style.width = '100%';
            strengthBar.style.backgroundColor = '#198754';
        } else {
            strengthBar.style.width = '0%';
            strengthBar.style.backgroundColor = 'transparent';
        }
    }

    passwordInput.addEventListener('input', updatePasswordStrength);

    function showError(id, message) {
        var box = form.querySelector('[data-error-for="' + id + '"]');
        if (box) { box.textContent = message || ''; }
    }

    var rules = {
        student_id:        function () { return Validate.idNumber(val('student_id')); },
        first_name:        function () { return Validate.name(val('first_name'), 'First Name', true, maxName); },
        middle_name:       function () { return Validate.name(val('middle_name'), 'Middle Name', false, maxName); },
        last_name:         function () { return Validate.name(val('last_name'), 'Family Name', true, maxName); },
        birthdate:         function () { return Validate.birthdate(val('birthdate')); },
        street:            function () { return Validate.street(val('street')); },
        barangay:          function () { return Validate.place(val('barangay'), 'Barangay'); },
        city:              function () { return Validate.place(val('city'), 'Municipality / City'); },
        province:          function () { return Validate.place(val('province'), 'Province'); },
        country:           function () { return Validate.place(val('country'), 'Country'); },
        postal_code:       function () { return Validate.zip(val('postal_code')); },
        academic_program:  function () { return val('academic_program') ? null : 'Please select a valid academic program.'; },
        year_level:        function () { return val('year_level') ? null : 'Please select a valid year level.'; },
        student_status:    function () { return val('student_status') ? null : 'Please select a valid student status.'; },
        emergency_contact: function () { return Validate.contact(val('emergency_contact')); },
        subject_interests: function () { return Validate.interests(val('subject_interests')); },
        email: function () { return Validate.studentEmail(val('email')); },
        username:          function () { return Validate.username(val('username'), minUser, maxUser); },
        password:          function () { return Validate.password(el('password').value, minPass, maxPass); },
        confirm_password:  function () { return el('password').value === el('confirm_password').value ? null : 'Passwords do not match.'; },
        question1:         function () { return questionError('question1'); },
        question2:         function () { return questionError('question2'); },
        question3:         function () { return questionError('question3'); },
        answer1:           function () { return Validate.answer(val('answer1'), 'Answer 1'); },
        answer2:           function () { return Validate.answer(val('answer2'), 'Answer 2'); },
        answer3:           function () { return Validate.answer(val('answer3'), 'Answer 3'); },
        consent:           function () { return el('consent').checked ? null : 'You must agree to the Privacy Notice to register.'; }
    };

    // Each question must be chosen and different from the other two.
    function questionError(id) {
        var value = val(id);
        if (value === '') { return 'Please select a valid question.'; }
        var clash = ['question1', 'question2', 'question3'].some(function (other) {
            return other !== id && val(other) === value;
        });
        return clash ? 'Please choose three different questions.' : null;
    }

    function check(id) {
        var message = rules[id]();
        showError(id, message);
        return message === null;
    }

    Object.keys(rules).forEach(function (id) {
        var input = el(id);
        if (input) { input.addEventListener('blur', function () { check(id); }); }
    });

    // Changing one question re-checks the other two (they must all be different).
    ['question1', 'question2', 'question3'].forEach(function (id) {
        var select = el(id);
        if (select) {
            select.addEventListener('change', function () {
                ['question1', 'question2', 'question3'].forEach(function (other) {
                    if (val(other) !== '' || other === id) { check(other); }
                });
            });
        }
    });

    // Name Extension: "Other" shows a text box.
    var ext = el('extension_choice');
    var other = el('other_extension');
    ext.addEventListener('change', function () {
        other.classList.toggle('hidden', ext.value !== 'Other');
        if (ext.value !== 'Other') { other.value = ''; }
    });

    // Age is read-only and calculated from the birthdate (server recalculates it).
    var birth = el('birthdate');
    birth.addEventListener('change', function () {
        var r = Validate.ageFrom(birth.value);
        el('age').value = (r && !r.future) ? String(r.age) : '';
        check('birthdate');
    });

    // Live username availability.
    var timer = null;
    var status = el('username-status');
    el('username').addEventListener('input', function () {
        clearTimeout(timer);
        var name = val('username');
        if (Validate.username(name, minUser, maxUser) !== null) { status.textContent = ''; return; }
        timer = setTimeout(function () {
            fetch('php/check_username?u=' + encodeURIComponent(name), { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    status.textContent = data.message;
                    status.className = 'hint ' + (data.available ? 'ok' : 'bad');
                })
                .catch(function () { status.textContent = ''; });
        }, 350);
    });

    form.addEventListener('submit', function (event) {
        var allOk = true;
        Object.keys(rules).forEach(function (id) {
            if (el(id) && !check(id)) { allOk = false; }
        });
        if (!allOk) {
            event.preventDefault();
            var firstBad = form.querySelector('.field-error:not(:empty)');
            if (firstBad) { firstBad.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
        }
    });
})();
