/*
 * Browser-side validation. It only gives quick feedback - the SERVER
 * (php/validation.php) repeats every rule and is the real protection.
 * Messages are the same as on the server.
 */
var Validate = (function () {
    'use strict';

    function name(v, label, required, maxLen) {
        if (v === '') { return required ? label + ' is required.' : null; }
        if (/\d/.test(v)) { return 'Numbers are not allowed in ' + label + '.'; }
        if (/[^A-Za-z\u00C0-\u024F ]/.test(v)) { return 'Special characters are not allowed in ' + label + '.'; }
        if (v.indexOf('  ') !== -1) { return 'Double space is not allowed.'; }
        if (v !== v.trim()) { return label + ' must not start or end with a space.'; }
        if (/([A-Za-z\u00C0-\u024F])\1\1/i.test(v)) { return 'Three consecutive identical letters are not allowed.'; }
        if (v.length < 2) { return label + ' must be at least 2 characters.'; }
        if (v.length > maxLen) { return label + ' must not exceed ' + maxLen + ' characters.'; }
        var letters = v.replace(/[^A-Za-z\u00C0-\u024F]/g, '');
        if (letters.length >= 2 && letters === letters.toUpperCase()) { return 'Do not use all capital letters.'; }
        var words = v.split(' ');
        for (var i = 0; i < words.length; i++) {
            var first = words[i].charAt(0), rest = words[i].slice(1);
            if (first !== first.toUpperCase()) { return 'First letter of your name must be capital.'; }
            if (rest !== rest.toLowerCase()) { return 'Only the first letter of each word may be capital.'; }
        }
        return null;
    }

    function idNumber(v) {
        return /^\d{4}-\d{4}$/.test(v) ? null : 'ID Number must follow the format xxxx-xxxx.';
    }

    function email(v) {
        if (v === '' || v.length > 100 || /\s/.test(v) || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) {
            return 'Please enter a valid email address.';
        }
        return null;
    }

    function username(v, min, max) {
        if (!/^[A-Za-z][A-Za-z0-9]*$/.test(v)) { return 'Username must start with a letter and contain letters and digits only.'; }
        if (v.length < min || v.length > max) { return 'Username must be ' + min + '-' + max + ' characters.'; }
        return null;
    }

    function strength(pw, min) {
        var types = 0;
        types += /[a-z]/.test(pw) ? 1 : 0;
        types += /[A-Z]/.test(pw) ? 1 : 0;
        types += /\d/.test(pw) ? 1 : 0;
        types += /[^A-Za-z0-9]/.test(pw) ? 1 : 0;
        if (pw.length < min || types < 3) { return 'Weak'; }
        if (pw.length >= min + 2 && types === 4) { return 'Strong'; }
        return 'Medium';
    }

    function password(pw, min, max) {
        if (pw.length < min || pw.length > max) { return 'Password must be ' + min + '-' + max + ' characters.'; }
        if (strength(pw, min) === 'Weak') { return 'Password is too weak. Use upper and lower case letters, digits and symbols.'; }
        return null;
    }

    function ageFrom(dateStr) {
        var b = new Date(dateStr + 'T00:00:00');
        if (isNaN(b.getTime())) { return null; }
        var t = new Date();
        var age = t.getFullYear() - b.getFullYear();
        var m = t.getMonth() - b.getMonth();
        if (m < 0 || (m === 0 && t.getDate() < b.getDate())) { age--; }
        return { age: age, future: b > t };
    }

    function birthdate(v) {
        if (v === '') { return 'Please enter a valid birthdate.'; }
        var r = ageFrom(v);
        if (!r) { return 'Please enter a valid birthdate.'; }
        if (r.future) { return 'Birthdate cannot be in the future.'; }
        if (r.age < 18) { return 'You must be at least 18 years old to register.'; }
        return null;
    }

    function place(v, label) {
        if (!/^[A-Za-z\u00C0-\u024F]+( [A-Za-z\u00C0-\u024F]+)*$/.test(v)) { return label + ' must contain letters and single spaces only.'; }
        if (!/^[A-Z][a-z\u00DF-\u024F]*( [A-Z][a-z\u00DF-\u024F]*)*$/.test(v)) { return label + ' must be in Title Case (for example: San Isidro).'; }
        if (v.length < 2 || v.length > 50) { return label + ' must be 2-50 characters.'; }
        return null;
    }

    function street(v) {
        if (!/^[A-Za-z0-9]+( [A-Za-z0-9]+)*$/.test(v)) { return 'Purok / Street may contain letters, digits and single spaces only.'; }
        if (v.length < 3 || v.length > 50) { return 'Purok / Street must be 3-50 characters.'; }
        return null;
    }

    function zip(v) { return /^\d{4}$/.test(v) ? null : 'ZIP Code must be exactly 4 digits.'; }

    function answer(v, label) {
        if (!/^[A-Za-z\u00C0-\u024F]+( [A-Za-z\u00C0-\u024F]+)*$/.test(v)) { return label + ' may contain letters and single spaces only.'; }
        if (v.length < 2 || v.length > 50) { return label + ' must be 2-50 characters.'; }
        return null;
    }

    function contact(v) { return /^09\d{9}$/.test(v) ? null : 'Contact number must be 11 digits and start with 09.'; }

    function interests(v) {
        if (v === '') { return null; }
        if (v.length > 100 || !/^[A-Za-z, ]+$/.test(v)) { return 'Subjects of interest may contain letters, commas and spaces only (max 100 characters).'; }
        return null;
    }

    return { name: name, idNumber: idNumber, email: email, username: username, strength: strength,
             password: password, ageFrom: ageFrom, birthdate: birthdate, place: place, street: street,
             zip: zip, answer: answer, contact: contact, interests: interests };
})();
