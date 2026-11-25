<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

page_start('Privacy Notice');
?>
<section class="card privacy">
    <h1>Privacy Notice</h1>
    <p class="muted">Data Privacy Act of 2012 (Republic Act No. 10173)</p>

    <h2>1. What we collect, and why</h2>
    <p>We collect only what the library needs. Every field is listed here with its reason.</p>
    <div class="table-scroll">
    <table>
        <thead><tr><th>Information</th><th>Type under RA 10173</th><th>Why it is needed</th></tr></thead>
        <tbody>
            <tr><td>ID Number</td><td>Personal; a government or school-issued identifier is treated as sensitive</td><td>Uniquely identifies the borrower (primary key).</td></tr>
            <tr><td>Name (first, middle, family, extension)</td><td>Personal</td><td>Identifies the borrower on records and receipts.</td></tr>
            <tr><td>Birthdate and age</td><td>Sensitive (age and date of birth)</td><td>Confirms the borrower is at least 18 to register.</td></tr>
            <tr><td>Address (street, barangay, city, province, country, ZIP)</td><td>Personal</td><td>Lets the library contact the borrower about unreturned books.</td></tr>
            <tr><td>Email address</td><td>Personal</td><td>Sends one-time codes and security alerts.</td></tr>
            <tr><td>Username and password (stored as a hash)</td><td>Personal</td><td>Signs the borrower in. The password itself is never stored.</td></tr>
            <tr><td>Three security answers (stored as hashes)</td><td>Personal</td><td>Lets the borrower recover a forgotten password.</td></tr>
            <tr><td>Academic program, year level, student status</td><td>Personal; educational record</td><td>Decides who may borrow and for how long.</td></tr>
            <tr><td>Emergency contact number (encrypted, AES-256)</td><td>Personal</td><td>Reaches someone if the borrower cannot be contacted.</td></tr>
            <tr><td>Activity log: time, IP address, browser</td><td>Personal</td><td>Detects attacks on accounts and keeps accountability.</td></tr>
            <tr><td>Borrowing records</td><td>Personal</td><td>Tracks which book is with which borrower.</td></tr>
        </tbody>
    </table>
    </div>

    <h2>2. How we protect it</h2>
    <p>Passwords, security answers and one-time codes are stored as hashes and cannot be read back.
    The emergency contact number is encrypted. Every form is protected against forged requests,
    sessions expire after <?= IDLE_TIMEOUT_MINUTES ?> idle minutes, and repeated failed log-ins lock the account.
    Only administrators can view the security log.</p>

    <h2>3. Who can see it</h2>
    <p>Only library staff who need the information for their work. We do not sell or share your data
    with other parties unless the law requires it.</p>

    <h2>4. How long we keep it</h2>
    <p>Account and borrowing records are kept while your account is active and for up to one year after
    your last borrowing, then deleted. Security logs are kept for one year.</p>

    <h2>5. Your rights</h2>
    <p>You may ask to see, correct, block or delete your personal data, object to its processing, and
    complain to the National Privacy Commission.</p>

    <h2>6. Contact</h2>
    <p>Library Administrator, through the library office, or the school's Data Protection Officer.</p>

    <p><a href="register">Back to Registration</a> &nbsp;|&nbsp; <a href="index">Back to Home</a></p>
</section>
<?php page_end();
