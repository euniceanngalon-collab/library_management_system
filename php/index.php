<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

page_start('Home');
?>



<section class="home-hero">
    <h1>Library Management and Borrowing System</h1>

    <p>
        Your convenient way to explore library books and manage borrowing
        transactions. Create your student account to get started.
    </p>

    <div class="home-actions">
        <a class="home-primary" href="register">
            Create Student Account
        </a>

        <a class="home-secondary" href="login">
            Sign In
        </a>

        <a class="home-secondary" href="books">
            Browse Books
        </a>
    </div>
</section>

<h2 class="home-section-title">What You Can Do</h2>

<section class="home-features">
    <article class="home-feature">
        <div class="home-feature-icon" aria-hidden="true">📚</div>
        <h3>Explore Books</h3>
        <p>
            Browse the available books and check their current availability
            before borrowing.
        </p>
    </article>

    <article class="home-feature">
        <div class="home-feature-icon" aria-hidden="true">🎓</div>
        <h3>Student Account</h3>
        <p>
            Register your student account to access the system's
            borrowing services.
        </p>
    </article>

    <article class="home-feature">
        <div class="home-feature-icon" aria-hidden="true">📋</div>
        <h3>Borrowing Records</h3>
        <p>
            After signing in, view your borrowing records and monitor
            your book return dates.
        </p>
    </article>
</section>

<div class="home-footer-note">
    Please sign in to access your account and borrowing records.
    Your account information should be kept private and secure.
</div>

<?php page_end(); ?>
