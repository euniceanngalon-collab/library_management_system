<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_login();

$stmt = $pdo->prepare(
    'SELECT id, first_name, role
     FROM users
     WHERE id = ?
     LIMIT 1'
);
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite'] ?? 'Strict'
            ]
        );
    }

    session_destroy();

    redirect('login');
    exit;
}

$_SESSION['role'] = $user['role'];

$firstName = $user['first_name'];
$role = $user['role'];

$roleLabel = match ($role) {
    'admin' => 'Administrator',
    'librarian' => 'Librarian',
    default => 'Student'
};

page_start('Dashboard');

/* Each role sees only the cards for what it is allowed to do. */
$intro = match ($role) {
    'admin'     => 'Monitor system security and manage user accounts.',
    'librarian' => 'Manage the book collection and process borrowing and returns.',
    default     => 'Browse books, borrow them and check your borrowing history.',
};
?>
<div class="dashboard">

    <section class="dashboard-header">
        <h1>Welcome, <?= e($firstName) ?>!</h1>
        <p><?= e($intro) ?></p>
        <span class="role-badge"><?= e($roleLabel) ?> Account</span>
    </section>

    <h2 class="dashboard-section-title">Quick Access</h2>

    <section class="dashboard-grid">

        <a href="books" class="dashboard-card">
            <div class="dashboard-icon" aria-hidden="true">📚</div>
            <?php if ($role === 'librarian'): ?>
                <h3>Manage Books</h3>
                <p>Add, edit and remove books in the collection.</p>
                <span class="card-link">Manage Books →</span>
            <?php else: ?>
                <h3>Browse Books</h3>
                <p>Explore the available books in the library collection.</p>
                <span class="card-link">View Books →</span>
            <?php endif; ?>
        </a>

        <?php if ($role === 'student'): ?>
            <a href="borrowings" class="dashboard-card">
                <div class="dashboard-icon" aria-hidden="true">📖</div>
                <h3>Borrow and My Records</h3>
                <p>Borrow a book and see your due dates and returns.</p>
                <span class="card-link">Open →</span>
            </a>
        <?php elseif ($role === 'librarian'): ?>
            <a href="borrowings" class="dashboard-card">
                <div class="dashboard-icon" aria-hidden="true">🔄</div>
                <h3>Borrow and Return Desk</h3>
                <p>Process student borrowing and book returns.</p>
                <span class="card-link">Open Desk →</span>
            </a>
        <?php else: ?>
            <a href="borrowings" class="dashboard-card">
                <div class="dashboard-icon" aria-hidden="true">📖</div>
                <h3>Borrowing Records</h3>
                <p>View all borrowing records (read-only).</p>
                <span class="card-link">View Records →</span>
            </a>
        <?php endif; ?>

        <?php if ($role === 'admin'): ?>
            <a href="admin_users" class="dashboard-card">
                <div class="dashboard-icon" aria-hidden="true">👥</div>
                <h3>Manage Users</h3>
                <p>See every account and control student access.</p>
                <span class="card-link">Open Users →</span>
            </a>

            <a href="admin" class="dashboard-card">
                <div class="dashboard-icon" aria-hidden="true">📊</div>
                <h3>Security Monitoring</h3>
                <p>Review log-in attacks, alerts and security flags.</p>
                <span class="card-link">Open Monitoring →</span>
            </a>
        <?php endif; ?>

    </section>

    <div class="dashboard-footer">Library Management and Borrowing System</div>
</div>

<?php page_end(); ?>
