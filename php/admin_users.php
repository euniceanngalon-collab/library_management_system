<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

require_login();

/* ADMIN ONLY. Same guard as the monitoring dashboard: refuse and log everyone else. */
if (current_user_role() !== 'admin') {
    log_event('ADMIN_ACCESS_DENIED', 'Non-admin opened the user list.', (int)$_SESSION['user_id']);
    http_response_code(403);
    page_start('Access denied');
    echo '<section class="card"><h1>Access denied</h1><p>This page is for administrators only.</p></section>';
    page_end();
    exit;
}

$msg = '';
$msgType = 'success';

/*
| The admin can switch a STUDENT between "Currently Enrolled" and "On Leave".
| An account that is not "Currently Enrolled" cannot log in (see login.php).
| Admin and librarian accounts cannot be changed here.
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    $targetId  = (int)($_POST['user_id'] ?? 0);
    $newStatus = (string)($_POST['status'] ?? '');

    try {
        if ($targetId <= 0 || !in_array($newStatus, STUDENT_STATUS_LIST, true)) {
            throw new RuntimeException('Invalid request.');   // the dropdown value is checked on the server
        }

        $stmt = $pdo->prepare("UPDATE users SET student_status = ? WHERE id = ? AND role = 'student'");
        $stmt->execute([$newStatus, $targetId]);

        if ($stmt->rowCount() === 0) {
            throw new RuntimeException('No change was made. The account may already have that status.');
        }

        log_event('USER_STATUS_CHANGED', 'User ID ' . $targetId . ' set to ' . $newStatus, (int)$_SESSION['user_id']);
        $msg = 'Student status updated.';
    } catch (RuntimeException $e) {
        $msg = $e->getMessage();
        $msgType = 'error';
    } catch (Throwable $e) {
        error_log('User status error: ' . $e->getMessage());
        $msg = 'Unable to update the account. Please try again.';
        $msgType = 'error';
    }
}

/* Totals per role (read-only overview). */
$totals = ['student' => 0, 'librarian' => 0, 'admin' => 0];
foreach ($pdo->query('SELECT role, COUNT(*) AS c FROM users GROUP BY role')->fetchAll() as $r) {
    $totals[(string)$r['role']] = (int)$r['c'];
}

/* Search and role filter. Every value is a bound parameter (protection 1). */
$search = trim((string)($_GET['search'] ?? ''));
$roleFilter = (string)($_GET['role'] ?? '');
if (!in_array($roleFilter, ['student', 'librarian', 'admin'], true)) {
    $roleFilter = '';
}

$where = [];
$params = [];
if ($roleFilter !== '') {
    $where[] = 'role = ?';
    $params[] = $roleFilter;
}
if ($search !== '') {
    $where[] = '(student_id LIKE ? OR username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)';
    $term = '%' . $search . '%';
    array_push($params, $term, $term, $term, $term, $term);
}

$sql = 'SELECT id, student_id, first_name, last_name, username, email, role, student_status, email_verified_at
        FROM users' . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . '
        ORDER BY role, last_name, first_name LIMIT 200';
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$users = $stmt->fetchAll();

page_start('Manage Users');
?>
<div class="books-page">

    <section class="books-header">
        <h1>Manage Users</h1>
        <p>
            Students: <?= $totals['student'] ?> &nbsp;|&nbsp;
            Librarians: <?= $totals['librarian'] ?> &nbsp;|&nbsp;
            Admins: <?= $totals['admin'] ?>
        </p>
        <p class="muted-small">
            Librarian and admin accounts are created from the command line
            (<code>php/create_admin.php</code>), never through the public registration form.
        </p>
    </section>

    <?php if ($msg): ?>
        <div class="books-notice <?= e($msgType) ?>"><?= e($msg) ?></div>
    <?php endif; ?>

    <section class="books-panel">
        <div class="books-toolbar">
            <h2>All Accounts</h2>
            <form method="get" class="books-search">
                <select name="role" aria-label="Filter by role">
                    <option value="">All roles</option>
                    <?php foreach (['student', 'librarian', 'admin'] as $r): ?>
                        <option value="<?= e($r) ?>" <?= $roleFilter === $r ? 'selected' : '' ?>><?= e(ucfirst($r)) ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="search" name="search" value="<?= e($search) ?>"
                       placeholder="Search ID, name, username or email..." aria-label="Search users">
                <button type="submit">Search</button>
            </form>
        </div>

        <p class="books-count"><?= count($users) ?> account(s) shown</p>

        <?php if ($users): ?>
            <div class="books-table-wrap">
                <table class="books-table">
                    <thead>
                        <tr>
                            <th>ID Number</th>
                            <th>Name</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Verified</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $u): ?>
                            <tr>
                                <td><?= e($u['student_id']) ?></td>
                                <td><?= e($u['first_name'] . ' ' . $u['last_name']) ?></td>
                                <td><?= e($u['username']) ?></td>
                                <td><?= e($u['email']) ?></td>
                                <td><?= e(ucfirst((string)$u['role'])) ?></td>
                                <td><?= $u['email_verified_at'] ? 'Yes' : 'No' ?></td>
                                <td>
                                    <?php if ($u['role'] === 'student'): ?>
                                        <form method="post" class="inline-form">
                                            <?= csrf_field() ?>
                                            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                            <select name="status" aria-label="Status of <?= e($u['username']) ?>">
                                                <?php foreach (STUDENT_STATUS_LIST as $st): ?>
                                                    <option value="<?= e($st) ?>" <?= $u['student_status'] === $st ? 'selected' : '' ?>><?= e($st) ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                            <button type="submit" class="btn btn-secondary">Save</button>
                                        </form>
                                    <?php else: ?>
                                        <span class="muted">Staff account</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="books-empty"><strong>No accounts found.</strong></div>
        <?php endif; ?>
    </section>

</div>
<?php page_end(); ?>
