<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

require_login();

// Get the logged-in user's role
$stmt = $pdo->prepare(
    'SELECT role FROM users WHERE id = ? LIMIT 1'
);
$stmt->execute([$_SESSION['user_id']]);
$role = $stmt->fetchColumn();

if (!$role) {
    $_SESSION = [];
    session_destroy();
    redirect('login');
    exit;
}

$_SESSION['role'] = $role;

$isStudent = ($role === 'student');
$isLibrarian = ($role === 'librarian');
$isAdmin = ($role === 'admin');

if (!$isStudent && !$isLibrarian && !$isAdmin) {
    http_response_code(403);
    exit('Access denied.');
}

$msg = '';
$msgType = 'success';

// Get students for librarian's borrowing form
$students = [];

if ($isLibrarian) {
    $students = $pdo->query("
        SELECT id, student_id, first_name, last_name
        FROM users
        WHERE role = 'student'
        ORDER BY last_name, first_name
    ")->fetchAll();
}

// Handle borrowing and returning
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();   // rejects and logs CSRF_REJECTED on a missing or wrong token

    try {
        // STUDENT BORROWING
        if (isset($_POST['borrow']) && $isStudent) {
            $bookId = (int) ($_POST['book_id'] ?? 0);

            if ($bookId <= 0) {
                throw new RuntimeException('Please select a book.');
            }

            $pdo->beginTransaction();

            // Rule: at most 3 books at a time, and not the same book twice.
            $stmt = $pdo->prepare(
                "SELECT COUNT(*) AS active, SUM(book_id = ?) AS same_book
                 FROM borrowing_transactions
                 WHERE user_id = ? AND status IN ('borrowed','overdue')"
            );
            $stmt->execute([$bookId, (int) $_SESSION['user_id']]);
            $loans = $stmt->fetch();
            if ((int) $loans['active'] >= 3) {
                throw new RuntimeException('You can borrow at most 3 books at a time. Please return a book first.');
            }
            if ((int) $loans['same_book'] > 0) {
                throw new RuntimeException('You already borrowed this book.');
            }

            $stmt = $pdo->prepare("
                SELECT available_copies
                FROM books
                WHERE id = ?
                FOR UPDATE
            ");
            $stmt->execute([$bookId]);
            $available = $stmt->fetchColumn();

            if ($available === false) {
                throw new RuntimeException('Book not found.');
            }

            if ((int) $available <= 0) {
                throw new RuntimeException('No available copies.');
            }

            $stmt = $pdo->prepare("
                UPDATE books
                SET available_copies = available_copies - 1
                WHERE id = ?
            ");
            $stmt->execute([$bookId]);

            $stmt = $pdo->prepare("
                INSERT INTO borrowing_transactions
                (user_id, book_id, borrowed_at, due_date, status)
                VALUES (?, ?, NOW(), DATE_ADD(CURDATE(), INTERVAL 14 DAY), 'borrowed')
            ");
            $stmt->execute([(int) $_SESSION['user_id'], $bookId]);

            log_event('BOOK_BORROWED', 'Book ID ' . $bookId, (int) $_SESSION['user_id']);

            $pdo->commit();

            $msg = 'Book borrowed successfully. Due in 14 days.';
        }

        // LIBRARIAN PROCESSES STUDENT BORROWING
        elseif (isset($_POST['process_borrow']) && $isLibrarian) {
            $studentId = (int) ($_POST['student_id'] ?? 0);
            $bookId = (int) ($_POST['book_id'] ?? 0);

            if ($studentId <= 0 || $bookId <= 0) {
                throw new RuntimeException(
                    'Please select a student and a book.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare("
                SELECT id
                FROM users
                WHERE id = ? AND role = 'student'
                FOR UPDATE
            ");
            $stmt->execute([$studentId]);

            if (!$stmt->fetchColumn()) {
                throw new RuntimeException('Invalid student selected.');
            }

            $stmt = $pdo->prepare("
                SELECT available_copies
                FROM books
                WHERE id = ?
                FOR UPDATE
            ");
            $stmt->execute([$bookId]);
            $available = $stmt->fetchColumn();

            if ($available === false) {
                throw new RuntimeException('Book not found.');
            }

            if ((int) $available <= 0) {
                throw new RuntimeException('No available copies.');
            }

            $stmt = $pdo->prepare("
                UPDATE books
                SET available_copies = available_copies - 1
                WHERE id = ?
            ");
            $stmt->execute([$bookId]);

            $stmt = $pdo->prepare("
                INSERT INTO borrowing_transactions
                (user_id, book_id, borrowed_at, due_date, status)
                VALUES (?, ?, NOW(), DATE_ADD(CURDATE(), INTERVAL 14 DAY), 'borrowed')
            ");
            $stmt->execute([$studentId, $bookId]);

            log_event('STUDENT_BOOK_BORROWED', 'Student ID: ' . $studentId . ', Book ID: ' . $bookId, (int) $_SESSION['user_id']);

            $pdo->commit();

            $msg = 'Student borrowing processed successfully.';
        }

        // LIBRARIAN PROCESSES BOOK RETURN
        elseif (isset($_POST['return_book']) && $isLibrarian) {
            $transactionId = (int) ($_POST['transaction_id'] ?? 0);

            if ($transactionId <= 0) {
                throw new RuntimeException('Invalid borrowing record.');
            }

            $pdo->beginTransaction();

            // Lock the borrowing transaction
            $stmt = $pdo->prepare("
                SELECT book_id, status
                FROM borrowing_transactions
                WHERE id = ?
                FOR UPDATE
            ");
            $stmt->execute([$transactionId]);
            $transaction = $stmt->fetch();

            if (!$transaction) {
                throw new RuntimeException('Borrowing record not found.');
            }

            if (!in_array(
                $transaction['status'],
                ['borrowed', 'overdue'],
                true
            )) {
                throw new RuntimeException(
                    'This book has already been returned.'
                );
            }

            // Lock the book and check its copy count
            $stmt = $pdo->prepare("
                SELECT total_copies, available_copies
                FROM books
                WHERE id = ?
                FOR UPDATE
            ");
            $stmt->execute([$transaction['book_id']]);
            $book = $stmt->fetch();

            if (!$book) {
                throw new RuntimeException('Book record not found.');
            }

            if ((int) $book['available_copies'] >= (int) $book['total_copies']) {
                throw new RuntimeException(
                    'The available copy count has already reached its limit.'
                );
            }

            // Mark transaction as returned
            $stmt = $pdo->prepare("
                UPDATE borrowing_transactions
                SET status = 'returned',
                    returned_at = NOW()
                WHERE id = ?
            ");
            $stmt->execute([$transactionId]);

            // Restore one available copy
            $stmt = $pdo->prepare("
                UPDATE books
                SET available_copies = available_copies + 1
                WHERE id = ?
            ");
            $stmt->execute([$transaction['book_id']]);

            log_event('BOOK_RETURNED', 'Transaction ID ' . $transactionId, (int) $_SESSION['user_id']);

            $pdo->commit();

            $msg = 'Book return processed successfully.';
        } else {
            throw new RuntimeException(
                'You are not allowed to perform this action.'
            );
        }

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log('Borrowing process error: ' . $e->getMessage());

        $msg = $e instanceof RuntimeException
            ? $e->getMessage()
            : 'Something went wrong. Please try again.';

        $msgType = 'error';
    }
}

// Get available books
$books = $pdo->query("
    SELECT id, title, available_copies
    FROM books
    WHERE available_copies > 0
    ORDER BY title
")->fetchAll();

// Search borrowing records
$search = trim($_GET['search'] ?? '');

$searchSql = '';
$params = [];

if ($isStudent) {
    $searchSql = 'WHERE t.user_id = ?';
    $params[] = (int) $_SESSION['user_id'];
}

if ($search !== '') {
    $condition = "
        (b.title LIKE ?
         OR u.username LIKE ?
         OR u.student_id LIKE ?
         OR u.first_name LIKE ?
         OR u.last_name LIKE ?)
    ";

    $term = '%' . $search . '%';

    if ($searchSql !== '') {
        $searchSql .= ' AND ' . $condition;
    } else {
        $searchSql = 'WHERE ' . $condition;
    }

    array_push($params, $term, $term, $term, $term, $term);
}

// Get borrowing records
$sql = "
    SELECT
        t.*,
        b.title,
        u.username,
        u.student_id,
        u.first_name,
        u.last_name,
        CASE
            WHEN t.status = 'borrowed'
                 AND t.due_date < CURDATE()
            THEN 'overdue'
            ELSE t.status
        END AS display_status
    FROM borrowing_transactions t
    JOIN books b ON b.id = t.book_id
    JOIN users u ON u.id = t.user_id
    $searchSql
    ORDER BY t.id DESC
";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$totalRecords = count($rows);

page_start('Borrowing Records');
?>



<div class="borrow-page">

    <section class="borrow-header">
        <h1>Borrowing Records</h1>
        <p>
            Manage book borrowing transactions, monitor due dates,
            and keep track of returned books.
        </p>
    </section>

    <?php if ($msg): ?>
        <div class="borrow-notice <?= e($msgType) ?>">
            <?= e($msg) ?>
        </div>
    <?php endif; ?>

    <?php if ($isStudent): ?>
        <section class="borrow-panel">
            <h2>Borrow a Book</h2>
            <p>Select an available book from the library collection.</p>

            <?php if ($books): ?>
                <form method="post">
                    <?= csrf_field() ?>

                    <label for="book_id">Select Book</label>

                    <select name="book_id" id="book_id" required>
                        <option value="">Choose a book</option>

                        <?php foreach ($books as $book): ?>
                            <option value="<?= (int) $book['id'] ?>">
                                <?= e($book['title']) ?>
                                (<?= (int) $book['available_copies'] ?> available)
                            </option>
                        <?php endforeach; ?>
                    </select>

                    <button
                        type="submit"
                        name="borrow"
                        value="1"
                        class="borrow-submit"
                    >
                        Borrow Book
                    </button>
                </form>
            <?php else: ?>
                <div class="borrow-empty">
                    <strong>No available books.</strong>
                    Please check again later.
                </div>
            <?php endif; ?>
        </section>

    <?php elseif ($isLibrarian): ?>
        <section class="borrow-panel">
            <h2>Process Student Borrowing</h2>
            <p>Select the student and book to record a borrowing transaction.</p>

            <?php if ($books && $students): ?>
                <form method="post">
                    <?= csrf_field() ?>

                    <div class="borrow-form-grid">
                        <div>
                            <label for="student_id">Select Student</label>

                            <select name="student_id" id="student_id" required>
                                <option value="">Choose a student</option>

                                <?php foreach ($students as $student): ?>
                                    <option value="<?= (int) $student['id'] ?>">
                                        <?= e(
                                            $student['first_name'] . ' ' .
                                            $student['last_name']
                                        ) ?>
                                        (<?= e($student['student_id']) ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label for="book_id">Select Book</label>

                            <select name="book_id" id="book_id" required>
                                <option value="">Choose a book</option>

                                <?php foreach ($books as $book): ?>
                                    <option value="<?= (int) $book['id'] ?>">
                                        <?= e($book['title']) ?>
                                        (<?= (int) $book['available_copies'] ?> available)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <button
                        type="submit"
                        name="process_borrow"
                        value="1"
                        class="borrow-submit"
                    >
                        Process Borrowing
                    </button>
                </form>
            <?php else: ?>
                <div class="borrow-empty">
                    <strong>Unable to process borrowing.</strong>
                    Make sure there are registered students and available books.
                </div>
            <?php endif; ?>
        </section>
    <?php endif; ?>

    <section class="borrow-panel">
        <div class="borrow-toolbar">
            <h2>
                <?= $isStudent ? 'My Borrowing History' : 'All Borrowing Records' ?>
            </h2>

            <form method="get" class="borrow-search">
                <input
                    type="search"
                    name="search"
                    value="<?= e($search) ?>"
                    placeholder="Search borrowing records..."
                    aria-label="Search borrowing records"
                >
                <button type="submit">Search</button>
            </form>
        </div>

        <p class="borrow-count">
            <?= $totalRecords ?> record(s) found
        </p>

        <?php if ($rows): ?>
            <div class="borrow-table-wrap">
                <table class="borrow-table">
                    <thead>
                        <tr>
                            <th>Book</th>

                            <?php if (!$isStudent): ?>
                                <th>Borrower</th>
                            <?php endif; ?>

                            <th>Borrowed Date</th>
                            <th>Due Date</th>
                            <th>Returned Date</th>
                            <th>Status</th>

                            <?php if ($isLibrarian): ?>
                                <th>Action</th>
                            <?php endif; ?>
                        </tr>
                    </thead>

                    <tbody>
                        <?php foreach ($rows as $row): ?>
                            <?php
                                $status = $row['display_status'];
                            ?>

                            <tr>
                                <td>
                                    <strong><?= e($row['title']) ?></strong>
                                </td>

                                <?php if (!$isStudent): ?>
                                    <td>
                                        <?= e(
                                            $row['first_name'] . ' ' .
                                            $row['last_name']
                                        ) ?>
                                        <br>
                                        <small>
                                            <?= e($row['student_id']) ?>
                                        </small>
                                    </td>
                                <?php endif; ?>

                                <td><?= e($row['borrowed_at']) ?></td>
                                <td><?= e($row['due_date']) ?></td>
                                <td><?= e($row['returned_at'] ?? '—') ?></td>

                                <td>
                                    <span class="status-badge <?= e($status) ?>">
                                        <?= e(ucfirst($status)) ?>
                                    </span>
                                </td>

                                <?php if ($isLibrarian): ?>
                                    <td>
                                        <?php if (
                                            in_array(
                                                $row['status'],
                                                ['borrowed', 'overdue'],
                                                true
                                            )
                                        ): ?>
                                            <form method="post">
                                                <?= csrf_field() ?>

                                                <input
                                                    type="hidden"
                                                    name="transaction_id"
                                                    value="<?= (int) $row['id'] ?>"
                                                >

                                                <button
                                                    type="submit"
                                                    name="return_book"
                                                    value="1"
                                                    class="return-button"
                                                >
                                                    Return Book
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <span class="returned-label">
                                                Already returned
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                <?php endif; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="borrow-empty">
                <strong>No borrowing records found.</strong>
                <?php if ($search !== ''): ?>
                    Try a different search term.
                <?php else: ?>
                    Borrowing transactions will appear here.
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </section>

</div>

<?php page_end(); ?>
