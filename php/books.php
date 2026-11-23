<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

require_login();

$role = current_user_role();
if ($role === null) {
    destroy_session();
    redirect('login');
}
$_SESSION['role'] = $role;

/*
| ROLE RULES for this page
|   student   : search and view only
|   librarian : add, edit and delete books
|   admin     : search and view only (the admin does not run the collection)
| The server checks the role again on every POST, so hiding a button is never the only protection.
*/
$canManageBooks = ($role === 'librarian');

$msg = '';
$msgType = 'success';

/* Returns an error message, or null when title, author, isbn and copies are valid. */
function validate_book_input(string $title, string $author, string $isbn, string $copies): ?string
{
    if ($title === '' || $author === '') {
        return 'Please enter both the book title and author.';
    }
    if (mb_strlen($title) > 200) {
        return 'Book title must be 200 characters or fewer.';
    }
    if (mb_strlen($author) > 150) {
        return 'Author must be 150 characters or fewer.';
    }
    if ($isbn !== '' && !preg_match('/^[0-9-]{10,17}$/', $isbn)) {
        return 'ISBN may contain digits and hyphens only (10 to 17 characters).';
    }
    if (!ctype_digit($copies) || (int)$copies < 1 || (int)$copies > 9999) {
        return 'Please enter a valid number of copies from 1 to 9999.';
    }
    return null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();   // rejects and logs CSRF_REJECTED when the token is missing or wrong

    if (!$canManageBooks) {
        log_event('ACCESS_DENIED', 'Non-librarian tried to change books.', (int)$_SESSION['user_id']);
        http_response_code(403);
        exit('Access denied.');
    }

    $action = (string)($_POST['action'] ?? '');
    $title  = trim((string)($_POST['title'] ?? ''));
    $author = trim((string)($_POST['author'] ?? ''));
    $isbn   = trim((string)($_POST['isbn'] ?? ''));
    $copies = trim((string)($_POST['copies'] ?? ''));

    try {
        if ($action === 'add') {
            $err = validate_book_input($title, $author, $isbn, $copies);
            if ($err !== null) {
                throw new RuntimeException($err);
            }
            $n = (int)$copies;
            $pdo->prepare(
                'INSERT INTO books (title, author, isbn, total_copies, available_copies) VALUES (?, ?, ?, ?, ?)'
            )->execute([$title, $author, $isbn === '' ? null : $isbn, $n, $n]);

            log_event('BOOK_ADDED', 'Added book: ' . $title, (int)$_SESSION['user_id']);
            $msg = 'Book added successfully.';

        } elseif ($action === 'update') {
            $bookId = (int)($_POST['book_id'] ?? 0);
            $err = validate_book_input($title, $author, $isbn, $copies);
            if ($bookId <= 0) {
                throw new RuntimeException('Invalid book.');
            }
            if ($err !== null) {
                throw new RuntimeException($err);
            }

            $pdo->beginTransaction();
            $stmt = $pdo->prepare('SELECT total_copies, available_copies FROM books WHERE id = ? FOR UPDATE');
            $stmt->execute([$bookId]);
            $book = $stmt->fetch();
            if (!$book) {
                throw new RuntimeException('Book not found.');
            }

            $onLoan   = (int)$book['total_copies'] - (int)$book['available_copies'];
            $newTotal = (int)$copies;
            if ($newTotal < $onLoan) {
                throw new RuntimeException("Total copies cannot be lower than the $onLoan copy/copies currently borrowed.");
            }

            $pdo->prepare(
                'UPDATE books SET title = ?, author = ?, isbn = ?, total_copies = ?, available_copies = ? WHERE id = ?'
            )->execute([$title, $author, $isbn === '' ? null : $isbn, $newTotal, $newTotal - $onLoan, $bookId]);
            $pdo->commit();

            log_event('BOOK_UPDATED', 'Book ID ' . $bookId, (int)$_SESSION['user_id']);
            $msg = 'Book updated successfully.';

        } elseif ($action === 'delete') {
            $bookId = (int)($_POST['book_id'] ?? 0);
            if ($bookId <= 0) {
                throw new RuntimeException('Invalid book.');
            }

            $stmt = $pdo->prepare('SELECT COUNT(*) FROM borrowing_transactions WHERE book_id = ?');
            $stmt->execute([$bookId]);
            if ((int)$stmt->fetchColumn() > 0) {
                throw new RuntimeException('This book has borrowing records and cannot be deleted.');
            }

            $pdo->prepare('DELETE FROM books WHERE id = ?')->execute([$bookId]);
            log_event('BOOK_DELETED', 'Book ID ' . $bookId, (int)$_SESSION['user_id']);
            $msg = 'Book deleted.';

        } else {
            throw new RuntimeException('Unknown action.');
        }
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        if ($e instanceof RuntimeException) {
            $msg = $e->getMessage();
        } else {
            error_log('Book error: ' . $e->getMessage());
            $msg = 'Unable to save the change. Please try again.';
        }
        $msgType = 'error';
    }
}

// Search books by title, author or ISBN
$search = trim((string)($_GET['search'] ?? ''));

if ($search !== '') {
    $stmt = $pdo->prepare(
        'SELECT * FROM books WHERE title LIKE ? OR author LIKE ? OR isbn LIKE ? ORDER BY title'
    );
    $term = '%' . $search . '%';
    $stmt->execute([$term, $term, $term]);
    $books = $stmt->fetchAll();
} else {
    $books = $pdo->query('SELECT * FROM books ORDER BY title')->fetchAll();
}

$totalBooks = count($books);

page_start('Books');
?>
<div class="books-page">

    <section class="books-header">
        <h1>Library Books</h1>
        <p>
            <?php if ($canManageBooks): ?>
                Add, edit and remove books in the collection.
            <?php else: ?>
                Explore the library collection and check which books are currently available for borrowing.
            <?php endif; ?>
        </p>
    </section>

    <?php if ($msg): ?>
        <div class="books-notice <?= e($msgType) ?>"><?= e($msg) ?></div>
    <?php endif; ?>

    <?php if ($canManageBooks): ?>
        <section class="books-panel">
            <h2>Add New Book</h2>
            <p class="muted-small">Enter the book details to add a new item to the collection.</p>

            <form method="post">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="add">

                <div class="books-form-grid">
                    <div>
                        <label for="title">Book Title<span class="req">*</span></label>
                        <input type="text" id="title" name="title" maxlength="200" placeholder="Enter book title" required>
                    </div>
                    <div>
                        <label for="author">Author<span class="req">*</span></label>
                        <input type="text" id="author" name="author" maxlength="150" placeholder="Enter author's name" required>
                    </div>
                    <div>
                        <label for="isbn">ISBN <span class="opt">optional</span></label>
                        <input type="text" id="isbn" name="isbn" maxlength="17" placeholder="978-0-00-000000-0">
                    </div>
                    <div>
                        <label for="copies">Number of Copies<span class="req">*</span></label>
                        <input type="number" id="copies" name="copies" min="1" max="9999" value="1" required>
                    </div>
                </div>

                <button type="submit" class="books-submit">+ Add Book</button>
            </form>
        </section>
    <?php endif; ?>

    <section class="books-panel">
        <div class="books-toolbar">
            <h2>Book Collection</h2>

            <form method="get" class="books-search">
                <input type="search" name="search" placeholder="Search title, author or ISBN..."
                       value="<?= e($search) ?>" aria-label="Search books">
                <button type="submit">Search</button>
            </form>
        </div>

        <p class="books-count"><?= $totalBooks ?> book record(s) found</p>

        <?php if ($books): ?>
            <div class="books-table-wrap">
                <table class="books-table">
                    <thead>
                        <tr>
                            <th>Cover</th>
                            <th>Book Title</th>
                            <th>Author</th>
                            <th>ISBN</th>
                            <th>Total Copies</th>
                            <th>Available</th>
                            <th>Status</th>
                            <?php if ($canManageBooks): ?><th>Manage</th><?php endif; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($books as $book): ?>
                            <?php $available = (int)$book['available_copies']; ?>
                            <?php
                                $isbnDigits = preg_replace('/[^0-9Xx]/', '', (string)($book['isbn'] ?? ''));
                                $coverUrl = $isbnDigits !== '' ? 'https://covers.openlibrary.org/b/isbn/' . rawurlencode($isbnDigits) . '-M.jpg' : null;
                            ?>
                            <tr>
                                <td>
                                    <?php if ($coverUrl): ?>
                                        <img
                                            class="book-cover"
                                            src="<?= e($coverUrl) ?>"
                                            alt="Cover of <?= e($book['title']) ?>"
                                            loading="lazy"
                                            onerror="this.onerror=null;this.replaceWith(Object.assign(document.createElement('div'),{className:'book-cover book-cover-placeholder',textContent:<?= json_encode(mb_substr($book['title'], 0, 1)) ?>}));"
                                        >
                                    <?php else: ?>
                                        <div class="book-cover book-cover-placeholder"><?= e(mb_substr($book['title'], 0, 1)) ?></div>
                                    <?php endif; ?>
                                </td>
                                <td><strong><?= e($book['title']) ?></strong></td>
                                <td><?= e($book['author']) ?></td>
                                <td><?= e($book['isbn'] ?? '—') ?></td>
                                <td><?= (int)$book['total_copies'] ?></td>
                                <td><?= $available ?></td>
                                <td>
                                    <?php if ($available > 0): ?>
                                        <span class="availability available">Available</span>
                                    <?php else: ?>
                                        <span class="availability unavailable">Unavailable</span>
                                    <?php endif; ?>
                                </td>

                                <?php if ($canManageBooks): ?>
                                    <td>
                                        <details>
                                            <summary>Edit</summary>
                                            <form method="post">
                                                <?= csrf_field() ?>
                                                <input type="hidden" name="action" value="update">
                                                <input type="hidden" name="book_id" value="<?= (int)$book['id'] ?>">

                                                <label for="t<?= (int)$book['id'] ?>">Title</label>
                                                <input type="text" id="t<?= (int)$book['id'] ?>" name="title" maxlength="200"
                                                       value="<?= e($book['title']) ?>" required>

                                                <label for="a<?= (int)$book['id'] ?>">Author</label>
                                                <input type="text" id="a<?= (int)$book['id'] ?>" name="author" maxlength="150"
                                                       value="<?= e($book['author']) ?>" required>

                                                <label for="i<?= (int)$book['id'] ?>">ISBN</label>
                                                <input type="text" id="i<?= (int)$book['id'] ?>" name="isbn" maxlength="17"
                                                       value="<?= e($book['isbn'] ?? '') ?>">

                                                <label for="c<?= (int)$book['id'] ?>">Total copies</label>
                                                <input type="number" id="c<?= (int)$book['id'] ?>" name="copies" min="1" max="9999"
                                                       value="<?= (int)$book['total_copies'] ?>" required>

                                                <button type="submit" class="books-submit">Save</button>
                                            </form>

                                            <form method="post">
                                                <?= csrf_field() ?>
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="book_id" value="<?= (int)$book['id'] ?>">
                                                <button type="submit" class="return-button">Delete</button>
                                            </form>
                                        </details>
                                    </td>
                                <?php endif; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="books-empty">
                <strong>No books found.</strong>
                <?= $search !== '' ? 'Try another title, author or ISBN.' : 'There are currently no books in the collection.' ?>
            </div>
        <?php endif; ?>
    </section>

</div>

<?php page_end(); ?>