<?php
// Safe-but-suspicious code. A good reviewer reports NOTHING here.
require __DIR__ . '/config.php';

function safe_user(mysqli $mysqli, string $id): ?array {
    // Prepared statement with a bound parameter.
    $stmt = $mysqli->prepare('SELECT name, email FROM users WHERE id = ?');
    $stmt->bind_param('i', $id);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function safe_greet(string $name): string {
    // Output encoded for HTML context.
    return '<div>Hello ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</div>';
}

function safe_page(string $page): string {
    // Allowlist mapping; user input never reaches the filesystem path.
    $pages = ['home' => 'home.php', 'about' => 'about.php'];
    return $pages[$page] ?? 'home.php';
}
