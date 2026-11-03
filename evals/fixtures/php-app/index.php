<?php
// DELIBERATELY VULNERABLE TEST FIXTURE - DO NOT DEPLOY.
require __DIR__ . '/config.php';

$action = $_GET['action'] ?? 'home';

if ($action === 'user') {
    $id = $_GET['id'];
    $mysqli = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    $res = $mysqli->query("SELECT name, email FROM users WHERE id = " . $id);
    $row = $res->fetch_assoc();
    echo "Name: " . $row['name'];
}

if ($action === 'page') {
    $page = $_GET['page'];
    include __DIR__ . '/pages/' . $page . '.php';
}

if ($action === 'greet') {
    $name = $_GET['name'];
    echo "<div>Hello " . $name . "</div>";
}

if ($action === 'convert') {
    $file = $_GET['file'];
    system("convert " . $file . " /tmp/out.png");
}

if ($action === 'restore') {
    $data = unserialize($_COOKIE['prefs']);
    echo "Theme: " . $data->theme;
}

if ($action === 'login') {
    $mysqli = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    $u = $_POST['user'];
    $p = md5($_POST['pass']);
    $res = $mysqli->query("SELECT id FROM users WHERE name = '$u' AND pw = '$p'");
    echo $res->num_rows > 0 ? 'ok' : 'no';
}
