<?php
// DELIBERATELY VULNERABLE TEST FIXTURE - DO NOT DEPLOY.
// Insecure file upload: client filename trusted, no type/extension check,
// stored under a web-served directory (a .php upload becomes executable).
$name = $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], __DIR__ . '/public/uploads/' . $name);
echo 'saved ' . $name;
