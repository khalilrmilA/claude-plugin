<?php
// DELIBERATELY VULNERABLE TEST FIXTURE - DO NOT DEPLOY.
// Hardcoded database credentials (secrets) and a default admin account.
$DB_HOST = 'db.example.internal';
$DB_USER = 'root';
$DB_PASS = 'P@ssw0rd-prod-9271';
$DB_NAME = 'shop';

define('ADMIN_USER', 'admin');
define('ADMIN_PASS', 'admin');

ini_set('display_errors', '1');
error_reporting(E_ALL);
