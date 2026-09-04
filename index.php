<?php
/**
 * Application Entry Point / Router
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/security.php';

init_secure_session();

if (!empty($_SESSION['authenticated']) && !empty($_SESSION['user_id'])) {
    header('Location: dashboard.php');
} else {
    header('Location: login.php');
}
exit;
