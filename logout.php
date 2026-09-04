<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Secure Logout & Session Termination
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Requirement 5:
 * Securely terminates the authenticated session by:
 * 1. Overwriting server-side $_SESSION superglobal array
 * 2. Explicitly expiring the client-side session cookie in the browser
 * 3. Destroying server-side session storage via session_destroy()
 * 
 * Defense Note (ITP216 Lab 3 / OWASP):
 * Calling session_destroy() alone does NOT unset $_SESSION in current script
 * execution, nor does it clear the client-side cookie! A truly secure logout
 * must clear all three layers to prevent session revival attacks.
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/security.php';

// Initialize session to ensure proper handler access
init_secure_session();

// 1. Flush memory: Unset all session variables
$_SESSION = [];

// 2. Destroy cookie on client: Overwrite session cookie with past expiration date
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000, // 42000 seconds in the past ensures immediate browser purge
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

// 3. Destroy server-side session file/storage
session_destroy();

// Redirect to login screen with logged out status confirmation
header('Location: login.php?logged_out=1');
exit;
