<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Configuration & Security Settings
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * This file centralizes security policies, database parameters, session
 * hardening directives, and global HTTP response headers.
 */

// Prevent direct access if called out of context in web server
if (php_sapi_name() !== 'cli' && count(get_included_files()) === 1) {
    http_response_code(403);
    exit('Direct script access is forbidden.');
}

// Private configuration must be outside the web root or supplied through the environment.
$itpPrivateConfig = getenv('ITP_CONFIG_FILE') ?: dirname(__DIR__) . '/itp216.private.php';
$itpSettings = is_file($itpPrivateConfig) ? require $itpPrivateConfig : [];
if (!is_array($itpSettings)) {
    throw new RuntimeException('Invalid private configuration.');
}
function itp_config(string $name, string $default = ''): string
{
    global $itpSettings;
    $value = getenv($name);
    return $value !== false ? $value : (string) ($itpSettings[$name] ?? $default);
}

// ------------------------------------------------------------------------------
// 1. Error Reporting Configuration
// In production/defense, suppress verbose database error details from end users
// to avoid information disclosure vulnerabilities (Ties to ITP216 Lab 4 Nessus).
// ------------------------------------------------------------------------------
error_reporting(E_ALL);
ini_set('display_errors', 0); // Keep off for production; logs errors internally
ini_set('log_errors', 1);

// ------------------------------------------------------------------------------
// 2. Database Connection Credentials
// Adjust these credentials to match your local or shared hosting environment.
// ------------------------------------------------------------------------------
define('DB_HOST', itp_config('DB_HOST', 'localhost'));
define('DB_PORT', itp_config('DB_PORT', '3306'));
define('DB_NAME', itp_config('DB_NAME', 'itp216'));
define('DB_USER', itp_config('DB_USER', 'root'));
define('DB_PASS', itp_config('DB_PASS', ''));
define('DB_CHARSET', 'utf8mb4');

// ------------------------------------------------------------------------------
// 3. Brute-Force & Account Lockout Policy
// Security Reasoning (Detailed in SECURITY_REPORT.md):
// - MAX_FAILED_ATTEMPTS: 5 attempts balances security against Denial of Service.
// - LOCKOUT_MINUTES: 15 minutes halts automated online dictionary attacks.
// ------------------------------------------------------------------------------
define('MAX_FAILED_ATTEMPTS', 5);
define('LOCKOUT_MINUTES', 15);

// ------------------------------------------------------------------------------
// 4. Two-Factor Authentication (2FA) Policy
// Ties directly to ITP216 Lab 5:
// - OTP_EXPIRY_SECONDS: 300s (5 minutes), following NIST SP 800-63B guidelines.
// - OTP_MAX_ATTEMPTS: 3 tries per code prevents brute-forcing the 6-digit space.
// - OTP_DEMO_MODE: When true, displays an on-screen toast/modal with the OTP
//   for seamless grading and classroom defense without external SMTP setup.
// ------------------------------------------------------------------------------
define('OTP_EXPIRY_SECONDS', 300); // 5 minutes
define('OTP_MAX_ATTEMPTS', 3);      // Max 3 incorrect OTP guesses before invalidation
define('OTP_RESEND_COOLDOWN', 60);  // 60 seconds rate limit for requesting a new OTP
define('OTP_DEMO_MODE', false);     // Disabled: Real out-of-band email delivery is active

// ------------------------------------------------------------------------------
// 5. Gmail SMTP Email Sender Configuration (PHPMailer)
// ------------------------------------------------------------------------------
define('SMTP_HOST', itp_config('SMTP_HOST', 'smtp.gmail.com'));
define('SMTP_PORT', itp_config('SMTP_PORT', '465'));
define('SMTP_USERNAME', itp_config('SMTP_USERNAME', ''));
define('SMTP_PASSWORD', itp_config('SMTP_PASSWORD', ''));
define('SMTP_FROM_EMAIL', itp_config('SMTP_FROM_EMAIL', ''));
define('SMTP_FROM_NAME', itp_config('SMTP_FROM_NAME', 'ITP216'));
define('SMTP_REPLY_TO_EMAIL', itp_config('SMTP_REPLY_TO_EMAIL', ''));
define('SMTP_REPLY_TO_NAME', itp_config('SMTP_REPLY_TO_NAME', 'ITP216'));

define('SMTP_ENABLED', SMTP_USERNAME !== '' && SMTP_PASSWORD !== '');

// ------------------------------------------------------------------------------
// 5. Session Timeout Settings
// Ties to ITP216 Lab 3 (Session Expiration - CWE-613):
// - Inactivity timeout terminates stale sessions left on unattended devices.
// ------------------------------------------------------------------------------
define('SESSION_INACTIVITY_TIMEOUT', 900); // 15 minutes of inactivity (900s)
define('SESSION_ABSOLUTE_TIMEOUT', 28800);  // 8 hours absolute lifetime (28800s)

// ------------------------------------------------------------------------------
// 6. Global HTTP Security Headers
// Defense-in-depth mitigation against Clickjacking, MIME-sniffing, and XSS
// (Directly addresses vulnerabilities flagged in ITP216 Lab 4 Nessus scans).
// ------------------------------------------------------------------------------
function apply_security_headers(): void {
    if (!headers_sent()) {
        // Prevent Clickjacking by disallowing framing in iframe/frame
        header('X-Frame-Options: DENY');

        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');

        // Content Security Policy (CSP) restricts unauthorized scripts & style injections
        header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:;");

        // Control referrer information leakage
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // Legacy XSS filter enforcement
        header('X-XSS-Protection: 1; mode=block');
    }
}

// ------------------------------------------------------------------------------
// 7. Secure Session Initialization
// Hardens PHP sessions according to OWASP Session Management Guidelines:
// - HttpOnly: JavaScript cannot read document.cookie, mitigating XSS session theft.
// - SameSite=Strict: Blocks CSRF request forgery by suppressing cross-site cookie transmission.
// - Secure: Transmitted only over HTTPS (auto-detects HTTPS or relaxes for localhost dev).
// - Strict Mode: Disallows uninitialized session IDs, thwarting session adoption attacks.
// ------------------------------------------------------------------------------
function init_secure_session(): void {
    if (session_status() === PHP_SESSION_NONE) {
        // Enforce strict session handling
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');

        $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                    || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);

        session_set_cookie_params([
            'lifetime' => 0,            // Session cookie expires when browser is closed
            'path'     => '/',
            'domain'   => '',           // Host-only cookie
            'secure'   => $is_https,    // Transmit only over HTTPS in production
            'httponly' => true,         // Mitigates XSS cookie theft
            'samesite' => 'Strict'      // Mitigates CSRF
        ]);

        // Custom session name obscures the underlying PHP technology stack
        session_name('ITP216_SECURE_AUTH');
        session_start();
    }
}

// Automatically apply baseline security headers upon inclusion
apply_security_headers();
