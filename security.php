<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Security Operations & Cryptographic Utility Library
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Provides:
 * - CSRF token generation and timing-safe validation (CWE-352)
 * - State-of-the-art password hashing (Argon2id / Bcrypt) and constant-time verify
 * - Timing-attack defense (CWE-208)
 * - Brute-force account lockout tracking (CWE-307)
 * - Two-Factor Authentication (2FA) OTP issuance and verification (ITP216 Lab 5)
 * - Inactivity and absolute session timeout enforcement (CWE-613 / ITP216 Lab 3)
 * - Comprehensive security audit logging for forensic analysis
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

// PHPMailer Integration for Out-of-Band 2FA Email Dispatch
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} elseif (file_exists(__DIR__ . '/vendor/phpmailer/phpmailer/src/PHPMailer.php')) {
    require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/Exception.php';
    require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/PHPMailer.php';
    require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/SMTP.php';
}

// ------------------------------------------------------------------------------
// 1. HTML Output Sanitization (Anti-XSS - CWE-79)
// ------------------------------------------------------------------------------
function e(?string $value): string {
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// ------------------------------------------------------------------------------
// 2. Client IP Address Resolver
// ------------------------------------------------------------------------------
function get_client_ip(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    // Validate IP format to avoid log injection
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }
    return '0.0.0.0';
}

// ------------------------------------------------------------------------------
// 3. CSRF Protection (Cross-Site Request Forgery - CWE-352)
// Generates a cryptographically strong 256-bit token stored in the user session.
// Validated with timing-safe hash_equals() to defeat side-channel analysis.
// ------------------------------------------------------------------------------
function generate_csrf_token(): string {
    init_secure_session();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function get_csrf_token(): string {
    return generate_csrf_token();
}

function validate_csrf_token(?string $token): bool {
    init_secure_session();
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function render_csrf_input(): string {
    $token = e(get_csrf_token());
    return '<input type="hidden" name="csrf_token" value="' . $token . '">';
}

// ------------------------------------------------------------------------------
// 4. Password Hashing & Timing-Attack Defense
// Hashing Decision (Detailed in SECURITY_REPORT.md):
// - Primary: PASSWORD_ARGON2ID (winner of Password Hashing Competition, memory-hard)
// - Fallback: PASSWORD_BCRYPT (adaptive work factor = 12)
// ------------------------------------------------------------------------------
function hash_user_password(string $password): string {
    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64MB RAM
            'time_cost'   => 4,     // 4 iterations
            'threads'     => 1
        ]);
    }
    // Reliable fallback on legacy environments
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verify_user_password(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

/**
 * Executes a simulated password verify with a precomputed hash.
 * This ensures that even if an email is not registered, the response time
 * matches that of an existing user, thwarting user enumeration timing attacks.
 */
function dummy_password_verify(): void {
    // Pre-calculated Argon2/Bcrypt hash to waste equivalent CPU/memory cycles
    $dummy_hash = '$argon2id$v=19$m=65536,t=4,p=1$ZHVtbXlzYWx0MTIzNDU2Nw$r+6f0zUv8Z8Qf6d8h7K8zF3z4K3pL3q7R9t5V1w2X4Y';
    if (!defined('PASSWORD_ARGON2ID')) {
        $dummy_hash = '$2y$12$e8rUq8zWzXz8qX8yQ8e8ru8Z8q8X8yQ8e8ru8Z8q8X8yQ8e8ru8Z8';
    }
    password_verify('dummy_password_timing_pad', $dummy_hash);
}

// ------------------------------------------------------------------------------
// 5. Audit Logging Mechanism (Requirement 6)
// Records every login attempt with email, IP address, user agent, and status.
// ------------------------------------------------------------------------------
function log_auth_event(?int $user_id, string $email, string $status): void {
    try {
        $db = get_db();
        $ip = get_client_ip();
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 500);

        $stmt = $db->prepare(
            "INSERT INTO login_attempts (user_id, email_attempted, ip_address, user_agent, status, attempted_at)
             VALUES (:user_id, :email, :ip, :ua, :status, NOW())"
        );
        $stmt->execute([
            ':user_id' => $user_id,
            ':email'   => $email,
            ':ip'      => $ip,
            ':ua'      => $ua,
            ':status'  => $status
        ]);
    } catch (Exception $e) {
        error_log('Audit logging failed: ' . $e->getMessage());
    }
}

// ------------------------------------------------------------------------------
// 6. Brute-Force Protection & Account Lockout Logic (Requirement 4)
// Tracks consecutive failed attempts and locks the account for LOCKOUT_MINUTES.
// ------------------------------------------------------------------------------
function check_account_lockout(array $user): array {
    if (!empty($user['lockout_until'])) {
        $lockout_time = strtotime($user['lockout_until']);
        $now = time();

        if ($lockout_time > $now) {
            $remaining_seconds = $lockout_time - $now;
            $remaining_minutes = ceil($remaining_seconds / 60);
            return [
                'is_locked'         => true,
                'remaining_seconds' => $remaining_seconds,
                'remaining_minutes' => $remaining_minutes,
                'message'           => "Account is temporarily locked due to excessive failed attempts. Try again in {$remaining_minutes} minute(s)."
            ];
        }
    }
    return ['is_locked' => false, 'remaining_seconds' => 0, 'remaining_minutes' => 0, 'message' => ''];
}

function handle_failed_login(array $user): array {
    $db = get_db();
    $new_attempts = (int)$user['failed_login_attempts'] + 1;
    $user_id = (int)$user['id'];
    $email = $user['email'];

    if ($new_attempts >= MAX_FAILED_ATTEMPTS) {
        // Enforce lockout for LOCKOUT_MINUTES
        $stmt = $db->prepare(
            "UPDATE users 
             SET failed_login_attempts = :attempts, 
                 lockout_until = DATE_ADD(NOW(), INTERVAL :lockout_min MINUTE) 
             WHERE id = :id"
        );
        $stmt->execute([
            ':attempts'    => $new_attempts,
            ':lockout_min' => LOCKOUT_MINUTES,
            ':id'          => $user_id
        ]);

        log_auth_event($user_id, $email, 'ACCOUNT_LOCKED');

        return [
            'locked'  => true,
            'message' => "Account locked due to " . MAX_FAILED_ATTEMPTS . " consecutive failed attempts. Locked for " . LOCKOUT_MINUTES . " minutes."
        ];
    } else {
        // Increment count without locking yet
        $stmt = $db->prepare("UPDATE users SET failed_login_attempts = :attempts WHERE id = :id");
        $stmt->execute([
            ':attempts' => $new_attempts,
            ':id'       => $user_id
        ]);

        log_auth_event($user_id, $email, 'FAILED_PASSWORD');

        $remaining = MAX_FAILED_ATTEMPTS - $new_attempts;
        return [
            'locked'  => false,
            'message' => "Invalid email or password. {$remaining} attempt(s) remaining before account lockout."
        ];
    }
}

function reset_failed_login_attempts(int $user_id): void {
    $db = get_db();
    $stmt = $db->prepare("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = :id");
    $stmt->execute([':id' => $user_id]);
}

// ------------------------------------------------------------------------------
// 7. Two-Factor Authentication (2FA) Engine (Requirement 3 & ITP216 Lab 5)
// Generates cryptographically secure 6-digit OTP, stores hashed token,
// enforces single-use semantics, 5-minute expiry, and max 3 entry attempts.
// ------------------------------------------------------------------------------
function issue_user_otp(int $user_id): string {
    $db = get_db();

    // Invalidate any previously active OTPs for this user
    $invalidate_stmt = $db->prepare("UPDATE otp_codes SET is_used = 1 WHERE user_id = :uid AND is_used = 0");
    $invalidate_stmt->execute([':uid' => $user_id]);

    // Generate cryptographically secure 6-digit integer
    $plain_otp = (string)random_int(100000, 999999);

    // Hash the OTP with Bcrypt or SHA-256 before database insertion
    // Security defense: If database is dumped, attacker cannot read valid unexpired OTPs
    $otp_hash = password_hash($plain_otp, PASSWORD_BCRYPT);

    $insert_stmt = $db->prepare(
        "INSERT INTO otp_codes (user_id, otp_hash, expires_at, is_used, attempts, created_at)
         VALUES (:uid, :hash, DATE_ADD(NOW(), INTERVAL :expiry SECOND), 0, 0, NOW())"
    );
    $insert_stmt->execute([
        ':uid'    => $user_id,
        ':hash'   => $otp_hash,
        ':expiry' => OTP_EXPIRY_SECONDS
    ]);

    return $plain_otp;
}

/**
 * Dispatches a 6-digit One-Time Password to the user's email address via PHPMailer.
 * Uses Gmail SMTP with credentials configured in config.php.
 *
 * @param string $recipient_email The destination email
 * @param string $plain_otp The plain 6-digit code
 * @return array ['success' => bool, 'error' => string|null]
 */
function send_otp_email(string $recipient_email, string $plain_otp): array {
    if (!defined('SMTP_ENABLED') || !SMTP_ENABLED) {
        return ['success' => false, 'error' => 'SMTP is disabled in configuration.'];
    }

    if (!class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        return ['success' => false, 'error' => 'PHPMailer library is not loaded.'];
    }

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);

    try {
        // SMTP Server Configuration
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        $mail->SMTPSecure = (SMTP_PORT == 465) ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = (int)SMTP_PORT;
        $mail->Timeout    = 10;
        $mail->CharSet    = 'UTF-8';

        // Sender, Reply-To & Recipient
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        if (defined('SMTP_REPLY_TO_EMAIL') && !empty(SMTP_REPLY_TO_EMAIL)) {
            $mail->addReplyTo(SMTP_REPLY_TO_EMAIL, defined('SMTP_REPLY_TO_NAME') ? SMTP_REPLY_TO_NAME : 'ITP216 No-Reply');
        }
        $mail->addAddress($recipient_email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'ITP216 Verification Code: ' . $plain_otp;
        $mail->Body    = "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        </head>
        <body style='font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif; background-color: #0b0d11; color: #f3f4f6; padding: 24px 12px; margin: 0;'>
            <div style='max-width: 480px; margin: 0 auto; background: #12151b; border: 1px solid #232836; border-radius: 12px; padding: 32px 28px; box-shadow: 0 4px 14px rgba(0,0,0,0.35);'>
                <div style='text-align: center; margin-bottom: 24px;'>
                    <div style='display: inline-block; padding: 4px 12px; background: #181c24; border: 1px solid #232836; border-radius: 9999px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: #38bdf8; margin-bottom: 12px;'>
                        ITP216 Security System
                    </div>
                    <h1 style='color: #ffffff; font-size: 21px; margin: 0 0 6px 0; font-weight: 600; letter-spacing: -0.015em;'>Two-Factor Authentication</h1>
                    <p style='color: #9ca3af; font-size: 13px; margin: 0;'>One-time security verification code</p>
                </div>

                <p style='font-size: 14px; line-height: 1.5; color: #d1d5db; margin: 0 0 20px 0;'>
                    A sign-in attempt requires identity verification. Enter the 6-digit passcode below to complete authentication:
                </p>

                <div style='background: #181c24; border: 1px solid #232836; border-radius: 8px; padding: 18px; text-align: center; margin: 20px 0 24px 0;'>
                    <div style='font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #6b7280; margin-bottom: 6px;'>Verification Code</div>
                    <span style='font-family: ui-monospace, \"Courier New\", Courier, monospace; font-size: 34px; font-weight: 700; letter-spacing: 8px; color: #38bdf8;'>{$plain_otp}</span>
                </div>

                <div style='background: #181c24; border-left: 3px solid #38bdf8; border-radius: 4px; padding: 12px 14px; margin-bottom: 12px;'>
                    <div style='font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #38bdf8; margin-bottom: 3px;'>Validity Period</div>
                    <div style='font-size: 13px; color: #d1d5db; line-height: 1.4;'>Expires in <strong>" . (OTP_EXPIRY_SECONDS / 60) . " minutes</strong>. Single-use only.</div>
                </div>

                <div style='background: #181c24; border-left: 3px solid #f59e0b; border-radius: 4px; padding: 12px 14px; margin-bottom: 24px;'>
                    <div style='font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #f59e0b; margin-bottom: 3px;'>Security Notice</div>
                    <div style='font-size: 13px; color: #d1d5db; line-height: 1.4;'>If you did not request this code, your credentials may be exposed. Change your password immediately.</div>
                </div>

                <hr style='border: none; border-top: 1px solid #1f2533; margin: 20px 0;'>
                <p style='font-size: 11px; color: #6b7280; text-align: center; margin: 0; line-height: 1.4;'>
                    ITP216 Endterm Project &bull; Automated Security Dispatcher<br>
                    This is an automated security transmission. Please do not reply.
                </p>
            </div>
        </body>
        </html>";
        $mail->AltBody = "ITP216 Security Verification\n\nYour verification code is: {$plain_otp}\n\nThis code expires in " . (OTP_EXPIRY_SECONDS / 60) . " minutes. Single-use only.\nIf you did not initiate this request, please change your password immediately.";

        $mail->send();
        return ['success' => true, 'error' => null];
    } catch (Exception $e) {
        $err = $mail->ErrorInfo ?: $e->getMessage();
        error_log("PHPMailer failed to send OTP to {$recipient_email}: " . $err);
        return ['success' => false, 'error' => $err];
    }
}

function verify_user_otp(int $user_id, string $entered_otp): array {
    $db = get_db();

    // Retrieve most recent unused OTP
    $stmt = $db->prepare(
        "SELECT id, otp_hash, expires_at, attempts 
         FROM otp_codes 
         WHERE user_id = :uid AND is_used = 0 
         ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([':uid' => $user_id]);
    $otp_record = $stmt->fetch();

    if (!$otp_record) {
        return [
            'success' => false,
            'status'  => 'OTP_FAILED',
            'error'   => 'No active 2FA code found. Please request a new code.'
        ];
    }

    $otp_id   = (int)$otp_record['id'];
    $attempts = (int)$otp_record['attempts'];

    // 1. Check if expired (Requirement 3: 5-minute timeout)
    if (strtotime($otp_record['expires_at']) < time()) {
        $db->prepare("UPDATE otp_codes SET is_used = 1 WHERE id = :id")->execute([':id' => $otp_id]);
        return [
            'success' => false,
            'status'  => 'OTP_EXPIRED',
            'error'   => 'Verification code has expired (5-minute limit exceeded). Please log in again.'
        ];
    }

    // 2. Check if maximum attempts exceeded (Brute-force protection on OTP space)
    if ($attempts >= OTP_MAX_ATTEMPTS) {
        $db->prepare("UPDATE otp_codes SET is_used = 1 WHERE id = :id")->execute([':id' => $otp_id]);
        return [
            'success' => false,
            'status'  => 'OTP_FAILED',
            'error'   => 'Too many invalid attempts. For your security, this code was invalidated. Please log in again.'
        ];
    }

    // 3. Verify OTP cryptographic hash
    if (password_verify($entered_otp, $otp_record['otp_hash'])) {
        // Mark as used (Single-use token guarantee)
        $db->prepare("UPDATE otp_codes SET is_used = 1 WHERE id = :id")->execute([':id' => $otp_id]);
        return [
            'success' => true,
            'status'  => 'OTP_SUCCESS',
            'error'   => null
        ];
    } else {
        // Increment attempts on incorrect guess
        $new_attempts = $attempts + 1;
        $db->prepare("UPDATE otp_codes SET attempts = :attempts WHERE id = :id")
           ->execute([':attempts' => $new_attempts, ':id' => $otp_id]);

        $remaining = OTP_MAX_ATTEMPTS - $new_attempts;
        $err = $remaining > 0 
            ? "Incorrect verification code. {$remaining} attempt(s) remaining."
            : "Maximum verification attempts exceeded. Code has been invalidated.";

        return [
            'success' => false,
            'status'  => 'OTP_FAILED',
            'error'   => $err
        ];
    }
}

// ------------------------------------------------------------------------------
// 8. Session Security & Inactivity Verification (Requirement 5)
// Thwarts Session Fixation, Session Hijacking, and Stale Session Exposure.
// ------------------------------------------------------------------------------
function require_authenticated_user(): void {
    init_secure_session();

    // Check if fully authenticated (both password and 2FA completed)
    if (empty($_SESSION['authenticated']) || empty($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }

    $now = time();

    // Enforce Inactivity Timeout (Requirement 5)
    if (isset($_SESSION['last_activity']) && ($now - $_SESSION['last_activity'] > SESSION_INACTIVITY_TIMEOUT)) {
        // Clear session data
        destroy_user_session();
        header('Location: login.php?reason=timeout');
        exit;
    }

    // Enforce Absolute Session Lifetime
    if (isset($_SESSION['session_created_at']) && ($now - $_SESSION['session_created_at'] > SESSION_ABSOLUTE_TIMEOUT)) {
        destroy_user_session();
        header('Location: login.php?reason=expired');
        exit;
    }

    // Slide inactivity window forward
    $_SESSION['last_activity'] = $now;
}

function destroy_user_session(): void {
    init_secure_session();
    $_SESSION = [];

    // Expire session cookie on browser
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
}
