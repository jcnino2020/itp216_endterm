<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Secondary Authentication Module (Factor 2: Possession / OTP)
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Requirement 3:
 * - Verifies 6-digit time-sensitive One-Time Password (OTP)
 * - 5-minute expiry enforcement
 * - Single-use token invalidation
 * - Max 3 attempts per OTP to thwart brute-force cracking
 * - Prevents Session Fixation (Requirement 2) via session_regenerate_id(true)
 * - Ties directly to ITP216 Lab 5 (Two-Factor Authentication)
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';

init_secure_session();

// 1. Guard: Ensure user has passed Factor 1 (Password verification)
if (empty($_SESSION['2fa_pending']) || empty($_SESSION['2fa_user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id   = (int)$_SESSION['2fa_user_id'];
$user_email = $_SESSION['2fa_email'] ?? 'Unknown User';
$demo_otp   = $_SESSION['2fa_otp_display'] ?? null;
$error_msg  = '';
$info_msg   = (!empty($_SESSION['2fa_email_sent'])) 
    ? "A 6-digit verification code has been emailed to {$user_email}." 
    : '';

// Calculate remaining lifetime in seconds for client-side countdown
$now = time();
$elapsed = $now - ($_SESSION['2fa_timestamp'] ?? $now);
$remaining_seconds = max(0, OTP_EXPIRY_SECONDS - $elapsed);

// Handle "Resend OTP" Request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'resend') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_msg = 'Security verification failed (Invalid CSRF token).';
    } else {
        $last_sent = $_SESSION['2fa_timestamp'] ?? 0;
        if (($now - $last_sent) < OTP_RESEND_COOLDOWN) {
            $cooldown_rem = OTP_RESEND_COOLDOWN - ($now - $last_sent);
            $error_msg = "Please wait {$cooldown_rem} second(s) before requesting a new OTP.";
        } else {
            // Issue new OTP
            $new_otp = issue_user_otp($user_id);
            $_SESSION['2fa_timestamp']   = time();
            $_SESSION['2fa_otp_display'] = $new_otp;
            $demo_otp = $new_otp;
            $remaining_seconds = OTP_EXPIRY_SECONDS;

            // Dispatch via Gmail SMTP (PHPMailer)
            $mail_res = send_otp_email($user_email, $new_otp);
            if ($mail_res['success']) {
                $info_msg = "A fresh 6-digit verification code has been sent to {$user_email}.";
            } else {
                $info_msg = 'A fresh 6-digit verification code has been issued.';
            }

            log_auth_event($user_id, $user_email, 'OTP_SENT');
        }
    }
}
// Handle OTP Submission
elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_msg = 'Security verification failed (Invalid CSRF token).';
    } else {
        $entered_otp = trim($_POST['otp'] ?? '');

        // Validate format (exact 6 digits)
        if (!preg_match('/^[0-9]{6}$/', $entered_otp)) {
            $error_msg = 'Please enter a valid 6-digit numeric verification code.';
        } else {
            // Verify against database records
            $result = verify_user_otp($user_id, $entered_otp);

            if ($result['success']) {
                // ==============================================================
                // CRITICAL SECURITY OPERATION: Session Fixation Prevention
                // (Requirement 2 & OWASP Guidelines)
                // Discard the old pre-auth session identifier and generate
                // a completely new cryptographic session identifier.
                // ==============================================================
                session_regenerate_id(true);

                // Elevate session to fully authenticated state
                $_SESSION['authenticated']      = true;
                $_SESSION['user_id']            = $user_id;
                $_SESSION['user_email']         = $user_email;
                $_SESSION['last_activity']      = time();
                $_SESSION['session_created_at'] = time();

                // Clean up temporary 2FA artifacts
                unset(
                    $_SESSION['2fa_pending'],
                    $_SESSION['2fa_user_id'],
                    $_SESSION['2fa_email'],
                    $_SESSION['2fa_timestamp'],
                    $_SESSION['2fa_otp_display']
                );

                // Audit Log Successful 2FA Login
                log_auth_event($user_id, $user_email, 'SUCCESS');

                // Redirect to protected dashboard
                header('Location: dashboard.php');
                exit;
            } else {
                // Log failed OTP attempt
                log_auth_event($user_id, $user_email, $result['status']);
                $error_msg = $result['error'];
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication (2FA) - Step 2</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="center-layout">
    <div class="card auth-card">
        <div class="card-header text-center">
            <div class="shield-icon"><span class="material-icons">smartphone</span></div>
            <h2>Two-Factor Verification</h2>
            <p class="subtitle">Step 2 of 2: Enter code sent to <strong><?= e($user_email) ?></strong></p>
        </div>

        <div class="card-body">
            <?php if (OTP_DEMO_MODE && !empty($demo_otp)): ?>
                <!-- Simulated 2FA Delivery Banner for Defense Demonstration -->
                <div class="demo-banner">
                    <div class="demo-banner-title">
                        <span class="material-icons" style="font-size: 1rem; vertical-align: middle;">notifications</span> Live OTP & Demo Fallback
                    </div>
                    <p style="font-size: 0.8rem; color: var(--text-secondary);">
                        Code dispatched to <strong><?= e($user_email) ?></strong>. On-screen fallback:
                    </p>
                    <div class="demo-otp-display" id="demoCodeDisplay"><?= e($demo_otp) ?></div>
                    <div class="text-center">
                        <button type="button" class="btn btn-secondary btn-sm" onclick="autoFillOtp('<?= e($demo_otp) ?>')">
                            <span class="material-icons" style="font-size: 0.95rem; vertical-align: -1px;">content_copy</span> Auto-Fill Code
                        </button>
                    </div>
                </div>
            <?php endif; ?>

            <?php if (!empty($info_msg)): ?>
                <div class="alert-box alert-success">
                    <div><?= e($info_msg) ?></div>
                </div>
            <?php endif; ?>

            <?php if (!empty($error_msg)): ?>
                <div class="alert-box alert-danger">
                    <div>
                        <strong>Verification Error:</strong><br>
                        <?= e($error_msg) ?>
                    </div>
                </div>
            <?php endif; ?>

            <div class="countdown-container">
                Code expires in: <span id="countdownTimer" class="countdown-timer">05:00</span>
            </div>

            <form method="POST" action="verify_otp.php" id="otpForm">
                <?= render_csrf_input() ?>

                <div class="otp-input-container">
                    <input type="text" id="otpInput" name="otp" class="otp-input-large" 
                           maxlength="6" placeholder="••••••" pattern="[0-9]{6}" 
                           inputmode="numeric" autocomplete="one-time-code" autofocus required>
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    Verify Code & Complete Sign In &rarr;
                </button>
            </form>

            <form method="POST" action="verify_otp.php" style="margin-top: 1rem;">
                <?= render_csrf_input() ?>
                <input type="hidden" name="action" value="resend">
                <button type="submit" class="btn btn-secondary btn-block btn-sm">
                    <span class="material-icons" style="font-size: 0.95rem; vertical-align: -1px;">refresh</span> Resend New Security Code
                </button>
            </form>

            <div class="auth-links">
                <a href="logout.php">&larr; Cancel and return to Login</a>
            </div>

            <div class="security-note">
                <strong>Defense Rationale (Requirement 3 & Lab 5):</strong>
                2FA satisfies the possession factor ("something you have"). Codes are 6 digits, cryptographically hashed in storage, valid for 5 minutes, and invalidated after <?= OTP_MAX_ATTEMPTS ?> failed attempts. Successful verification triggers <code>session_regenerate_id(true)</code> to mitigate Session Fixation (CWE-384).
            </div>
        </div>
    </div>

    <script>
        // Countdown Timer Logic
        let remainingSeconds = <?= (int)$remaining_seconds ?>;
        const timerElement = document.getElementById('countdownTimer');

        function updateCountdown() {
            if (remainingSeconds <= 0) {
                timerElement.textContent = 'EXPIRED';
                timerElement.classList.add('expiring');
                return;
            }

            const minutes = Math.floor(remainingSeconds / 60);
            const seconds = remainingSeconds % 60;
            timerElement.textContent = 
                String(minutes).padStart(2, '0') + ':' + 
                String(seconds).padStart(2, '0');

            if (remainingSeconds < 60) {
                timerElement.classList.add('expiring');
            }

            remainingSeconds--;
            setTimeout(updateCountdown, 1000);
        }

        updateCountdown();

        // Helper to auto-fill code from demo banner
        function autoFillOtp(code) {
            const input = document.getElementById('otpInput');
            input.value = code;
            input.focus();
        }
    </script>
</body>
</html>
