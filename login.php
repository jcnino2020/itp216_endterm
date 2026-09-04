<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Primary Authentication Module (Factor 1: Knowledge / Password)
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Requirement 2 & 4:
 * - Credentials verified using password_verify()
 * - Brute-force protection: Tracks failed attempts, locks account after N failures
 * - Timing-attack defense: Uses dummy password verify if email does not exist
 * - Initiates Factor 2: Generates 6-digit OTP and redirects to verify_otp.php
 * - Comprehensive audit logging to login_attempts table
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';

init_secure_session();

// If already fully authenticated, bypass login
if (!empty($_SESSION['authenticated']) && !empty($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error_msg = '';
$info_msg = '';
$email_input = '';

// Handle redirect parameters/flash notifications
if (isset($_GET['registered'])) {
    $info_msg = 'Account registered successfully. Please authenticate below.';
} elseif (isset($_GET['logged_out'])) {
    $info_msg = 'You have been securely logged out. Session destroyed.';
} elseif (isset($_GET['reason']) && $_GET['reason'] === 'timeout') {
    $error_msg = 'Your session timed out due to ' . (SESSION_INACTIVITY_TIMEOUT / 60) . ' minutes of inactivity. Please log in again.';
} elseif (isset($_GET['reason']) && $_GET['reason'] === 'expired') {
    $error_msg = 'Your session has reached its absolute maximum lifetime. Please re-authenticate.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Verify CSRF Token (CWE-352)
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_msg = 'Security verification failed (Invalid CSRF token). Please try again.';
    } else {
        $email_input = trim($_POST['email'] ?? '');
        $password    = $_POST['password'] ?? '';

        if (empty($email_input) || empty($password)) {
            $error_msg = 'Please enter both your email address and password.';
        } else {
            try {
                $db = get_db();

                // 2. Fetch User Record
                $stmt = $db->prepare(
                    "SELECT id, email, password_hash, failed_login_attempts, lockout_until 
                     FROM users 
                     WHERE email = :email LIMIT 1"
                );
                $stmt->execute([':email' => $email_input]);
                $user = $stmt->fetch();

                if ($user) {
                    // 3. Brute-Force Protection: Check if Account is Locked (Requirement 4)
                    $lockout_status = check_account_lockout($user);
                    if ($lockout_status['is_locked']) {
                        log_auth_event((int)$user['id'], $email_input, 'ACCOUNT_LOCKED');
                        $error_msg = $lockout_status['message'];
                    } else {
                        // 4. Verify Password Hash using password_verify() (Requirement 2)
                        if (verify_user_password($password, $user['password_hash'])) {
                            // Successful Password Check!
                            // Reset failed login attempts on valid credential entry
                            reset_failed_login_attempts((int)$user['id']);

                            // 5. Generate Two-Factor Authentication OTP (Requirement 3 & ITP216 Lab 5)
                            $plain_otp = issue_user_otp((int)$user['id']);

                            // Dispatch Out-of-Band 2FA Email via Gmail SMTP (PHPMailer)
                            $email_result = send_otp_email($user['email'], $plain_otp);

                            // Store temporary 2FA state in session (User is NOT authenticated yet!)
                            $_SESSION['2fa_pending']     = true;
                            $_SESSION['2fa_user_id']     = (int)$user['id'];
                            $_SESSION['2fa_email']       = $user['email'];
                            $_SESSION['2fa_timestamp']   = time();
                            $_SESSION['2fa_otp_display'] = $plain_otp; // For on-screen demo fallback
                            $_SESSION['2fa_email_sent']  = $email_result['success'];

                            // Log OTP issuance
                            log_auth_event((int)$user['id'], $user['email'], 'OTP_SENT');

                            // Redirect to Factor 2 verification
                            header('Location: verify_otp.php');
                            exit;
                        } else {
                            // Incorrect Password: Track failed attempt & enforce lockout
                            $fail_result = handle_failed_login($user);
                            $error_msg = $fail_result['message'];
                        }
                    }
                } else {
                    // User Not Found:
                    // Security Defense: Execute dummy verify to equalize response time
                    // defeating user enumeration via timing analysis (CWE-208 / ITP216 Lab 3).
                    dummy_password_verify();

                    // Log failed attempt without leaking non-existence
                    log_auth_event(null, $email_input, 'FAILED_PASSWORD');

                    // Generic error message prevents account enumeration
                    $error_msg = 'Invalid email or password.';
                }
            } catch (PDOException $e) {
                error_log('Login failure: ' . $e->getMessage());
                $error_msg = 'An error occurred while processing your authentication. Please try again.';
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
    <title>Secure Login - 2FA Authentication System</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="center-layout">
    <div class="card auth-card">
        <div class="card-header text-center">
            <div class="shield-icon"><span class="material-icons">shield</span></div>
            <h2>Secure Sign In</h2>
        </div>

        <div class="card-body">
            <?php if (!empty($info_msg)): ?>
                <div class="alert-box alert-success">
                    <div><?= e($info_msg) ?></div>
                </div>
            <?php endif; ?>

            <?php if (!empty($error_msg)): ?>
                <div class="alert-box alert-danger">
                    <div>
                        <strong>Authentication Error:</strong><br>
                        <?= e($error_msg) ?>
                    </div>
                </div>
            <?php endif; ?>

            <form method="POST" action="login.php" novalidate>
                <?= render_csrf_input() ?>

                <div class="form-group">
                    <label for="email" class="form-label">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" 
                           value="<?= e($email_input) ?>" placeholder="user@university.edu" required autocomplete="email">
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Master Password</label>
                    <input type="password" id="password" name="password" class="form-control" 
                           placeholder="••••••••••••" required autocomplete="current-password">
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    Verify Credentials & Send OTP &rarr;
                </button>
            </form>

            <div class="auth-links">
                Don't have an account? <a href="register.php">Register now</a> | <a href="setup.php">Setup Database</a>
            </div>
        </div>
    </div>
</body>
</html>
