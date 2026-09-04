<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * User Registration Module
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Requirement 1:
 * - User registration with email + password.
 * - Passwords hashed using PHP's password_hash() (Argon2id/Bcrypt).
 * - Plaintext passwords are NEVER stored.
 * - CSRF token verification on all POST requests.
 * - Enforces strong password complexity policy.
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';

init_secure_session();

// If user is already fully authenticated, redirect to dashboard
if (!empty($_SESSION['authenticated']) && !empty($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$errors = [];
$success_msg = '';
$email_input = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Validate CSRF Token (CWE-352)
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Security verification failed (Invalid CSRF token). Please refresh and try again.';
    } else {
        $email_input = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $password_confirm = $_POST['password_confirm'] ?? '';

        // 2. Validate Email
        if (empty($email_input) || !filter_var($email_input, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please provide a valid email address.';
        } elseif (strlen($email_input) > 255) {
            $errors[] = 'Email address exceeds maximum allowable length (255 chars).';
        }

        // 3. Enforce Strong Password Policy (CWE-521 / ITP216 Lab 3)
        // Must have >= 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special character
        if (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters long.';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter (A-Z).';
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter (a-z).';
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number (0-9).';
        }
        if (!preg_match('/[\W_]/', $password)) {
            $errors[] = 'Password must contain at least one special character (!@#$%^&* etc.).';
        }

        // 4. Confirm Password Match
        if ($password !== $password_confirm) {
            $errors[] = 'Passwords do not match.';
        }

        // 5. Check for Existing Account & Insert
        if (empty($errors)) {
            try {
                $db = get_db();

                // Check if email already registered
                $check_stmt = $db->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
                $check_stmt->execute([':email' => $email_input]);
                if ($check_stmt->fetch()) {
                    $errors[] = 'An account with this email address already exists. Please log in.';
                } else {
                    // Cryptographic Hashing with Argon2id / Bcrypt
                    // Requirement 1: Plaintext passwords are NEVER stored
                    $password_hash = hash_user_password($password);

                    $insert_stmt = $db->prepare(
                        "INSERT INTO users (email, password_hash, failed_login_attempts, lockout_until, created_at)
                         VALUES (:email, :hash, 0, NULL, NOW())"
                    );
                    $insert_stmt->execute([
                        ':email' => $email_input,
                        ':hash'  => $password_hash
                    ]);

                    // Redirect to login with confirmation parameter
                    header('Location: login.php?registered=1');
                    exit;
                }
            } catch (PDOException $e) {
                error_log('Registration failure: ' . $e->getMessage());
                $errors[] = 'An unexpected system error occurred during registration. Please try again.';
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
    <title>Register - Secure 2FA Login System</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="center-layout">
    <div class="card auth-card">
        <div class="card-header text-center">
            <div class="shield-icon"><span class="material-icons">lock</span></div>
            <h2>Create Account</h2>
            <p class="subtitle">ITP216 Endterm: Secure 2FA Authentication</p>
        </div>

        <div class="card-body">
            <?php if (!empty($errors)): ?>
                <div class="alert-box alert-danger">
                    <div>
                        <strong>Registration Error:</strong>
                        <ul style="margin-left: 1.25rem; margin-top: 0.35rem;">
                            <?php foreach ($errors as $err): ?>
                                <li><?= e($err) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            <?php endif; ?>

            <form method="POST" action="register.php" novalidate id="registerForm">
                <?= render_csrf_input() ?>

                <div class="form-group">
                    <label for="email" class="form-label">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" 
                           value="<?= e($email_input) ?>" placeholder="user@university.edu" required autocomplete="email">
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Master Password</label>
                    <input type="password" id="password" name="password" class="form-control" 
                           placeholder="••••••••••••" required autocomplete="new-password">
                    
                    <div class="strength-meter">
                        <div id="strengthBar" class="strength-bar"></div>
                    </div>
                    <div id="strengthLabel" class="strength-label">Password strength: None</div>
                </div>

                <div class="form-group">
                    <label for="password_confirm" class="form-label">Confirm Master Password</label>
                    <input type="password" id="password_confirm" name="password_confirm" class="form-control" 
                           placeholder="••••••••••••" required autocomplete="new-password">
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    Register Secure Account
                </button>
            </form>

            <div class="auth-links">
                Already registered? <a href="login.php">Log in to your account</a>
            </div>

            <div class="security-note">
                <strong>Defense Rationale (Requirement 1):</strong>
                Passwords are never stored in plaintext. They are processed using <code>password_hash()</code> with <code>PASSWORD_ARGON2ID</code> (memory-hard, resistant to GPU/ASIC attacks) with adaptive <code>PASSWORD_BCRYPT</code> fallback.
            </div>
        </div>
    </div>

    <script>
        // Interactive Client-Side Password Strength Meter
        const passwordInput = document.getElementById('password');
        const strengthBar = document.getElementById('strengthBar');
        const strengthLabel = document.getElementById('strengthLabel');

        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            let score = 0;

            if (val.length >= 8) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[a-z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[\W_]/.test(val)) score++;

            const colors = ['#6b7280', '#ef4444', '#f59e0b', '#3b82f6', '#10b981'];
            const labels = ['Too Short', 'Weak', 'Fair', 'Good', 'Strong & Compliant'];

            const widthPercent = (score / 5) * 100;
            strengthBar.style.width = widthPercent + '%';
            strengthBar.style.backgroundColor = colors[Math.max(0, score - 1)] || '#6b7280';
            strengthLabel.textContent = val.length === 0 ? 'Password strength: None' : 'Password strength: ' + labels[Math.max(0, score - 1)];
        });
    </script>
</body>
</html>
