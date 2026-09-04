<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Protected Dashboard & Security Audit Console
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Requirement 5 & 6:
 * - Access-controlled: Strictly requires authenticated session
 * - Enforces session inactivity timeout (15 mins) and absolute timeout (8 hours)
 * - Security Audit Log view: Queries login_attempts table with timestamps and IPs
 * - Provides interactive security controls to demonstrate defense concepts
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';

// Enforce session access control & timeouts (Requirement 5)
require_authenticated_user();

$user_id    = (int)$_SESSION['user_id'];
$user_email = $_SESSION['user_email'];
$last_act   = $_SESSION['last_activity'];
$db         = get_db();

// Fetch User Profile details
$user_stmt = $db->prepare("SELECT id, email, failed_login_attempts, created_at, updated_at FROM users WHERE id = :id");
$user_stmt->execute([':id' => $user_id]);
$current_user = $user_stmt->fetch();

// Fetch Security Audit Logs (Requirement 6)
// We fetch the most recent 25 attempts across the system to give a comprehensive security view
$logs_stmt = $db->prepare(
    "SELECT id, email_attempted, ip_address, user_agent, status, attempted_at 
     FROM login_attempts 
     ORDER BY attempted_at DESC 
     LIMIT 25"
);
$logs_stmt->execute();
$audit_logs = $logs_stmt->fetchAll();

// Calculate session statistics
$active_cookie_params = session_get_cookie_params();
$session_lifetime = time() - ($_SESSION['session_created_at'] ?? time());
$inactivity_remaining = SESSION_INACTIVITY_TIMEOUT - (time() - $last_act);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Console - Dashboard</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="dashboard-layout">
    <!-- Main Navigation Bar -->
    <header class="navbar">
        <div class="container nav-content">
            <a href="dashboard.php" class="nav-brand">
                <span class="material-icons" style="font-size: 1.25rem;">security</span>
                <span>ITP216 Security Console</span>
                <span class="brand-badge">2FA Protected</span>
            </a>

            <div class="nav-user">
                <div class="user-pill">
                    <span class="user-status-dot"></span>
                    <span><?= e($user_email) ?></span>
                </div>
                <a href="logout.php" class="btn btn-danger btn-sm">Sign Out</a>
            </div>
        </div>
    </header>

    <!-- Main Content Area -->
    <main class="container" style="flex: 1; padding-top: 2rem; padding-bottom: 3rem;">
        
        <!-- Welcome Hero Banner -->
        <div class="card" style="padding: 1.75rem 2rem; margin-bottom: 2rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <h2>Authentication Verified</h2>
                    <p class="subtitle" style="margin-bottom: 0;">
                        Both Factor 1 (Master Password) and Factor 2 (Time-based OTP) successfully verified.
                    </p>
                </div>
                <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    <span class="badge badge-success"><span class="material-icons">check_circle</span> Session Active</span>
                    <span class="badge badge-info"><span class="material-icons">verified_user</span> HttpOnly & SameSite</span>
                    <span class="badge badge-warning"><span class="material-icons">timer</span> Timeout: 15 min</span>
                </div>
            </div>
        </div>

        <!-- Security Architecture Metrics Grid -->
        <div class="dashboard-grid">
            <!-- Metric 1: Session Security -->
            <div class="card stat-card">
                <div class="stat-header">
                    <span class="stat-title">Session Hardening</span>
                    <span class="material-icons" style="font-size: 1.15rem; color: var(--text-muted);">lock</span>
                </div>
                <div class="stat-value" style="font-size: 1.25rem;">
                    SameSite=Strict
                </div>
                <div class="stat-desc">
                    HttpOnly: <code><?= $active_cookie_params['httponly'] ? 'True' : 'False' ?></code><br>
                    Secure: <code><?= $active_cookie_params['secure'] ? 'True' : 'Off (Dev)' ?></code><br>
                    Fixation Defense: <code>Regenerated</code>
                </div>
            </div>

            <!-- Metric 2: 2FA Policy -->
            <div class="card stat-card">
                <div class="stat-header">
                    <span class="stat-title">Two-Factor Policy</span>
                    <span class="material-icons" style="font-size: 1.15rem; color: var(--text-muted);">smartphone</span>
                </div>
                <div class="stat-value" style="font-size: 1.25rem;">
                    6-Digit OTP
                </div>
                <div class="stat-desc">
                    Expiry Window: <code><?= OTP_EXPIRY_SECONDS / 60 ?> minutes</code><br>
                    Max Tries: <code><?= OTP_MAX_ATTEMPTS ?> attempts</code><br>
                    Storage: <code>Hashed (One-way)</code>
                </div>
            </div>

            <!-- Metric 3: Brute-Force Defense -->
            <div class="card stat-card">
                <div class="stat-header">
                    <span class="stat-title">Brute-Force Guard</span>
                    <span class="material-icons" style="font-size: 1.15rem; color: var(--text-muted);">block</span>
                </div>
                <div class="stat-value" style="font-size: 1.25rem;">
                    <?= MAX_FAILED_ATTEMPTS ?> Tries / Lockout
                </div>
                <div class="stat-desc">
                    Lockout Duration: <code><?= LOCKOUT_MINUTES ?> minutes</code><br>
                    Timing Defense: <code>Constant-Time</code><br>
                    Current Failures: <code><?= (int)$current_user['failed_login_attempts'] ?></code>
                </div>
            </div>

            <!-- Metric 4: Session Inactivity Monitor -->
            <div class="card stat-card">
                <div class="stat-header">
                    <span class="stat-title">Inactivity Countdown</span>
                    <span class="material-icons" style="font-size: 1.15rem; color: var(--text-muted);">hourglass_top</span>
                </div>
                <div class="stat-value mono" id="sessionCountdown" style="font-size: 1.6rem; color: var(--accent-cyan);">
                    15:00
                </div>
                <div class="stat-desc">
                    Auto-logs out upon 15 minutes of idle time to thwart unattended session hijack.
                </div>
            </div>
        </div>

        <!-- Security Audit Log Table (Requirement 6) -->
        <div class="card table-card">
            <div class="table-header">
                <div>
                    <h3 style="font-size: 1.25rem;">Security Audit Logs (<code>login_attempts</code>)</h3>
                    <p class="subtitle" style="margin-bottom: 0;">
                        Requirement 6: Real-time record of all login activities, failed passwords, and 2FA challenges.
                    </p>
                </div>
                <div>
                    <button class="btn btn-secondary btn-sm" onclick="location.reload()">
                        <span class="material-icons">refresh</span> Refresh Logs
                    </button>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>#ID</th>
                            <th>Timestamp</th>
                            <th>Target Account</th>
                            <th>IP Address</th>
                            <th>Security Event Status</th>
                            <th>Client Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($audit_logs)): ?>
                            <tr>
                                <td colspan="6" class="text-center text-muted" style="padding: 2rem;">
                                    No authentication events recorded yet.
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($audit_logs as $log): ?>
                                <tr>
                                    <td class="mono"><?= (int)$log['id'] ?></td>
                                    <td class="mono"><?= e($log['attempted_at']) ?></td>
                                    <td><strong><?= e($log['email_attempted']) ?></strong></td>
                                    <td><span class="mono"><?= e($log['ip_address']) ?></span></td>
                                    <td>
                                        <?php
                                        $status = $log['status'];
                                        if ($status === 'SUCCESS' || $status === 'OTP_SUCCESS') {
                                            echo '<span class="badge badge-success"><span class="material-icons">check</span> ' . e($status) . '</span>';
                                        } elseif ($status === 'ACCOUNT_LOCKED') {
                                            echo '<span class="badge badge-danger"><span class="material-icons">lock</span> ' . e($status) . '</span>';
                                        } elseif ($status === 'FAILED_PASSWORD' || $status === 'OTP_FAILED') {
                                            echo '<span class="badge badge-danger"><span class="material-icons">close</span> ' . e($status) . '</span>';
                                        } elseif ($status === 'OTP_SENT') {
                                            echo '<span class="badge badge-info"><span class="material-icons">sms</span> ' . e($status) . '</span>';
                                        } else {
                                            echo '<span class="badge badge-warning"><span class="material-icons">warning</span> ' . e($status) . '</span>';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <small class="text-muted" title="<?= e($log['user_agent']) ?>">
                                            <?= e(substr($log['user_agent'] ?? 'Unknown', 0, 45)) ?>...
                                        </small>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="security-note mt-3">
                <strong>Forensic Analysis Note (ITP216 Lab 3 & Lab 4):</strong>
                This audit log table supports incident response and forensic analysis. Rapid bursts of <code>FAILED_PASSWORD</code> or <code>ACCOUNT_LOCKED</code> entries indicate automated dictionary or credential stuffing attacks.
            </div>
        </div>

    </main>

    <!-- Global Footer -->
    <footer class="footer">
        <div class="container">
            <p>ITP216 Endterm Project &bull; Secure Authentication System with Two-Factor Authentication</p>
        </div>
    </footer>

    <script>
        // Live Inactivity Countdown Timer (Client-Side Feedback)
        let inactivitySeconds = <?= (int)$inactivity_remaining ?>;
        const countdownEl = document.getElementById('sessionCountdown');

        function updateSessionTimer() {
            if (inactivitySeconds <= 0) {
                countdownEl.textContent = '00:00 (Expired)';
                countdownEl.style.color = '#f87171';
                // Trigger auto redirect on expiry
                window.location.href = 'login.php?reason=timeout';
                return;
            }

            const min = Math.floor(inactivitySeconds / 60);
            const sec = inactivitySeconds % 60;
            countdownEl.textContent = 
                String(min).padStart(2, '0') + ':' + 
                String(sec).padStart(2, '0');

            if (inactivitySeconds < 120) {
                countdownEl.style.color = '#fbbf24';
            }

            inactivitySeconds--;
            setTimeout(updateSessionTimer, 1000);
        }

        updateSessionTimer();
    </script>
</body>
</html>
