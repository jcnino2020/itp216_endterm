<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Database Setup & Migration Wizard
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Provides automated table initialization, schema verification,
 * and optional demo seed data creation for presentation/defense.
 */

require_once __DIR__ . '/config.php';

$messages = [];
$errors = [];
$installed = false;

// Check PHP Extensions
$req_exts = ['pdo', 'pdo_mysql', 'openssl', 'session'];
$missing_exts = [];
foreach ($req_exts as $ext) {
    if (!extension_loaded($ext)) {
        $missing_exts[] = $ext;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'initialize') {
    try {
        // Connect to MySQL server (without specifying DB name initially to create it if needed)
        $dsn_server = sprintf('mysql:host=%s;port=%s;charset=%s', DB_HOST, DB_PORT, DB_CHARSET);
        $pdo = new PDO($dsn_server, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);

        // Create Database if it does not exist
        $db_name = DB_NAME;
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $messages[] = "Database <code>{$db_name}</code> verified / created.";

        // Select the database
        $pdo->exec("USE `{$db_name}`");

        // Read and execute schema.sql
        $schema_file = __DIR__ . '/schema.sql';
        if (!file_exists($schema_file)) {
            throw new Exception("schema.sql file not found in " . __DIR__);
        }

        $sql = file_get_contents($schema_file);
        $pdo->exec($sql);
        $messages[] = "Database tables (<code>users</code>, <code>login_attempts</code>, <code>otp_codes</code>) created successfully.";

        // Seed demo user if requested
        if (!empty($_POST['seed_demo'])) {
            require_once __DIR__ . '/security.php';
            $demo_email = 'student@defense.lab';
            $demo_pass  = 'Defense2026!Secure';

            // Check if demo user already exists
            $check_stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
            $check_stmt->execute([':email' => $demo_email]);
            $existing = $check_stmt->fetch();

            if (!$existing) {
                $hash = hash_user_password($demo_pass);
                $ins_stmt = $pdo->prepare("INSERT INTO users (email, password_hash, created_at) VALUES (:email, :hash, NOW())");
                $ins_stmt->execute([':email' => $demo_email, ':hash' => $hash]);
                $messages[] = "Demo account created:<br>Email: <code>{$demo_email}</code><br>Password: <code>{$demo_pass}</code>";
            } else {
                $messages[] = "Demo account <code>{$demo_email}</code> already exists.";
            }
        }

        $installed = true;
    } catch (PDOException $e) {
        $errors[] = "Database Error: " . htmlspecialchars($e->getMessage());
    } catch (Exception $e) {
        $errors[] = "Setup Error: " . htmlspecialchars($e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Setup Wizard - Secure 2FA System</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="center-layout">
    <div class="card auth-card" style="max-width: 580px;">
        <div class="card-header text-center">
            <div class="shield-icon success"><span class="material-icons">security</span></div>
            <h2>System Setup & Migrator</h2>
            <p class="subtitle">ITP216 Endterm Project: Secure Authentication with 2FA</p>
        </div>

        <div class="card-body">
            <?php if (!empty($missing_exts)): ?>
                <div class="alert-box alert-danger">
                    <strong>Missing PHP Extensions:</strong> <?= htmlspecialchars(implode(', ', $missing_exts)) ?>. Please enable them in your php.ini.
                </div>
            <?php endif; ?>

            <?php if (!empty($errors)): ?>
                <div class="alert-box alert-danger">
                    <?php foreach ($errors as $err): ?>
                        <div><?= $err ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($messages)): ?>
                <div class="alert-box alert-success">
                    <div>
                        <strong>Installation Progress:</strong>
                        <ul style="margin-left: 1.25rem; margin-top: 0.5rem;">
                            <?php foreach ($messages as $msg): ?>
                                <li><?= $msg ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($installed): ?>
                <div class="actions mt-3">
                    <a href="login.php" class="btn btn-primary btn-block">Proceed to Secure Login</a>
                </div>
            <?php else: ?>
                <form method="POST" action="setup.php">
                    <input type="hidden" name="action" value="initialize">

                    <div class="alert-box alert-info">
                        <div>
                            <strong>Configuration Target:</strong><br>
                            Host: <code><?= htmlspecialchars(DB_HOST . ':' . DB_PORT) ?></code><br>
                            Database: <code><?= htmlspecialchars(DB_NAME) ?></code><br>
                            User: <code><?= htmlspecialchars(DB_USER) ?></code>
                        </div>
                    </div>

                    <div class="form-group">
                        <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer; color: var(--text-primary);">
                            <input type="checkbox" name="seed_demo" value="1" checked>
                            <span>Seed ready-to-use demo account (<code>student@defense.lab</code>)</span>
                        </label>
                    </div>

                    <button type="submit" class="btn btn-primary btn-block">
                        Initialize MySQL Tables & Apply Schema
                    </button>
                </form>
            <?php endif; ?>

            <div class="security-note mt-3">
                <small><strong>Security Note (ITP216 Lab 4):</strong> Once your database tables are created, you may optionally remove or restrict access to <code>setup.php</code> to prevent unauthorized schema re-initialization.</small>
            </div>
        </div>
    </div>
</body>
</html>
