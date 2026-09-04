<?php
/**
 * ==============================================================================
 * Secure Login System with Two-Factor Authentication (2FA)
 * Database Connection & PDO Abstraction
 * Course Reference: ITP216 Endterm Project
 * ==============================================================================
 * 
 * Uses PHP Data Objects (PDO) with parameterized prepared statements
 * to guarantee immunity against SQL Injection (CWE-89 / ITP216 Lab 3).
 */

require_once __DIR__ . '/config.php';

class Database {
    private static ?PDO $instance = null;

    /**
     * Get or establish the singleton PDO database connection.
     * 
     * @return PDO
     * @throws Exception if connection fails
     */
    public static function getConnection(): PDO {
        if (self::$instance === null) {
            $dsn = sprintf(
                'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                DB_HOST,
                DB_PORT,
                DB_NAME,
                DB_CHARSET
            );

            $options = [
                // Throw exceptions on SQL errors for reliable transaction handling
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                // Return associative arrays by default
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                // Crucial: Disable native emulation so MySQL performs real server-side prepares
                // This completely neutralizes SQL injection attacks
                PDO::ATTR_EMULATE_PREPARES   => false,
                // Ensure persistent connections are disabled for predictable state
                PDO::ATTR_PERSISTENT         => false,
            ];

            try {
                self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
            } catch (PDOException $e) {
                // Log the real technical error securely to server logs
                error_log('Database Connection Failure: ' . $e->getMessage());

                // Defense-in-depth: Never output the raw PDO exception to the user,
                // as it can leak database usernames, hostnames, and internal IPs (Nessus Finding).
                $error_view = self::renderConnectionError($e->getMessage());
                die($error_view);
            }
        }

        return self::$instance;
    }

    /**
     * Render a clean, non-disclosing error screen with a link to setup.php.
     */
    private static function renderConnectionError(string $internal_msg): string {
        $setup_url = 'setup.php';
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Connection Error - Secure Login System</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="center-layout">
    <div class="card auth-card">
        <div class="card-header text-center">
            <div class="shield-icon alert"><span class="material-icons">warning</span></div>
            <h2>Database Connection Required</h2>
            <p class="subtitle">Unable to connect to the configured MySQL database.</p>
        </div>
        <div class="card-body">
            <div class="alert-box alert-warning">
                <strong>Status:</strong> The application could not connect to MySQL using the credentials in <code>config.php</code>.
            </div>
            <p>If this is your first time deploying or testing the project, please run the automated setup wizard:</p>
            <div class="actions">
                <a href="{$setup_url}" class="btn btn-primary btn-block">Run Setup Wizard & Table Migrator</a>
            </div>
            <div class="security-note mt-3">
                <small><strong>Security Note (ITP216 Lab 4):</strong> Detailed connection exceptions and system paths are suppressed from public view to prevent sensitive information disclosure.</small>
            </div>
        </div>
    </div>
</body>
</html>
HTML;
    }
}

/**
 * Convenient shorthand helper to obtain the PDO instance.
 */
function get_db(): PDO {
    return Database::getConnection();
}
