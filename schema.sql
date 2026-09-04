-- ==============================================================================
-- Secure Login System with Two-Factor Authentication (2FA)
-- Database Schema for MySQL / MariaDB
-- Course Reference: ITP216 Endterm Project
-- ==============================================================================

-- Create Database if not exists
CREATE DATABASE IF NOT EXISTS `itp216` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `itp216`;

-- ------------------------------------------------------------------------------
-- Table 1: users
-- Stores registered accounts, secure password hashes, and brute-force lockout states.
-- Security Note:
-- - Plaintext passwords are NEVER stored. Only one-way cryptographic hashes (Argon2id/Bcrypt).
-- - failed_login_attempts & lockout_until track state to enforce account locking.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `email` VARCHAR(255) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `failed_login_attempts` INT UNSIGNED NOT NULL DEFAULT 0,
    `lockout_until` DATETIME NULL DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uk_users_email` (`email`),
    INDEX `idx_users_lockout` (`lockout_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- Table 2: login_attempts
-- Comprehensive security audit log recording every authentication event.
-- Security Note:
-- - Essential for post-incident forensics, CVE analysis, and intrusion detection.
-- - Captures successful logins, failed passwords, account lockouts, and OTP outcomes.
-- - Stores IP address (IPv4 or IPv6) and User-Agent header for anomaly detection.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `login_attempts` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NULL DEFAULT NULL,
    `email_attempted` VARCHAR(255) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(500) NULL DEFAULT NULL,
    `status` ENUM(
        'SUCCESS',
        'FAILED_PASSWORD',
        'ACCOUNT_LOCKED',
        'OTP_SENT',
        'OTP_SUCCESS',
        'OTP_FAILED',
        'OTP_EXPIRED'
    ) NOT NULL,
    `attempted_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_attempts_email` (`email_attempted`),
    INDEX `idx_attempts_ip` (`ip_address`),
    INDEX `idx_attempts_time` (`attempted_at`),
    CONSTRAINT `fk_login_attempts_user`
        FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- Table 3: otp_codes
-- Manages short-lived, single-use Two-Factor Authentication codes.
-- Security Note:
-- - Ties directly to ITP216 Lab 5 (2FA Out-of-band verification).
-- - otp_hash: Storing hashed OTPs provides defense-in-depth against database leaks.
-- - expires_at: Hard timeout (e.g. 5 minutes) limits the window of replay/interception.
-- - is_used: Enforces single-use token semantics.
-- - attempts: Throttles verification attempts (e.g. max 3 tries per code) to mitigate brute force.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `otp_codes` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `otp_hash` VARCHAR(255) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `is_used` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
    `attempts` INT UNSIGNED NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_otp_user_active` (`user_id`, `is_used`, `expires_at`),
    CONSTRAINT `fk_otp_codes_user`
        FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
