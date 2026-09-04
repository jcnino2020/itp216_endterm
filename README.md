# Secure Login System with Two-Factor Authentication (2FA)

**Course:** ITP216 Endterm Project  
**Tech Stack:** Native PHP 8.x, MySQL / MariaDB, Vanilla CSS3 (Zero Framework Dependencies)  
**Security Standard Compliance:** NIST SP 800-63B, OWASP Top 10, ASVS v4.0

---

## 📁 Project File Structure

```text
itp216_endterm/
├── assets/
│   └── css/
│       └── style.css            # Cyber defense dark-mode design system & glassmorphic UI
├── config.php                   # Security parameters, session hardening, & HTTP headers
├── db.php                       # PDO database singleton with prepared statements
├── security.php                 # Cryptographic helpers, CSRF, 2FA engine, lockout tracking
├── schema.sql                   # MySQL database schema (users, login_attempts, otp_codes)
├── setup.php                    # 1-Click database installer & demo account migrator
├── register.php                 # User registration with password hashing & complexity rules
├── login.php                    # Factor 1 verification, brute-force guard, timing defense
├── verify_otp.php               # Factor 2 (6-digit OTP), session fixation defense, countdown
├── dashboard.php                # Protected area, session inactivity monitor, audit log table
├── logout.php                   # Triple-layer session and cookie destruction
├── index.php                    # Application router / entry point
├── SECURITY_REPORT.md           # Academic defense report & ITP216 Lab 3/4/5 tie-ins
└── README.md                    # Deployment guide & walkthrough documentation
```

---

## 🚀 Quickstart & Setup Guide

### Step 1: Database Setup
1. Ensure your MySQL / MariaDB server is running.
2. In `config.php`, confirm or update your database credentials (default: host `127.0.0.1`, user `root`, password ``, database `itp216`).
3. You can import `schema.sql` directly via MySQL CLI or phpMyAdmin:
   ```bash
   mysql -u root -p < schema.sql
   ```
   **OR** simply open `http://localhost:8000/setup.php` in your browser to run the **1-click automated setup wizard**, which creates the database, all tables, and an optional ready-to-use demo account (`student@defense.lab` / `Defense2026!Secure`).

### Step 2: Start PHP Built-in Server
From the project root directory:
```bash
php -S localhost:8000
```
Open your browser at:
```text
http://localhost:8000
```

---

## 🛡️ Core Requirements Verification Matrix

| Requirement | Implementation File | Verification & Defense Details |
| :--- | :--- | :--- |
| **1. Registration & Hashing** | `register.php`<br>`security.php` | Passwords hashed using `password_hash()` with `PASSWORD_ARGON2ID` (or `PASSWORD_BCRYPT` fallback). Enforces >= 8 chars, uppercase, lowercase, numbers, and symbols. Plaintext is never stored. |
| **2. Login System** | `login.php` | Credentials verified via `password_verify()`. Constant-time dummy verification (`dummy_password_verify()`) defeats user enumeration timing attacks. |
| **3. Two-Factor Authentication** | `verify_otp.php`<br>`security.php` | Generates 6-digit cryptographically random OTP. Single-use token, 5-minute expiry, max 3 tries before code invalidation. OTPs are hashed in DB. Includes simulated on-screen banner for demo. |
| **4. Brute-Force Defense** | `login.php`<br>`security.php` | Tracks `failed_login_attempts`. Account locked for 15 minutes upon 5 consecutive failures. Logs `ACCOUNT_LOCKED` security events. |
| **5. Session Security** | `config.php`<br>`dashboard.php`<br>`logout.php` | Cookies hardened with `HttpOnly=true`, `SameSite=Strict`, `Secure=true`. `session_regenerate_id(true)` called upon 2FA success. Auto-logout after 15 minutes of idle time. Triple-layer logout. |
| **6. Audit Logging** | `login_attempts`<br>`dashboard.php` | Real-time logging of all authentication events (`SUCCESS`, `FAILED_PASSWORD`, `ACCOUNT_LOCKED`, `OTP_SENT`, `OTP_SUCCESS`, `OTP_FAILED`, `OTP_EXPIRED`) with client IP and User-Agent. |

---

## 📚 Academic Defense & Laboratory Tie-Ins
Refer to [`SECURITY_REPORT.md`](SECURITY_REPORT.md) for full academic details:
- **ITP216 Lab 5 (2FA):** Out-of-band verification, entropy analysis, single-use token lifecycle.
- **ITP216 Lab 3 (CVE Analysis):** Mitigation of CWE-89 (SQLi), CWE-384 (Session Fixation), CWE-613 (Session Expiration), CWE-307 (Brute Force), CWE-208 (Timing Attacks), CWE-352 (CSRF), CWE-79 (XSS).
- **ITP216 Lab 4 (Nessus Scanning):** Mitigation of missing cookie flags (`HttpOnly`/`Secure`), missing HTTP headers (`X-Frame-Options`, CSP, `nosniff`), and verbose information disclosure.
- **Defense Q&A:** Includes 10 high-probability instructor questions and answers.
