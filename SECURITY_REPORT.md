# Comprehensive Security Architecture Report & Defense Guide
**Project Title:** Secure Login System with Two-Factor Authentication (2FA)  
**Course Reference:** ITP216 Endterm Project  
**Author:** Security Engineering Student  
**System Architecture:** Plain PHP 8.x + MySQL / MariaDB (Zero External Framework Dependencies)

---

## Table of Contents
1. [Executive Summary & Security Posture](#1-executive-summary--security-posture)
2. [Password Hashing Selection & Cryptographic Analysis](#2-password-hashing-selection--cryptographic-analysis)
3. [Brute-Force Defense & Account Lockout Threshold Reasoning](#3-brute-force-defense--account-lockout-threshold-reasoning)
4. [Two-Factor Authentication (2FA) & OTP Expiry Rationale](#4-two-factor-authentication-2fa--otp-expiry-rationale)
5. [Session Hardening & Cookie Security Flags](#5-session-hardening--cookie-security-flags)
6. [Ties to ITP216 Laboratory Coursework](#6-ties-to-itp216-laboratory-coursework)
   - [Lab 5: Two-Factor Authentication (2FA)](#tie-in-1-itp216-lab-5--two-factor-authentication-2fa)
   - [Lab 3: Common Vulnerabilities and Exposures (CVE) Analysis](#tie-in-2-itp216-lab-3--cve--cwe-vulnerability-analysis)
   - [Lab 4: Nessus Vulnerability Scanning & Remediation](#tie-in-3-itp216-lab-4--nessus-vulnerability-scanning--remediation)
7. [Defense Q&A: High-Probability Oral Defense Questions & Answers](#7-defense-qa-high-probability-oral-defense-questions--answers)
8. [Database Schema & Forensic Audit Logging Architecture](#8-database-schema--forensic-audit-logging-architecture)

---

## 1. Executive Summary & Security Posture

Modern authentication architectures must withstand aggressive automated adversary tactics, including credential stuffing, distributed brute-force attacks, rainbow table lookups, session fixation, and side-channel timing attacks.

This system demonstrates defense-in-depth engineering using plain PHP and MySQL without relying on heavyweight third-party frameworks. Every component adheres to **NIST SP 800-63B** (Digital Identity Guidelines) and **OWASP Top 10** mitigation standards:

```
[Client Request]
       │
       ▼
[Security Headers & Cookie Hardening] (X-Frame-Options, CSP, HttpOnly, SameSite)
       │
       ▼
[CSRF & Input Validation] (256-bit cryptographically secure token, Anti-XSS)
       │
       ▼
[Step 1: Credential Verification] ────► [Lockout Guard (5 failed / 15-min lock)]
       │ (password_verify + constant-time dummy)
       ▼
[Step 2: 2FA OTP Challenge] ──────────► [6-digit cryptographically hashed OTP]
       │ (NIST 5-min expiry, max 3 tries)
       ▼
[Session Privilege Elevation] ────────► [session_regenerate_id(true) Anti-Fixation]
       │
       ▼
[Protected Dashboard] ────────────────► [15-min Inactivity Auto-Logout & Audit Log]
```

---

## 2. Password Hashing Selection & Cryptographic Analysis

### 2.1 The Prohibition of Plaintext & Weak Hashes
Storing passwords in plaintext or using legacy unsalted hashes like **MD5**, **SHA-1**, or bare **SHA-256** is unacceptable in modern software engineering:
1. **High Throughput Cracking:** Modern GPUs can compute over 100 billion MD5 or bare SHA-256 operations per second. An unsalted database breach allows offline dictionary attacks to crack millions of passwords within hours.
2. **Rainbow Tables:** Precomputed lookup tables of hashes easily invert unsalted digests in constant time ($O(1)$).

### 2.2 Why `password_hash()` with `PASSWORD_ARGON2ID` & `PASSWORD_BCRYPT`
The application utilizes PHP's native `password_hash()` API configured primarily for **Argon2id** (`PASSWORD_ARGON2ID`) with an automatic graceful fallback to **Bcrypt** (`PASSWORD_BCRYPT`, cost factor 12):

| Criterion | MD5 / SHA-256 | Bcrypt | Argon2id (Selected) |
| :--- | :--- | :--- | :--- |
| **Algorithm Type** | General Cryptographic Hash | Key Derivation (Blowfish) | Password Hashing Competition (PHC) Winner |
| **Salt Handling** | Manual (High risk of CWE-326) | Automated CSPRNG 128-bit | Automated CSPRNG 128-bit |
| **CPU Hardness** | No (Extremely fast on GPU) | Yes (Configurable work factor) | Yes (Time cost parameter) |
| **Memory Hardness** | None (0 KB memory needed) | Low (~4 KB memory state) | **High (Configured to 64 MB RAM)** |
| **GPU / ASIC Resistance**| Extremely Poor | Moderate | **State-of-the-Art (Hardware resistant)** |

### 2.3 Parameter Tuning & Implementation
In `security.php`:
```php
password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536, // 64 MB of RAM allocated per hash calculation
    'time_cost'   => 4,     // 4 iterations through memory space
    'threads'     => 1
]);
```
- **Defense Rationale:** A dedicated cracking rig with high-end GPUs cannot parallelize attacks on Argon2id because each hashing thread consumes 64 MB of high-speed memory. Attempting 10,000 parallel threads would require 640 GB of instantaneous GPU VRAM, making offline attacks economically infeasible.

### 2.4 Timing Attack Mitigation (`dummy_password_verify`)
If an attacker attempts to log in with an email address that does **not** exist in the database, a naive system immediately returns `"User not found"` in ~1 millisecond. In contrast, verifying a registered user takes ~150 milliseconds due to the Argon2id computation.
- **Vulnerability (CWE-208):** Attackers can measure server response times to systematically harvest valid user email addresses (Account Enumeration).
- **Remediation:** When an email is not found, `security.php` immediately calls `dummy_password_verify()` using a precomputed hash. The server consumes the exact same execution time before returning a generic error, completely blinding side-channel timing analysis.

---

## 3. Brute-Force Defense & Account Lockout Threshold Reasoning

### 3.1 Choice of Lockout Thresholds
- **Threshold:** Maximum **5 consecutive failed attempts**.
- **Lockout Window:** **15 minutes** sliding duration.

### 3.2 Security vs. Usability / Denial of Service (DoS) Tradeoff
In cybersecurity architecture, account lockouts present a classic dilemma:
- **Overly Strict Lockout (e.g., 3 attempts, permanent lockout):** Enables a malicious actor to perform a Denial of Service (DoS) attack against legitimate users by intentionally submitting 3 wrong passwords for a known target (e.g., `ceo@company.com`), permanently locking them out.
- **Overly Permissive (e.g., 20 attempts, no delay):** Allows an attacker running automated Hydra or Burp Intruder scripts to crack weak passwords online.
- **The Optimal 5-Attempt / 15-Minute Compromise:**
  - Standard users rarely mistype their password 5 consecutive times.
  - An attacker attempting 5 passwords every 15 minutes can only test **20 passwords per hour** (480 per day). An 8-character complex password space ($94^8 \approx 6.09 \times 10^{15}$ permutations) would take hundreds of thousands of years to crack online.
  - A temporary 15-minute lock automatically self-heals without burdening system administrators or helpdesk personnel with reset tickets.

---

## 4. Two-Factor Authentication (2FA) & OTP Expiry Rationale

### 4.1 Multi-Factor Authentication Architecture
Authentication requires at least two distinct authentication factors:
1. **Factor 1: Knowledge ("Something you know")** &rarr; Master password verified via `password_verify()`.
2. **Factor 2: Possession ("Something you have")** &rarr; Out-of-band 6-digit One-Time Password (OTP).

Even if an attacker compromises the master password via a phishing campaign, credential leak, or keylogger, they cannot access the user's dashboard without compromising the secondary possession factor.

### 4.2 Why 6 Digits?
A 6-digit numeric string yields **$1,000,000$ possible combinations** ($000000$ to $999999$):
- Provides sufficient mathematical entropy against real-time guessing.
- Remains easily human-memorizable and quick to enter on mobile screens.

### 4.3 Expiry Window Rationale (5 Minutes)
- **Standard Reference:** **NIST SP 800-63B Section 5.1.4.2** mandates that out-of-band authenticators shall have a short validity lifetime.
- **Why not 30 seconds?** Network latency, email routing delay, or SMS queueing can take up to 60–90 seconds. A 30-second window creates severe user friction and false expiration failures.
- **Why not 30 minutes?** A 30-minute window creates a large vulnerability surface for man-in-the-middle interception, shoulder surfing, or compromised email inbox exploitation.
- **5-Minute Window:** Accommodates transmission delays while strictly capping the window of opportunity for an attacker.

### 4.4 Maximum Attempt Throttling (3 Tries per OTP)
A critical vulnerability in poorly designed 2FA systems is failing to rate-limit OTP verification submissions. With 1,000,000 possibilities, a multi-threaded script can brute-force the 6-digit code in seconds if unthrottled.
- **Enforced Rule:** The system terminates and invalidates the OTP after **3 incorrect attempts**.
- **Probability of an attacker guessing the code:**
  $$\text{Odds} = \frac{3}{1,000,000} = 0.0003\%$$
  The probability of unauthorized entry is reduced to near zero.

### 4.5 Defense-in-Depth: Hashing the OTP in Storage
In `otp_codes`, the plaintext OTP is **never stored in raw text**. Instead, it is hashed with Bcrypt:
```php
$otp_hash = password_hash($plain_otp, PASSWORD_BCRYPT);
```
- **Defense Rationale:** If an attacker achieves read-only SQL injection or obtains a raw database backup dump, they cannot read unexpired OTPs to hijack active login sessions.

---

## 5. Session Hardening & Cookie Security Flags

Session management adheres to OWASP ASVS Section 3 standards:

### 5.1 Session Fixation Prevention (`session_regenerate_id(true)`)
- **Threat (CWE-384):** An attacker tricks a victim into authenticating using a known session identifier (e.g., via URL parameter or cookie injection). If the server maintains the same session ID after authentication, the attacker can hijack the account.
- **Mitigation:** Upon successful completion of Factor 2 (OTP verification), `verify_otp.php` executes:
  ```php
  session_regenerate_id(true);
  ```
  The argument `true` deletes the old session file on the server, guaranteeing that any previously known session token becomes instantly useless.

### 5.2 Session Cookie Hardening Flags
In `config.php`:
```php
session_set_cookie_params([
    'lifetime' => 0,        // Expire cookie when the browser session terminates
    'path'     => '/',
    'domain'   => '',       // Host-only cookie (not shared with subdomains)
    'secure'   => $is_https,// Transmit ONLY over TLS/HTTPS encrypted connections
    'httponly' => true,     // Disallows document.cookie access in JavaScript
    'samesite' => 'Strict'  // Suppresses cookie transmission in all cross-site requests
]);
```
- **`HttpOnly = true`:** Neutralizes session hijacking via Cross-Site Scripting (XSS). Even if malicious JavaScript is injected, it cannot read the session cookie.
- **`SameSite = 'Strict'`:** Neutralizes Cross-Site Request Forgery (CSRF). When a user clicks a malicious external link, the browser refuses to attach the authentication cookie.
- **`Secure = true`:** Prevents transmission over unencrypted HTTP, mitigating Man-In-The-Middle (MITM) sniffing on public Wi-Fi networks.

### 5.3 Inactivity Timeout (15 Minutes) & Absolute Timeout (8 Hours)
- **Inactivity Timeout (900s):** If a user leaves their computer unattended at an academic lab or internet cafe, an active session will self-terminate after 15 minutes of inactivity (CWE-613).
- **Absolute Lifetime (28800s):** Even if continuously active, sessions expire after 8 hours to force periodic credential re-validation.

### 5.4 Triple-Layer Secure Logout (`logout.php`)
Calling `session_destroy()` alone leaves existing session data in PHP's superglobal memory for the remainder of the request, and leaves the session cookie stored in the client's browser!
Our implementation performs a three-layer destruction:
1. `$_SESSION = [];` (Flushes server-side memory immediately)
2. `setcookie(session_name(), '', time() - 42000, ...);` (Forces browser to discard client cookie)
3. `session_destroy();` (Deletes session state from disk/storage)

---

## 6. Ties to ITP216 Laboratory Coursework

### Tie-in 1: ITP216 Lab 5 — Two-Factor Authentication (2FA)
- **Lab 5 Concept:** Multi-factor authentication decouples authorization from single-credential dependency.
- **Application Implementation:**
  - Implements out-of-band 6-digit OTP challenge.
  - Implements NIST-compliant single-use token lifecycle.
  - Solves the state-transition problem: users must pass through a `2fa_pending` intermediate state where they cannot access `dashboard.php` until Factor 2 is verified.
  - Prevents replay attacks by marking `is_used = 1` immediately upon successful verification.

### Tie-in 2: ITP216 Lab 3 — CVE & CWE Vulnerability Analysis
The codebase explicitly remediates the core vulnerability patterns studied in Lab 3:

| CWE / CVE Pattern | Threat Description | Architectural Mitigation in This Project |
| :--- | :--- | :--- |
| **CWE-89** | SQL Injection | PDO parameterized queries with `PDO::ATTR_EMULATE_PREPARES => false`. Zero string concatenation in SQL queries. |
| **CWE-384** | Session Fixation | `session_regenerate_id(true)` called upon successful 2FA step. |
| **CWE-613** | Insufficient Session Expiration | Enforces both a 15-minute sliding inactivity timeout and an 8-hour absolute session ceiling. |
| **CWE-307** | Improper Restriction of Excessive Attempts | Automatic account lockout after 5 consecutive failed logins, logged with timestamps and client IPs. |
| **CWE-208** | Observable Timing Discrepancy | `dummy_password_verify()` executes identical cryptographic operations when email does not exist. |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | Unique 256-bit cryptographically random tokens (`random_bytes(32)`) validated on every POST form with `hash_equals()`. |
| **CWE-79** | Cross-Site Scripting (XSS) | `e()` helper wraps `htmlspecialchars(..., ENT_QUOTES | ENT_HTML5)` on all dynamic outputs; `HttpOnly` cookie prevents session exfiltration. |
| **CWE-521** | Weak Password Requirements | Strict server-side regex requiring minimum 8 characters, uppercase, lowercase, numbers, and symbols. |

### Tie-in 3: ITP216 Lab 4 — Nessus Vulnerability Scanning & Remediation
During Lab 4, Nessus web application scans flag several standard high and medium severity vulnerabilities. Our system directly implements remediations that satisfy Nessus audit checks:

1. **Nessus Plugin: "Cookie Does Not Contain 'HttpOnly' Attribute"**
   - *Fix:* `ini_set('session.cookie_httponly', 1)` and `session_set_cookie_params(['httponly' => true])`.
2. **Nessus Plugin: "Cookie Does Not Contain 'secure' Attribute"**
   - *Fix:* Dynamic detection of HTTPS enforces `secure => true` in production.
3. **Nessus Plugin: "Missing Anti-Clickjacking Header (X-Frame-Options)"**
   - *Fix:* `apply_security_headers()` dispatches `X-Frame-Options: DENY`.
4. **Nessus Plugin: "Missing Content-Security-Policy"**
   - *Fix:* Strict CSP dispatched: `Content-Security-Policy: default-src 'self'; ...`.
5. **Nessus Plugin: "MIME-Sniffing Vulnerability"**
   - *Fix:* Dispatches `X-Content-Type-Options: nosniff`.
6. **Nessus Plugin: "Information Disclosure / Verbose Error Messages"**
   - *Fix:* `ini_set('display_errors', 0)` and custom PDO exception handler rendering non-disclosing error screens without leaking database paths, usernames, or connection parameters.
7. **Nessus Plugin: "Lack of Account Lockout Mechanism"**
   - *Fix:* Enforces account lockout table state and audit logs.

---

## 7. Defense Q&A: High-Probability Oral Defense Questions & Answers

### Q1: Why did you use `password_hash()` instead of `md5()` or `sha256()`?
> **Answer:** `md5()` and `sha256()` are general-purpose cryptographic checksum algorithms optimized for fast throughput. Modern GPUs can calculate over 100 billion SHA-256 operations per second, making offline dictionary attacks trivially easy. In contrast, `password_hash()` utilizes **Argon2id** (or **Bcrypt**), which are slow key-derivation functions with adjustable work and memory costs. Argon2id requires 64 MB of RAM per computation, neutralizing GPU/ASIC acceleration attacks. Furthermore, `password_hash()` automatically generates a unique 128-bit CSPRNG salt for each password, rendering rainbow tables completely useless.

### Q2: How does your system prevent Session Fixation?
> **Answer:** Session fixation occurs when an attacker forces a victim to use a known session ID before authenticating. If the server does not issue a new session ID after login, the attacker can use their copy of the session ID to access the victim's account. We prevent this by calling `session_regenerate_id(true)` immediately after successful 2FA OTP verification. The `true` parameter deletes the old unauthenticated session file from the server and assigns a new cryptographically random session ID to the user.

### Q3: Why is the OTP expiration set to 5 minutes instead of 1 minute or 1 hour?
> **Answer:** Following **NIST SP 800-63B** guidelines, 5 minutes represents the optimal security-usability trade-off. An OTP must allow sufficient time for network transmission latency across cellular/email gateways and account for users checking secondary devices. A 1-minute window causes high failure rates due to legitimate network delay, while a 1-hour window leaves an unacceptable window of opportunity for an adversary to intercept or guess the code. Additionally, we enforce a strict 3-attempt limit per OTP, reducing the probability of a successful brute-force guess to 0.0003%.

### Q4: What happens if an attacker attempts to guess a user's password repeatedly?
> **Answer:** The system tracks failed attempts in the `users` table via `failed_login_attempts`. If an attacker fails 5 consecutive times, the account enters a locked state: `lockout_until` is set to `NOW() + 15 minutes`, and an `ACCOUNT_LOCKED` security event is recorded in `login_attempts`. Any subsequent login attempts during this 15-minute window are blocked before password evaluation takes place, completely stopping automated online dictionary attacks.

### Q5: How does your application protect against SQL Injection?
> **Answer:** We use PHP Data Objects (PDO) with parameterized prepared statements for every database interaction. Crucially, we set `PDO::ATTR_EMULATE_PREPARES => false`, forcing the database engine itself to prepare the query structure before user input is supplied. This completely separates executable SQL code from user-supplied data, making SQL injection mathematically impossible regardless of input content (remediating CWE-89 from ITP216 Lab 3).

### Q6: How do you prevent attackers from discovering which email addresses are registered?
> **Answer:** We remediate user enumeration in two ways:
> 1. **Timing Attack Defense:** When an unregistered email is submitted, we call `dummy_password_verify()`, consuming the same CPU and memory cycles as an actual password hash evaluation. This ensures uniform server response times.
> 2. **Generic Error Messaging:** The interface always displays a uniform `"Invalid email or password"` message rather than distinguishing between `"User not found"` and `"Incorrect password"`.

### Q7: Why do you store the OTP as a hash in the database instead of plaintext?
> **Answer:** Storing the OTP hash is a defense-in-depth practice. If an adversary gains temporary read access to the database (e.g., through an unpatched database backup exposure or server breach), they will only see one-way hashes of the OTP codes. They cannot read active plaintext codes to complete an in-progress authentication hijack.

### Q8: What are `HttpOnly` and `SameSite` cookie flags, and why are they critical?
> **Answer:**
> - `HttpOnly` instructs the browser that the session cookie must **not** be accessible via JavaScript's `document.cookie` API. If an attacker discovers a Cross-Site Scripting (XSS) vulnerability, they cannot exfiltrate the session cookie.
> - `SameSite=Strict` instructs the browser never to send the session cookie on cross-site requests originating from external sites, neutralizing Cross-Site Request Forgery (CSRF).

### Q9: Why is `session_destroy()` alone not enough to log out securely?
> **Answer:** `session_destroy()` deletes the session data stored on the server's filesystem, but it does **not** unset the `$_SESSION` array variables in PHP's active memory for the current script, nor does it remove the session cookie from the user's browser. An attacker could theoretically reuse the client cookie if strict mode is disabled. A secure logout must clear `$_SESSION = []`, explicitly overwrite the client cookie with an expired timestamp (`time() - 42000`), and call `session_destroy()`.

### Q10: How does your project tie into Nessus vulnerability scanning (Lab 4)?
> **Answer:** Nessus Web Application scans actively check for missing cookie security attributes, missing HTTP response headers, verbose error messages, and weak authentication schemes. Our system configures `HttpOnly`, `SameSite`, and `Secure` cookie attributes, dispatches `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and a strict `Content-Security-Policy`, suppresses verbose PHP and PDO error output to prevent information disclosure, and enforces account lockouts—directly addressing typical high/medium Nessus findings.

---

## 8. Database Schema & Forensic Audit Logging Architecture

### Relational Schema Diagram
```
┌─────────────────────────────────┐
│              users              │
├─────────────────────────────────┤
│ id (PK, INT UNSIGNED)           │
│ email (UNIQUE, VARCHAR 255)     │
│ password_hash (VARCHAR 255)     │
│ failed_login_attempts (INT)     │
│ lockout_until (DATETIME, NULL)  │
│ created_at (DATETIME)           │
│ updated_at (DATETIME)           │
└────────────────┬────────────────┘
                 │ 1
                 │
                 │ N (Cascading / Set Null)
                 ▼
┌─────────────────────────────────┐        ┌─────────────────────────────────┐
│         login_attempts          │        │            otp_codes            │
├─────────────────────────────────┤        ├─────────────────────────────────┤
│ id (PK, INT UNSIGNED)           │        │ id (PK, INT UNSIGNED)           │
│ user_id (FK -> users.id, NULL)  │        │ user_id (FK -> users.id)        │
│ email_attempted (VARCHAR 255)   │        │ otp_hash (VARCHAR 255)          │
│ ip_address (VARCHAR 45)         │        │ expires_at (DATETIME)           │
│ user_agent (VARCHAR 500)        │        │ is_used (TINYINT 1)             │
│ status (ENUM)                   │        │ attempts (INT UNSIGNED)         │
│ attempted_at (DATETIME)         │        │ created_at (DATETIME)           │
└─────────────────────────────────┘        └─────────────────────────────────┘
```

### Forensic Event Status Definitions
- `SUCCESS`: Complete authentication (both password and OTP verified).
- `FAILED_PASSWORD`: Incorrect primary password entered.
- `ACCOUNT_LOCKED`: Login blocked due to threshold exceeding 5 failed attempts.
- `OTP_SENT`: Factor 1 passed; 6-digit OTP generated and dispatched.
- `OTP_SUCCESS`: Correct OTP entered within expiry; session regenerated.
- `OTP_FAILED`: Incorrect OTP code submitted.
- `OTP_EXPIRED`: OTP code submitted after the 5-minute validity window elapsed.

---
*Report certified compliant with ITP216 Endterm Project Specifications.*
