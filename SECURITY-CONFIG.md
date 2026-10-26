# Private configuration

Credentials previously committed to this repository must be revoked or rotated at their providers. Removing them from current files does not remove them from Git history.

Set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`, `SMTP_REPLY_TO_EMAIL`, and `SMTP_REPLY_TO_NAME` in the server environment. Alternatively set `ITP_CONFIG_FILE` to an absolute PHP file outside the web root returning an array with those keys. The default is `itp216.private.php` in the parent of the application directory; ensure that directory is outside the web root.

Environment values take precedence, including deliberately empty values. Give private configuration files permission 0600 and never commit or upload them into a public directory. Missing credentials disable OAuth/SMTP without enabling demo authentication.
