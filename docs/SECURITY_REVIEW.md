# Security review: Phase 8

Reviewed on 2026-10-22 against SPEC §14 and the rules in `CLAUDE.md`. The checks were run on the code, the
configuration and the dependencies. Each finding below is marked **fixed** or **accepted**, with its evidence.

## Method

| Check | How | Result |
| --- | --- | --- |
| Shell / code execution | Search for `shell=True`, `eval(`, `exec(`, `os.system`, `pickle.load`, `yaml.load` | None found. `test_no_shell_true_anywhere_in_the_codebase` guards it |
| Passive monitoring | Search for Scapy send/probe functions (`send`, `sendp`, `sr`, `sr1`, `srp`, `arping`, …) | None found. `test_monitoring_code_is_passive_only` guards it |
| SQL injection | Review every f-string SQL statement | All values are bound as `?` parameters. f-strings only join constant column lists, placeholders or an allow-listed table name |
| HTML injection (XSS) | Review all 18 `unsafe_allow_html=True` sites | Every dynamic value passes through `html.escape`; the rest are code constants. The HTML report escapes everything (`test_html_report_escapes_everything`) |
| Secrets in git | `git ls-files` for `.env`, databases, artifacts, captures | None tracked. `.gitignore` covers them (`test_gitignore_keeps_secrets_and_data_out_of_git`) |
| Streamlit configuration | `streamlit config show` | See finding 1 |
| Dependencies | `pip-audit` | See finding 2 |
| Authentication flows | Code review plus tests | See findings 3 and 4 |
| Data exports | Code review | See finding 5 |

## Findings

### 1. Error details leaked stack traces (fixed)

`showErrorDetails = false` is deprecated, and Streamlit treats it as **"stacktrace"**. A crash during Phase 2
testing showed a full traceback with server file paths to the user.

- **Fix:** `showErrorDetails = "none"` in `.streamlit/config.toml`. Users see a generic message, and details go only to
  the server log.
- **Also:** `enableXsrfProtection = true` and `enableCORS = true` are now explicit.
- **Test:** `test_streamlit_config_hides_error_details_and_keeps_xsrf`.

### 2. Known vulnerabilities in dependencies (open: needs Python ≥ 3.10)

`pip-audit` reports **60 advisories**: pillow (41), urllib3 (5), pip (4), streamlit (2), filelock (2), and one each in
requests, python-dotenv, pyarrow, pytest, msgpack and setuptools. Almost all are transitive.

- **Why they can't be fixed now:** every fixed release requires **Python 3.10 or newer**. This machine runs Python
  3.9.6, which reached end of life in October 2025. For example, `pip index versions urllib3` shows 2.6.3 as the newest
  release available for 3.9.
- **Done on 3.9:** pip and setuptools were upgraded as far as 3.9 allows.
- **Recommendation:** install Python 3.11 or 3.12, recreate `.venv`, run `pip install -r requirements.txt`, and re-run
  `pip-audit` and `pytest -q`. The code uses nothing specific to 3.9.
- **Interim risk:** moderate. The app is meant for a local lab, most advisories concern image or HTTP-client
  parsing of untrusted input the app does not process, and Streamlit's advisories should be checked once upgraded.

### 3. No way to change a password (fixed)

Users could not change their own password, and an operator had no recovery path for a locked or forgotten admin.

- **Fix:** a **My account** page with password change. It requires the current password; wrong attempts count toward
  the sign-in lockout; the policy is enforced and the change is audited.
- **Recovery:** `python -m scripts.manage reset-password --email …` for operators. The password is prompted, never
  passed as an argument, and the reset clears the lockout. There is deliberately no web route for this.
- **Tests:** `test_change_password_*`, `test_wrong_current_password_counts_toward_lockout`,
  `test_cli_reset_password_clears_lockout`.

### 4. Lockout can lock out a known user (accepted)

Lockout is keyed by email, because Streamlit does not expose client IPs. An attacker who knows an address can keep it
locked for 15 minutes at a time. This is accepted for a lab tool: the alternative (no lockout) is worse. Admins see
these attempts in the audit log (`auth.login` denied). For deployment, put the app behind a reverse proxy with IP
rate limiting.

### 5. CSV/formula injection in exports (fixed before shipping)

Exports include user-supplied text such as alert reasons, notes and dataset names. A cell starting with `=`, `+`, `-`,
`@`, a tab or a carriage return would run as a formula in a spreadsheet.

- **Fix:** `reporting_service.safe_cell` prefixes these cells with an apostrophe.
- **Test:** `test_csv_export_neutralises_formulas`.

### 6. Capture worker re-ran the app (fixed in Phase 7)

With the `spawn` start method, the worker re-imported `app.py` and ran the app's startup code. This closed live sessions
and ran page code in a background process.

- **Fix:** `start_without_main_reimport`.
- **Test:** `test_spawned_worker_does_not_rerun_the_parent_main_script` uses a real spawned process. It was verified to
  fail without the fix.

## Controls confirmed in place

- **Passwords:** argon2id hashing, rehashed when parameters change, with a policy (10–128 characters, upper, lower,
  digit) and generic sign-in errors. A dummy hash check keeps the timing the same for unknown emails.
- **Accounts:** no default admin; the first registration becomes admin inside `BEGIN IMMEDIATE`; the last active
  admin cannot be demoted, deactivated or deleted (service check plus database trigger).
- **Authorization:** checked in services (`require_permission`), and every denial is audited. When signed out, only
  the login page is registered.
- **Database:** parameterized SQL, CHECK constraints, foreign keys, WAL, and transactions for every write.
- **Model loading:** only registered artifacts inside the artifact directory whose SHA-256 matches are loaded. A failed
  training run never replaces the active model.
- **Uploads:** size and row limits, strict validation, and files stored by hash. Deleting a dataset only removes files
  inside the dataset directory.
- **Traffic shaping:**
  - It is off by default, Linux only, allow-listed, admin-only, and requires typed confirmation.
  - It runs fixed argv lists only; interface names and rates are validated.
  - It is audited and reversible.
- **Monitoring:** passive only; interfaces are authorised by an admin, with nothing allowed by default; queues are
  bounded and storage is capped.
- **Retention:** off by default, admin-only, with a dry-run preview; audit logs are kept for at least 365 days; open
  alerts and incidents are never deleted.

## Residual risks and deployment notes

- **No TLS:** Streamlit serves plain HTTP. For anything beyond localhost, put it behind a TLS reverse proxy
  (nginx/Caddy) with authentication-friendly rate limiting.
- **Sessions:** they live in server memory per browser tab, and there is no "sign out everywhere".
- **Model artifacts:** they are pickles (joblib). The hash check stops tampering after registration, but anyone with
  write access to both the database and the artifact folder could register a malicious model. Protect the server's
  filesystem.
- **Error messages:** messages shown to signed-in users can include exception text (e.g. file-format errors). They
  contain no tracebacks, but they are not fully generic.
