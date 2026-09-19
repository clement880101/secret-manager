# Changelog

## v0.7.3

**Key rotation silently skipped secrets and made them unreadable.** Rotating
1200 secrets in batches of 500 left 500 of them on the old key while reporting
that it had examined all 1200. Dropping the retired key then made those 500
permanently unrecoverable — in the procedure whose entire purpose is to prevent
that.

The cause was paging with `OFFSET` and no `ORDER BY`. Rewriting a row writes a
new tuple, which moves it, so later pages skipped rows earlier pages had pushed
past. It now pages by primary key, which does not move, and counts what is left
afterwards rather than assuming. It exits non-zero if anything remains.


Client errors read as messages rather than crashes. Sharing a secret you did
not own answered 400, which no command handled, so the CLI printed a
PyInstaller traceback instead of "Secret not found for owner". Every command
now shows what the server said.

The security behaviour was already correct -- the share was refused, and the
third party could not read the secret. Only the reporting was broken.

## v0.7.2

Three bugs, all found by testing a published build rather than reading the
code.

**Sharing with a name that does not exist used to succeed.** It created the
account on the spot, so a typo looked like it had worked: the secret was shared
with a name nobody held, and whoever registered that name next would inherit
it. The recipient has to exist now, and a typo says so.

Two more that let you store a secret you could never read back.

- **A key containing `/` was accepted and then unreachable.** The route treats
  the key as one path segment, so the secret was created, appeared in `list`,
  and could not be read or deleted — it stayed there permanently. Such keys are
  now refused with a message saying why.
- **The CLI did not percent-encode the key in the URL**, so a key containing
  `?`, `#` or `%` had the same outcome through the CLI even though the server
  handled it correctly when encoded.

Both were found by testing unusual keys against a published build rather than
by reading the code. Every key that can survive a URL round trip still works,
including spaces, unicode, dots, colons, `?`, `#` and `%`.

A rejected key or an oversized value now prints an explanation instead of a
Python traceback.

## v0.7.1

Removed the AWS deployment entirely. `terraform/`, the ECS deploy job, and the
AWS credentials and variables that lived in repository settings are gone: the
account they pointed at was not this project's. CI builds and tests; it deploys
nowhere. The GitHub OAuth secrets and the `BACKEND_URL` variable went too,
unused since GitHub sign-in was removed.


**Breaking, and deliberately so.** `BACKEND_URL` is now required.

The CLI shipped with a default pointing at the project's own AWS deployment,
over plain HTTP. Anyone who downloaded the binary and ran it without reading
the docs sent their access token and secret values to a server belonging to
someone else. For a tool you are expected to self-host, the address has to be a
decision rather than a fallback.

Running any command without it now explains what to set and how to start a
deployment, and exits 2. `--help` and `version` still work without it.

## v0.7.0

Closes the gaps that stood between this and a production deployment.

- **Key rotation.** `SECRET_ENCRYPTION_KEYS_RETIRED` holds previous keys for
  decryption while the current one encrypts, and `rotate_keys.py` re-encrypts
  what is left. A rotation now takes two deploys with no window where anything
  is unreadable. Swapping the key in one step still fails loudly, and says
  which variable to set.
- **Schema migrations.** An ordered, recorded set of steps runs on startup, so
  a change that `create_all()` cannot make no longer means recreating the
  database.
- **Optional token expiry** via `TOKEN_TTL_DAYS`. Off by default; expired
  tokens are deleted rather than merely refused.
- **Administrator audit view.** Users named in `ADMIN_USERS` see everyone's
  trail rather than only their own.
- **`/metrics`**, in Prometheus text format with no new dependency. Off unless
  `ENABLE_METRICS` is set, since the counts are not for every deployment.
- Backup procedure documented for both Postgres and SQLite, including the point
  that a database backup without the encryption key is unreadable.

## v0.6.0

- `list` returns keys without values. A stolen token no longer hands over
  everything an account can read in a single request; values are fetched one at
  a time with the new `secretmgr get KEY`.
- An audit trail records reads, writes, shares, deletions, logins and credential
  changes. `secretmgr audit` shows your own activity. `ENABLE_AUDIT_LOG` and
  `AUDIT_RETENTION_DAYS` control it; nothing in the trail contains a secret
  value or a token.
- The landing page has a sitemap, a robots.txt and a canonical URL.

**Breaking:** `GET /secrets` no longer includes `value`. Use `GET /secrets/{key}`.

## v0.5.0

**Breaking.** GitHub sign-in is removed. The service manages its own accounts
and contacts nothing outside itself.

- Removed the OAuth flow, the `login_sessions` table, `AUTH_MODE`,
  `OAUTH_ID_GITHUB`, `OAUTH_SECRET_GITHUB` and `ENABLE_TEST_LOGIN`.
- `httpx` is no longer a runtime dependency — the backend makes no outbound
  HTTP calls at all.
- The share API field is `user_id` rather than `github_id`, the users table's
  primary key is `user_id`, and the CLI token file stores `user_id`.
- The integration suite no longer stubs anything: it runs the real application
  and registers the accounts it needs.

**Upgrading:** this changes the schema without a migration. Existing databases
have to be recreated, and anyone logged in has to log in again. The image
defaults to SQLite on the container's volume, so unless you set `DB_URL` to
something durable there was nothing to carry over anyway.

## v0.4.0

- Self-service registration with scrypt password hashing, `secretmgr register`.
- Rate-limited authentication, shared across replicas via the database.
- `secretmgr passwd` and `secretmgr revoke`.
- Honours `PORT`, so platforms that choose the port work without a custom command.
- One-command clustered Compose stack and Kubernetes manifests.
- Windows CLI binary.
- The database ships with the image, on a `/data` volume.

## v0.3.0

- CLI binary cut from 12.2MB to 9.45MB by dropping `rich`/`Pygments` and keeping
  test tooling out of the build environment.
- Runs on any platform: Postgres support, a published multi-arch container image,
  deployment documentation beyond AWS.
- Login state moved into the database, so more than one replica works.
- Fixed three races that only appear with concurrent writers.

## v0.2.0

- Security hardening: encryption at rest, token file `0600`, CORS locked down,
  API docs and the test-login route opt-in, cached token verification.
- First published release. Apache 2.0.

## v0.1.0

Tagged but never published — the release build stalled on a retired runner.
