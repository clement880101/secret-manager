# Changelog

## v0.5.0

**Breaking.** GitHub sign-in is removed. The service manages its own accounts
and contacts nothing outside itself.

- Removed the OAuth flow, the `login_sessions` table, `AUTH_MODE`,
  `OAUTH_ID_GITHUB`, `OAUTH_SECRET_GITHUB` and `ENABLE_TEST_LOGIN`.
- `httpx` is no longer a runtime dependency — the backend makes no outbound
  HTTP calls at all.
- The share API field is `user_id` rather than `github_id`, and the CLI token
  file stores `user_id`. Token files written by older versions are still read.
- The integration suite no longer stubs anything: it runs the real application
  and registers the accounts it needs.

**Upgrading:** accounts that signed in with GitHub cannot log in any more and
have to register. Secrets they own remain in the database under their old
identifier.

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
