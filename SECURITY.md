# Security

## Reporting a vulnerability

Open a [security advisory](https://github.com/clement880101/secret-manager/security/advisories/new)
rather than a public issue.

## Configuration

Every switch below defaults to the safe choice, so a fresh deployment is locked
down until its operator opts out.

| Variable | Default | What it does |
| --- | --- | --- |
| `SECRET_ENCRYPTION_KEY` | unset | Fernet key used to encrypt secret values before they reach the database. **Unset means values are stored in plaintext.** |
| `ENABLE_AUDIT_LOG` | `true` | Record who read, wrote, shared and deleted what. |
| `AUDIT_RETENTION_DAYS` | `90` | How long audit events are kept. `0` keeps them forever. |
| `ALLOWED_ORIGINS` | empty | Comma-separated CORS origins. Empty grants nothing, which is correct for a CLI-only deployment. A `*` entry drops credentials, since browsers reject that pairing. |
| `ENABLE_API_DOCS` | `false` | Serves `/docs`, `/redoc` and `/openapi.json`. These describe every route to anyone who asks. |
| `BACKEND_URL` | — | The public address clients reach. |

Generate an encryption key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store it in the Secrets Manager entry Terraform creates (`encryption_key_secret_arn`).
Values written before a key is configured stay readable — ciphertext carries an
`enc:v1:` prefix, and rows without it are treated as legacy plaintext. **Rotating
or losing the key makes existing encrypted values unreadable**; there is no
recovery path.

## Transport

`terraform apply` puts a CloudFront distribution in front of the load balancer
(`enable_https`, on by default), giving clients HTTPS on CloudFront's own
certificate with no domain required. Use the `api_base_url` output as the CLI's
`BACKEND_URL`.

The CloudFront-to-origin hop remains HTTP. It travels the AWS backbone rather
than the public internet, but it is not encrypted. Closing that gap requires a
certificate the origin can present, which requires a domain you control — set
`domain_name` and `acm_certificate_arn` (issued in `us-east-1`).

The CLI prints a warning when `BACKEND_URL` is cleartext HTTP to a non-loopback
host. Silence it with `SECRETS_ALLOW_INSECURE=1` if you accept the risk.

## Client credential storage

The CLI writes its access token to `~/.token` with mode `0600`, created
via `os.open` so it is never briefly world-readable. Tokens written by earlier
builds were mode `0644`; the CLI repairs the mode when it next reads the file.

## Limits

| Limit | Default | Variable |
| --- | --- | --- |
| Secret value | 64 KB | — |
| Secret key | 256 characters | — |
| Request body | 256 KB | `MAX_REQUEST_BYTES` |
| Failed logins | 10 per username and per address per 15 min | `AUTH_RATE_LIMIT` |

The service runs as an unprivileged user (uid 10001) in the image, and the
Kubernetes manifests require `runAsNonRoot`.

## Known limitations

- **Secrets are returned in plaintext by `GET /secrets`**, so a stolen token
  exposes every value the account can see at once.
- **Tokens do not expire.** Revoke them deliberately with `secretmgr revoke`
  when a machine is lost or someone leaves.
- **There is no key rotation.** Changing `SECRET_ENCRYPTION_KEY` makes every
  existing value unreadable; there is no re-encrypt step.
- **There is no schema migration mechanism.** `create_all()` adds missing
  tables but never alters an existing one, so an upgrade that changes a column
  needs the database recreated.
- **Nothing backs the database up.** That is yours to arrange.
- **There are no metrics.** Logs only, and unstructured.
- **There is no audit log.** The service does not record who read which secret
  and when, which some environments require.
- **There is no account recovery.** A forgotten password needs an administrator
  to issue a token with `secretmgr token <name>`; there is no reset by email.
- **Authentication is rate limited; the rest of the API is not.** Failed logins
  and registrations are counted per username and per address, and blocked past
  `AUTH_RATE_LIMIT` (default 10) within `AUTH_RATE_WINDOW_SECONDS` (default
  900). A *valid* token can still be replayed as fast as the service answers.
- **Lockout is by username as well as address**, so someone who knows a
  username can deliberately lock that account out for the window. The
  alternative — limiting only by address — lets a distributed attacker spray
  guesses freely, which is worse for a secret manager.
- **SQLite is the default** and does not survive a container being replaced.
  Set `DB_URL` to Postgres for any real deployment; see `DEPLOYMENT.md`.
- **Released binaries are unsigned.** Verify the published `SHA256SUMS`.
