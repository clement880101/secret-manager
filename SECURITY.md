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
| `ALLOWED_ORIGINS` | empty | Comma-separated CORS origins. Empty grants nothing, which is correct for a CLI-only deployment. A `*` entry drops credentials, since browsers reject that pairing. |
| `ENABLE_API_DOCS` | `false` | Serves `/docs`, `/redoc` and `/openapi.json`. These describe every route to anyone who asks. |
| `ENABLE_TEST_LOGIN` | `false` | Serves `POST /auth/login-test`, which swaps a GitHub PAT for a session. Needed by the integration suite; not an auth bypass, but a second way in. |
| `TOKEN_CACHE_TTL_SECONDS` | `300` | How long a verified GitHub token is trusted before revalidation. `0` disables caching, giving immediate revocation at the cost of one GitHub API call per request. |
| `BACKEND_URL` | — | Public base URL. Must match what clients call: GitHub redirects the OAuth callback here. |

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

The CLI writes its GitHub access token to `~/.token` with mode `0600`, created
via `os.open` so it is never briefly world-readable. Tokens written by earlier
builds were mode `0644`; the CLI repairs the mode when it next reads the file.

## Known limitations

- **Secrets are returned in plaintext by `GET /secrets`**, so a stolen token
  exposes every value the account can see at once.
- **No rate limiting.** A valid token can be replayed as fast as the service
  will answer.
- **SQLite is the default** and does not survive a container being replaced.
  Set `DB_URL` to Postgres for any real deployment; see `DEPLOYMENT.md`.
- **Released binaries are unsigned.** Verify the published `SHA256SUMS`.
