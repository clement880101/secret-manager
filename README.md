## Secret Manager

Cloud-backed secret manager with a FastAPI backend, Python CLI, end-to-end tests, and AWS infrastructure managed through Terraform. Local development mirrors CI/CD via Dev Containers and Docker.

### Repository Layout

| Path | Highlights |
| --- | --- |
| `backend/` | FastAPI service with OAuth authentication, unit tests under `tests/`, and containerized dev parity. |
| `cli/` | Python CLI packaged with PyInstaller for `x86_64` and `arm64`, tested via `pytest`. |
| `integration-tests/` | Runs the baked CLI binary against deployed endpoints using GitHub access tokens. |
| `terraform/` | AWS infrastructure definitions for ECS, load balancer, and related resources. |
| `docker-compose.yml` | Spins up backend and CLI containers together; mounts the repo for live code edits. |

### Local Development

1. Install Docker Desktop and the Dev Containers extension.
2. From Cursor/VS Code, open any component directory and choose **Reopen in Container** in the lower-left corner.
3. Create the required `.env` files before starting services:
   - `backend/.env`
     - `OAUTH_ID_GITHUB`: GitHub OAuth application client ID used for authenticating users.
     - `OAUTH_SECRET_GITHUB`: GitHub OAuth client secret paired with the client ID.
     - `BACKEND_URL`: Public URL for the backend (matches the load balancer endpoint in production; local environments can use `http://localhost:8000`).
   - `cli/.env`
     - `BACKEND_URL`: Base URL the CLI uses when issuing API requests (should align with the backend dev server or the deployed endpoint).
   - `integration-tests/.env`
     - `GH_ACCESS_TOKEN_1`: Personal access token for GitHub interactions exercised during integration tests.
     - `GH_ACCESS_TOKEN_2`: Secondary token used for multi-account/multi-user test flows.
   - `terraform/.env`
     - `AWS_ACCESS_KEY_ID`: Access key ID for the AWS IAM user or role executing Terraform.
     - `AWS_SECRET_ACCESS_KEY`: Secret key corresponding to the access key ID.
     - `AWS_REGION`: AWS region used for Terraform-managed resources.
4. Use `docker-compose up` to launch backend and CLI containers locally with shared volumes.

Component commands:

- Backend dev server:
  ```
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload --log-level debug
  ```
- CLI entrypoint:
  ```
  python cli.py
  ```
- Integration tests:
  1. Download the latest CLI binary artifact into the repo root.
  2. Reopen `integration-tests/` in a container.
  3. Run `pytest`.
- Terraform: once in the container, run Terraform commands (`terraform init`, `terraform apply`, etc.) immediately.

### CI/CD Pipelines

- `backend-ci.yml`: Runs for pushes/PRs touching `backend/**`. Executes unit tests, builds a Docker image with GitHub OAuth build args, pushes tags to ECR, and deploys the ECS service behind `http://secretmgr-nlb-750c1ac03b1b7c1f.elb.us-west-1.amazonaws.com:8000`.
- `cli-ci.yml`: Triggered for `cli/**` changes. Runs unit tests, builds PyInstaller binaries on Ubuntu `x86_64` and `arm64`, and publishes artifacts.
- `integration-tests.yml`: Fires after successful Backend or CLI CI runs (or direct changes within `integration-tests/**`). Downloads the latest CLI artifact and executes the integration test suite using GitHub access tokens.

