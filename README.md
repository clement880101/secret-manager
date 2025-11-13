## Secret Manager

- `backend/`: FastAPI service responsible for storing, retrieving, and managing secrets. Local development runs inside its own `.devcontainer.json`, matching GitHub Actions and the ECS deployment target. `backend` uses OAuth credentials and a configured `BACKEND_URL`; unit tests run with `pytest`.
- `cli/`: Python CLI that interacts with the backend. The CLI has its own development container configuration and builds into standalone binaries via PyInstaller for both `x86_64` and `arm64`. Unit tests live under `cli/tests`.
- `integration-tests/`: End-to-end tests that exercise the published CLI binary against real backend endpoints. The tests run in their dedicated devcontainer and require GitHub access tokens.
- `terraform/`: Infrastructure as code for AWS resources, including ECS integration. Terraform commands run with AWS credentials set in a local `.env`.
- `docker-compose.yml`: Brings up the backend and CLI containers together for local iteration, sharing the workspace so code changes are reflected immediately. Backend and CLI containers mirror the configurations used in CI/CD.

## Local Development

- Install the Dev Containers extension and Docker Desktop.
- Open the desired subdirectory (`backend`, `cli`, `integration-tests`, or `terraform`) in Cursor/VS Code, then use the status bar in the lower-left corner to “Reopen in Container.”
- Update the relevant `.env` file before launching services:
  - `backend/.env`: `OAUTH_ID_GITHUB`, `OAUTH_SECRET_GITHUB`, `BACKEND_URL`
  - `cli/.env`: `BACKEND_URL`
  - `integration-tests/.env`: `GH_ACCESS_TOKEN_1`, `GH_ACCESS_TOKEN_2`
  - `terraform/.env`: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
- `docker-compose up` starts the backend and CLI dev containers together.
- Backend dev server: `uvicorn app:app --host 0.0.0.0 --port 8000 --reload --log-level debug`
- CLI usage: `python cli.py`
- Integration tests: download the latest CLI binary artifact into the repository root and run `pytest` from `integration-tests/`.
- Terraform: run standard Terraform commands immediately once the devcontainer is open.

## CI/CD Overview

- `backend-ci.yml`: Executes on pushes and pull requests targeting `backend/**`. Runs backend unit tests, then builds a Docker image with OAuth and backend URL build args. Successful pushes to `main` publish the image to Amazon ECR, update the ECS task definition, and trigger a rolling deployment to the ECS service behind the load balancer at `http://secretmgr-nlb-750c1ac03b1b7c1f.elb.us-west-1.amazonaws.com:8000`.
- `cli-ci.yml`: Runs on pushes and pull requests touching `cli/**`. After unit tests pass, PyInstaller builds binaries for both Ubuntu `x86_64` and `arm64` runners, storing them as GitHub Action artifacts.
- `integration-tests.yml`: Kicks off whenever `Backend CI` or `CLI CI` completes successfully, or when files under `integration-tests/**` change. The workflow downloads the latest CLI artifact and executes the integration test suite using GitHub access tokens.

