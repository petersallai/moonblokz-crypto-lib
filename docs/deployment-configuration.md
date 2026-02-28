# Deployment Configuration

This repository is a Rust library crate (not a deployable service/application).

## Deployment Artifacts

- No runtime deployment manifests detected (`Dockerfile`, `docker-compose`, k8s charts, terraform, service units).
- No CI/CD pipeline config detected in this repo snapshot (`.github/workflows`, `.gitlab-ci.yml`, etc.).

## Distribution Model

- Intended as a dependency crate via Cargo/Git.
- Consumer projects select one implementation feature at compile time.

## Operational Note

For reproducibility, consumers should pin crate version/revision and enforce feature selection in their own build pipeline.
