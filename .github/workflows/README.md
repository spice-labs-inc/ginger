# GitHub Actions Workflows – Ginger

This folder contains GitHub Actions workflows for the Ginger project.

---

## `rust-ci.yml`

This workflow builds and tests the Rust project using `cargo`.

**Triggers automatically on:**
1. Push to any branch (`**`)
2. Pull requests targeting the `main` branch

---

## `rust_container_publishing.yml`

This workflow builds and publishes multi-platform Docker images to [Docker Hub](https://hub.docker.com/u/spicelabs) as `spicelabs/ginger`.

**Image includes:**
- Provenance attestations
- Software Bill of Materials (SBOM)
- Multi-format semver tags (e.g. `v1.2.3`, `v1.2`, `v1`)
- Security scan using the Spice Labs CLI

**Triggers automatically on:**
1. Push of a semantic version tag (e.g. `v1.2.3`)
2. Manual invocation via the GitHub Actions UI (`workflow_dispatch`)

**Version safety:**  
The image is only published if the Git tag matches the version declared in `Cargo.toml`.

