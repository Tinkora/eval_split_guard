# Changelog

All notable changes to this project are documented here.

## [0.1.0-alpha.3] - 2026-08-31

### Fixed

- Removed CI runner-local URIs from CycloneDX component and dependency references.
- Added fail-closed release contracts for local URIs, duplicate component references, and dangling dependencies.

## [0.1.0-alpha.2] - 2026-08-31

### Fixed

- Fixed draft release discovery and asset download so pre-publication verification works with GitHub draft semantics.

## [0.1.0-alpha.1] - 2026-08-31

### Added

- Added bounded, offline audits for a strict versioned JSONL manifest.
- Added exact SHA-256 content leakage and explicit `group_id` leakage findings.
- Added duplicate sample detection, privacy-safe text and JSON output, and stable exit codes.
- Added bilingual documentation, community health files, CI, dependency policy, SBOM, checksums, and release attestations.
