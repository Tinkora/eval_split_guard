# Eval Split Guard Product Specification

[简体中文](PRODUCT_SPEC.zh-CN.md)

## Problem evidence

Evaluation frameworks already expose decontamination and stable sample identity as real operational concerns. The [lm-evaluation-harness decontamination guide](https://github.com/EleutherAI/lm-evaluation-harness/blob/main/docs/decontamination.md) documents overlap checks, while [Inspect AI datasets](https://inspect.aisi.org.uk/datasets.html) make sample identifiers a first-class part of evaluation data. Teams still need a small, deterministic preflight check before an evaluation starts.

## Product decision

Build a local CLI that audits only a caller-provided manifest. Exact equality and explicit grouping are actionable and reproducible. Semantic similarity, training-data attribution, dataset downloads, and automatic repartitioning are outside the product boundary.

## Version 1 manifest

Each UTF-8 JSONL record is a strict object:

- `schema_version`: integer `1`.
- `split`: non-empty string, at most 256 bytes.
- `sample_id`: non-empty string, at most 256 bytes; unique within its split.
- Exactly one of `content` or `content_sha256`.
- `content`: non-empty string; SHA-256 uses its exact UTF-8 bytes.
- `content_sha256`: exactly 64 lowercase hexadecimal characters.
- `group_id`: optional non-empty string, at most 256 bytes.
- Unknown fields are rejected.

Leakage pairs are unordered and must be explicitly supplied using repeatable `--leakage-pair FROM:TO` arguments. Cross-split reuse outside those pairs is not reported. Every referenced split must occur in at least one valid record; otherwise the invocation is incomplete and exits `2`.

## Outputs and exit codes

Text and versioned JSON outputs contain only basename, counts, line numbers, fixed codes, severities, and fixed messages. Content, identifiers, groups, hashes, and absolute paths are forbidden.

- `0`: complete audit with no findings.
- `1`: complete audit with one or more findings.
- `2`: invalid invocation/input or a global resource limit prevented completion.

Finding codes and severities are normative in the README table.

## Resource contract

- Regular file only; reject symlinks and non-files.
- 64 MiB maximum input file.
- 1 MiB maximum JSONL record; an oversized record yields `ESG001`, is drained, and scanning continues.
- 100,000 maximum records.
- 10,000 maximum diagnostics.
- 64 MiB estimated tracking-memory budget.

Exceeding a global limit fails closed with exit code `2`; the tool never returns a clean or complete result after truncating evidence.

## Acceptance tests

- Clean manifest.
- Malformed JSON versus valid JSON with schema defects.
- Duplicate sample within a split.
- Same-split exact content and group warnings.
- Declared cross-pair content and group errors.
- Undeclared cross-split reuse ignored.
- Raw content and lowercase pre-hash equivalence.
- Uppercase or malformed hashes rejected.
- Oversized record drain and continuation.
- Symlink rejection, privacy-safe output, stable JSON schema, and exit codes `0`, `1`, and `2`.

## Explicit non-goals

No network, dataset adapters, evaluation execution, fuzzy or semantic matching, embeddings, LLM calls, automatic repair/repartitioning, or claims of proving model-training contamination.
