# Eval Split Guard

[简体中文](README.zh-CN.md)

Privacy-first, offline checks for exact leakage across evaluation dataset splits.

Eval Split Guard audits an explicit, versioned JSONL manifest before an agent evaluation runs. It detects duplicate sample identifiers, repeated exact content, and explicitly declared variant groups. It never downloads datasets, executes evaluations, performs fuzzy matching, or prints content-derived values.

## Install

Download a release archive or build with Rust 1.85 or later:

```bash
cargo build --release --locked
```

## Quick start

Create a UTF-8 JSONL manifest. Each record must contain `schema_version`, `split`, `sample_id`, and exactly one of `content` or `content_sha256`. `group_id` is optional.

```json
{"schema_version":1,"split":"train","sample_id":"train-1","content":"example","group_id":"source-7"}
{"schema_version":1,"split":"test","sample_id":"test-1","content_sha256":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}
```

Declare every cross-split relationship that should be treated as leakage:

```bash
eval_split_guard audit manifest.jsonl --pair train:test --pair validation:test
eval_split_guard audit manifest.jsonl --pair train:test --format json
```

Exit codes are `0` for a complete clean audit, `1` for a complete audit with findings, and `2` when input or resource limits prevent a complete audit.

## Findings

| Code | Meaning | Severity |
| --- | --- | --- |
| `ESG001` | Malformed, empty, or oversized JSONL record | Error |
| `ESG002` | Versioned schema or field violation | Error |
| `ESG003` | Duplicate `sample_id` inside one split | Error |
| `ESG004` | Exact content repeated inside one split | Warning |
| `ESG005` | Exact content crosses a declared leakage pair | Error |
| `ESG006` | `group_id` repeated inside one split | Warning |
| `ESG007` | `group_id` crosses a declared leakage pair | Error |

## Safety and limits

- Local regular files only; symlinks are rejected.
- No network, dataset loading, evaluation execution, embeddings, LLMs, or fuzzy matching.
- SHA-256 is computed over the exact UTF-8 bytes of `content`; pre-hashed values must be 64 lowercase hexadecimal characters.
- Output contains only the input basename, line numbers, fixed finding codes, severities, and fixed messages. It never contains content, `sample_id`, `group_id`, hashes, or absolute paths.
- Maximum input size: 64 MiB; record size: 1 MiB; records: 100,000; diagnostic entries: 10,000; estimated tracking memory: 64 MiB.
- Reaching a global resource limit returns exit code `2`; an oversized individual record produces `ESG001` and scanning continues.

## Project status

`v0.1.0-alpha.1` is intentionally narrow. Exact equality and caller-supplied grouping provide deterministic evidence; they do not prove model-training contamination or semantic similarity.

## Community

See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [Support](SUPPORT.md), and the [Code of Conduct](CODE_OF_CONDUCT.md).

If this project saves you time, you can support Tinkora on [Ko-fi](https://ko-fi.com/tinkora).

## License

MIT
