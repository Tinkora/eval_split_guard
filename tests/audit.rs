use eval_split_guard::{audit, render, AuditOptions, OutputFormat, Severity};
use std::fs;
use tempfile::tempdir;

fn options() -> AuditOptions {
    AuditOptions {
        leakage_pairs: vec![("train".into(), "test".into())],
    }
}

fn record(split: &str, sample_id: &str, content: &str, group_id: Option<&str>) -> String {
    let group = group_id
        .map(|v| format!(",\"group_id\":\"{v}\""))
        .unwrap_or_default();
    format!(
        r#"{{"schema_version":1,"split":"{split}","sample_id":"{sample_id}","content":"{content}"{group}}}
"#
    )
}

#[test]
fn clean_manifest_has_no_findings() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("manifest.jsonl");
    fs::write(
        &input,
        format!(
            "{}{}",
            record("train", "a", "alpha", Some("family-a")),
            record("test", "b", "beta", Some("family-b"))
        ),
    )
    .unwrap();
    let report = audit(&input, &options()).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.records, 2);
}

#[test]
fn detects_cross_pair_exact_and_group_leakage_without_echoing_secrets() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("private_manifest.jsonl");
    fs::write(
        &input,
        format!(
            "{}{}",
            record(
                "train",
                "SECRET_ID_ONE",
                "TOP_SECRET_PAYLOAD",
                Some("PRIVATE_GROUP")
            ),
            record(
                "test",
                "SECRET_ID_TWO",
                "TOP_SECRET_PAYLOAD",
                Some("PRIVATE_GROUP")
            )
        ),
    )
    .unwrap();
    let report = audit(&input, &options()).unwrap();
    assert!(report.findings.iter().any(|f| f.code == "ESG005"));
    assert!(report.findings.iter().any(|f| f.code == "ESG007"));
    let output = render(&report, OutputFormat::Json).unwrap();
    for secret in [
        "TOP_SECRET_PAYLOAD",
        "PRIVATE_GROUP",
        "SECRET_ID_ONE",
        "SECRET_ID_TWO",
    ] {
        assert!(!output.contains(secret));
    }
    assert!(!output.contains(dir.path().to_str().unwrap()));
}

#[test]
fn accepts_content_sha256_and_detects_cross_pair_reuse() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("hashed.jsonl");
    let hash = "a".repeat(64);
    fs::write(&input, format!("{{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content_sha256\":\"{hash}\"}}\n{{\"schema_version\":1,\"split\":\"test\",\"sample_id\":\"b\",\"content_sha256\":\"{hash}\"}}\n")).unwrap();
    let report = audit(&input, &options()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].code, "ESG005");
    assert!(!render(&report, OutputFormat::Text).unwrap().contains(&hash));
}

#[test]
fn rejects_uppercase_content_sha256() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("uppercase.jsonl");
    fs::write(
        &input,
        format!(
            "{{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content_sha256\":\"{}\"}}\n",
            "A".repeat(64)
        ) + &record("train", "valid-train", "train-only", None)
            + &record("test", "valid-test", "test-only", None),
    )
    .unwrap();
    let report = audit(&input, &options()).unwrap();
    assert_eq!(report.findings[0].code, "ESG002");
}

#[test]
fn drains_oversized_record_and_continues() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("oversized.jsonl");
    let mut bytes = vec![b'x'; 1024 * 1024 + 1];
    bytes.push(b'\n');
    bytes.extend_from_slice(record("train", "a", "valid", None).as_bytes());
    bytes.extend_from_slice(record("test", "b", "also-valid", None).as_bytes());
    fs::write(&input, bytes).unwrap();
    let report = audit(&input, &options()).unwrap();
    assert_eq!(report.records, 3);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].code, "ESG001");
}

#[test]
fn accepts_a_record_exactly_at_the_payload_limit() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("max_record.jsonl");
    let prefix = r#"{"schema_version":1,"split":"train","sample_id":"a","content":""#;
    let suffix = "\"}";
    let content = "x".repeat(1024 * 1024 - prefix.len() - suffix.len());
    let exact_record = format!("{prefix}{content}{suffix}\n");
    assert_eq!(exact_record.len() - 1, 1024 * 1024);
    fs::write(
        &input,
        exact_record + &record("test", "b", "test-content", None),
    )
    .unwrap();

    let report = audit(&input, &options()).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.records, 2);
}

#[test]
fn distinguishes_malformed_records_from_schema_defects() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("bad.jsonl");
    fs::write(&input, format!("{{bad json\n{{\"schema_version\":2,\"split\":\"train\",\"sample_id\":\"a\",\"content\":\"x\"}}\n{{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content\":\"x\",\"content_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}\n{{\"schema_version\":1,\"split\":\"test\",\"sample_id\":\"b\",\"content_sha256\":\"xyz\"}}\n{}{}", record("train", "valid-train", "train-valid", None), record("test", "valid-test", "test-valid", None))).unwrap();
    let report = audit(&input, &options()).unwrap();
    assert_eq!(report.records, 6);
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.code == "ESG001")
            .count(),
        1
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.code == "ESG002")
            .count(),
        3
    );
}

#[test]
fn detects_duplicate_sample_and_same_split_content_and_group() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("same_split.jsonl");
    fs::write(
        &input,
        format!(
            "{}{}{}{}",
            record("train", "a", "same", Some("family")),
            record("train", "a", "other", None),
            record("train", "b", "same", Some("family")),
            record("test", "c", "test-clean", Some("test-family"))
        ),
    )
    .unwrap();
    let report = audit(&input, &options()).unwrap();
    for (code, severity) in [
        ("ESG003", Severity::Error),
        ("ESG004", Severity::Warning),
        ("ESG006", Severity::Warning),
    ] {
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == code && f.severity == severity));
    }
}

#[test]
fn ignores_cross_split_reuse_outside_explicit_pairs() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("manifest.jsonl");
    fs::write(
        &input,
        format!(
            "{}{}{}",
            record("train", "a", "same", Some("family")),
            record("validation", "b", "same", Some("family")),
            record("test", "c", "test-clean", Some("test-family"))
        ),
    )
    .unwrap();
    assert!(audit(&input, &options()).unwrap().findings.is_empty());
}

#[test]
fn rejects_invalid_leakage_pairs_as_input_errors() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("manifest.jsonl");
    fs::write(&input, record("train", "a", "x", None)).unwrap();
    let invalid = AuditOptions {
        leakage_pairs: vec![("train".into(), "train".into())],
    };
    assert!(audit(&input, &invalid).is_err());
}

#[test]
fn rejects_declared_pairs_when_a_split_is_absent() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("manifest.jsonl");
    fs::write(&input, record("train", "a", "x", None)).unwrap();
    assert!(audit(&input, &options()).is_err());
}

#[test]
fn fails_closed_when_diagnostic_limit_is_exceeded() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("many_bad.jsonl");
    fs::write(&input, "{bad\n".repeat(10_001)).unwrap();
    assert!(audit(&input, &options()).is_err());
}

#[test]
fn fails_closed_when_record_limit_is_exceeded() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("many_records.jsonl");
    let mut manifest = String::new();
    for index in 0..100_001 {
        manifest.push_str(&record(
            "train",
            &format!("sample-{index}"),
            &format!("content-{index}"),
            None,
        ));
    }
    fs::write(&input, manifest).unwrap();
    assert!(audit(&input, &options()).is_err());
}

#[test]
fn json_report_uses_stable_schema() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("bad.jsonl");
    fs::write(
        &input,
        format!(
            "{{bad\n{}{}",
            record("train", "a", "train-valid", None),
            record("test", "b", "test-valid", None)
        ),
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(
        &render(&audit(&input, &options()).unwrap(), OutputFormat::Json).unwrap(),
    )
    .unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "eval_split_guard");
    assert_eq!(value["complete"], true);
}

#[cfg(unix)]
#[test]
fn rejects_symlink_inputs() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let real = dir.path().join("real.jsonl");
    let link = dir.path().join("link.jsonl");
    fs::write(&real, record("train", "a", "x", None)).unwrap();
    symlink(&real, &link).unwrap();
    assert!(audit(&link, &options()).is_err());
}
