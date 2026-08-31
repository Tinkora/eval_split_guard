use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_eval_split_guard"))
}

#[test]
fn exits_zero_for_clean_input_and_one_for_findings() {
    let dir = tempdir().unwrap();
    let clean = dir.path().join("clean.jsonl");
    fs::write(
        &clean,
        "{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content\":\"alpha\"}\n{\"schema_version\":1,\"split\":\"test\",\"sample_id\":\"b\",\"content\":\"beta\"}\n",
    )
    .unwrap();
    let status = command()
        .args([
            "audit",
            clean.to_str().unwrap(),
            "--leakage-pair",
            "train:test",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));

    let bad = dir.path().join("bad.jsonl");
    fs::write(&bad, "{bad\n{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content\":\"alpha\"}\n{\"schema_version\":1,\"split\":\"test\",\"sample_id\":\"b\",\"content\":\"beta\"}\n").unwrap();
    let status = command()
        .args([
            "audit",
            bad.to_str().unwrap(),
            "--leakage-pair",
            "train:test",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn exits_two_for_input_contract_errors() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("manifest.jsonl");
    fs::write(
        &input,
        "{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content\":\"alpha\"}\n",
    )
    .unwrap();
    let status = command()
        .args([
            "audit",
            input.to_str().unwrap(),
            "--leakage-pair",
            "train:train",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    let status = command()
        .args(["audit", input.to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    let status = command()
        .args([
            "audit",
            input.to_str().unwrap(),
            "--leakage-pair",
            "train:test",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    let text_output = command()
        .args([
            "audit",
            input.to_str().unwrap(),
            "--leakage-pair",
            "train:test",
        ])
        .output()
        .unwrap();
    assert_eq!(text_output.status.code(), Some(2));
    assert!(text_output.stdout.is_empty());
    assert!(!text_output.stderr.is_empty());
}

#[test]
fn json_mode_emits_privacy_safe_incomplete_envelope_for_exit_two() {
    let dir = tempdir().unwrap();
    let private_root = dir.path().join("PRIVATE_ABSOLUTE_DIRECTORY");
    fs::create_dir(&private_root).unwrap();
    let missing_split = private_root.join("SECRET_MANIFEST.jsonl");
    fs::write(
        &missing_split,
        "{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"SECRET_ID\",\"content\":\"SECRET_CONTENT\"}\n",
    )
    .unwrap();

    let cases = [
        command()
            .args([
                "audit",
                missing_split.to_str().unwrap(),
                "--leakage-pair",
                "train:test",
                "--format",
                "json",
            ])
            .output()
            .unwrap(),
        command()
            .args([
                "audit",
                private_root
                    .join("MISSING_SECRET_FILE.jsonl")
                    .to_str()
                    .unwrap(),
                "--leakage-pair",
                "train:test",
                "--format",
                "json",
            ])
            .output()
            .unwrap(),
    ];

    for output in cases {
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], "eval_split_guard");
        assert_eq!(value["complete"], false);
        assert_eq!(value["error_code"], "incomplete_audit");
        assert_eq!(
            value["message"],
            "Audit could not be completed because input or resource validation failed"
        );
        for secret in [
            "PRIVATE_ABSOLUTE_DIRECTORY",
            "SECRET_MANIFEST",
            "MISSING_SECRET_FILE",
            "SECRET_ID",
            "SECRET_CONTENT",
        ] {
            assert!(!stdout.contains(secret));
        }
    }
}

#[test]
fn json_mode_emits_incomplete_envelope_when_resource_limit_is_reached() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("resource.jsonl");
    fs::write(&input, "{bad\n".repeat(10_001)).unwrap();
    let output = command()
        .args([
            "audit",
            input.to_str().unwrap(),
            "--leakage-pair",
            "train:test",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["error_code"], "incomplete_audit");
}
