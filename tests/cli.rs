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
        "{\"schema_version\":1,\"split\":\"train\",\"sample_id\":\"a\",\"content\":\"alpha\"}\n",
    )
    .unwrap();
    let status = command()
        .args(["audit", clean.to_str().unwrap(), "--pair", "train:test"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));

    let bad = dir.path().join("bad.jsonl");
    fs::write(&bad, "{bad\n").unwrap();
    let status = command()
        .args(["audit", bad.to_str().unwrap(), "--pair", "train:test"])
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
        .args(["audit", input.to_str().unwrap(), "--pair", "train:train"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
