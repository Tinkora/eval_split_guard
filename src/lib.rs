use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_RECORDS: u64 = 100_000;
const MAX_LABEL_BYTES: usize = 256;
const MAX_TRACKING_BYTES: usize = 64 * 1024 * 1024;
const TRACKING_ENTRY_OVERHEAD: usize = 96;
const MAX_FINDINGS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub leakage_pairs: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub line: Option<u64>,
    pub message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub kind: &'static str,
    pub complete: bool,
    pub input: String,
    pub records: u64,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRecord {
    schema_version: u8,
    split: String,
    sample_id: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_sha256: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
}

pub fn audit(input: &Path, options: &AuditOptions) -> Result<Report> {
    let pairs = validate_pairs(options)?;
    validate_input(input)?;
    let file = File::open(input).context("could not open input file")?;
    let mut reader = BufReader::new(file);
    let mut report = Report {
        schema_version: 1,
        kind: "eval_split_guard",
        complete: true,
        input: safe_basename(input),
        records: 0,
        findings: Vec::new(),
    };
    let mut identities: HashMap<[u8; 32], HashSet<String>> = HashMap::new();
    let mut groups: HashMap<[u8; 32], HashSet<String>> = HashMap::new();
    let mut sample_keys: HashSet<[u8; 32]> = HashSet::new();
    let mut seen_splits: HashSet<String> = HashSet::new();
    let mut tracking_bytes = 0_usize;

    loop {
        let Some(line) = read_bounded_line(&mut reader)? else {
            break;
        };
        report.records = report.records.saturating_add(1);
        if report.records > MAX_RECORDS {
            bail!("input exceeds the {MAX_RECORDS} record limit");
        }
        let line_number = report.records;
        let bytes = match line {
            BoundedLine::Complete(bytes) if !bytes.iter().all(u8::is_ascii_whitespace) => bytes,
            BoundedLine::Complete(_) | BoundedLine::Oversized => {
                finding(
                    &mut report,
                    "ESG001",
                    Severity::Error,
                    Some(line_number),
                    "JSONL record is malformed or violates the manifest schema",
                )?;
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                finding(
                    &mut report,
                    "ESG001",
                    Severity::Error,
                    Some(line_number),
                    "JSONL record is malformed or violates the manifest schema",
                )?;
                continue;
            }
        };
        let record: ManifestRecord = match serde_json::from_value(value) {
            Ok(record) if valid_record(&record) => record,
            _ => {
                finding(
                    &mut report,
                    "ESG002",
                    Severity::Error,
                    Some(line_number),
                    "Record fields violate the versioned manifest schema",
                )?;
                continue;
            }
        };
        seen_splits.insert(record.split.clone());

        track_sample(
            &record.split,
            &record.sample_id,
            &mut sample_keys,
            &mut tracking_bytes,
            &mut report,
            line_number,
        )?;

        let identity = match (&record.content, &record.content_sha256) {
            (Some(content), None) => Sha256::digest(content.as_bytes()).into(),
            (None, Some(hash)) => decode_sha256(hash).expect("validated hash"),
            _ => unreachable!("validated exclusive identity source"),
        };
        inspect_token(
            identity,
            &record.split,
            &pairs,
            &mut identities,
            &mut tracking_bytes,
            &mut report,
            line_number,
            "ESG004",
            "Exact content identity is repeated within one split",
            "ESG005",
            "Exact content identity occurs in a declared leakage pair",
        )?;

        if let Some(group_id) = record.group_id {
            let group = Sha256::digest(group_id.as_bytes()).into();
            inspect_token(
                group,
                &record.split,
                &pairs,
                &mut groups,
                &mut tracking_bytes,
                &mut report,
                line_number,
                "ESG006",
                "A declared group is repeated within one split",
                "ESG007",
                "A declared group occurs in a declared leakage pair",
            )?;
        }
    }
    if pairs
        .iter()
        .any(|(left, right)| !seen_splits.contains(left) || !seen_splits.contains(right))
    {
        bail!("every declared leakage pair must reference two splits present in valid records");
    }
    Ok(report)
}

#[allow(
    clippy::too_many_arguments,
    reason = "The explicit privacy-safe finding metadata keeps content values out of diagnostics"
)]
fn inspect_token(
    token: [u8; 32],
    split: &str,
    pairs: &HashSet<(String, String)>,
    index: &mut HashMap<[u8; 32], HashSet<String>>,
    tracking_bytes: &mut usize,
    report: &mut Report,
    line: u64,
    same_code: &'static str,
    same_message: &'static str,
    cross_code: &'static str,
    cross_message: &'static str,
) -> Result<()> {
    if let Some(seen_splits) = index.get_mut(&token) {
        if seen_splits.contains(split) {
            finding(
                report,
                same_code,
                Severity::Warning,
                Some(line),
                same_message,
            )?;
        }
        if seen_splits
            .iter()
            .any(|seen| pair_matches(pairs, seen, split))
        {
            finding(
                report,
                cross_code,
                Severity::Error,
                Some(line),
                cross_message,
            )?;
        }
        if !seen_splits.contains(split) {
            let bytes = split.len().saturating_add(TRACKING_ENTRY_OVERHEAD);
            if tracking_bytes.saturating_add(bytes) <= MAX_TRACKING_BYTES {
                seen_splits.insert(split.to_owned());
                *tracking_bytes = tracking_bytes.saturating_add(bytes);
            } else {
                bail!("tracking memory limit reached before the audit completed");
            }
        }
        return Ok(());
    }

    let bytes = split.len().saturating_add(TRACKING_ENTRY_OVERHEAD + 32);
    if tracking_bytes.saturating_add(bytes) <= MAX_TRACKING_BYTES {
        index.insert(token, HashSet::from([split.to_owned()]));
        *tracking_bytes = tracking_bytes.saturating_add(bytes);
    } else {
        bail!("tracking memory limit reached before the audit completed");
    }
    Ok(())
}

fn track_sample(
    split: &str,
    sample_id: &str,
    sample_keys: &mut HashSet<[u8; 32]>,
    tracking_bytes: &mut usize,
    report: &mut Report,
    line: u64,
) -> Result<()> {
    let mut digest = Sha256::new();
    digest.update(split.as_bytes());
    digest.update([0]);
    digest.update(sample_id.as_bytes());
    let key: [u8; 32] = digest.finalize().into();
    if !sample_keys.insert(key) {
        finding(
            report,
            "ESG003",
            Severity::Error,
            Some(line),
            "Sample identifier is duplicated within one split",
        )?;
        return Ok(());
    }
    let bytes = TRACKING_ENTRY_OVERHEAD + 32;
    if tracking_bytes.saturating_add(bytes) > MAX_TRACKING_BYTES {
        bail!("tracking memory limit reached before the audit completed");
    }
    *tracking_bytes = tracking_bytes.saturating_add(bytes);
    Ok(())
}

pub fn render(report: &Report, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).context("could not render JSON"),
        OutputFormat::Text => {
            let mut output = format!(
                "eval_split_guard: {} record(s), {} finding(s)\n",
                report.records,
                report.findings.len()
            );
            for item in &report.findings {
                output.push_str(&format!(
                    "{} {:?} line {}: {}\n",
                    item.code,
                    item.severity,
                    item.line.unwrap_or(0),
                    item.message
                ));
            }
            Ok(output)
        }
    }
}

pub fn parse_pair(value: &str) -> Result<(String, String)> {
    let Some((left, right)) = value.split_once(':') else {
        bail!("leakage pair must use FROM:TO syntax");
    };
    if !valid_label(left) || !valid_label(right) || left == right || right.contains(':') {
        bail!("leakage pair must contain two distinct, bounded split labels");
    }
    Ok((left.to_owned(), right.to_owned()))
}

fn validate_pairs(options: &AuditOptions) -> Result<HashSet<(String, String)>> {
    if options.leakage_pairs.is_empty() {
        bail!("at least one explicit leakage pair is required");
    }
    let mut pairs = HashSet::new();
    for (left, right) in &options.leakage_pairs {
        if !valid_label(left) || !valid_label(right) || left == right {
            bail!("leakage pairs require two distinct, bounded split labels");
        }
        let pair = if left <= right {
            (left.clone(), right.clone())
        } else {
            (right.clone(), left.clone())
        };
        pairs.insert(pair);
    }
    Ok(pairs)
}

fn pair_matches(pairs: &HashSet<(String, String)>, left: &str, right: &str) -> bool {
    let pair = if left <= right {
        (left.to_owned(), right.to_owned())
    } else {
        (right.to_owned(), left.to_owned())
    };
    pairs.contains(&pair)
}

fn valid_record(record: &ManifestRecord) -> bool {
    record.schema_version == 1
        && valid_label(&record.split)
        && valid_label(&record.sample_id)
        && match (&record.content, &record.content_sha256) {
            (Some(content), None) => !content.is_empty(),
            (None, Some(hash)) => decode_sha256(hash).is_some(),
            _ => false,
        }
        && record
            .group_id
            .as_deref()
            .is_none_or(|value| !value.is_empty() && value.len() <= MAX_LABEL_BYTES)
}

fn valid_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_LABEL_BYTES && !value.chars().any(char::is_control)
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_input(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("could not inspect input file")?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("input must be a regular file and must not be a symlink");
    }
    if metadata.len() > MAX_FILE_BYTES {
        bail!("input exceeds the {MAX_FILE_BYTES} byte limit");
    }
    Ok(())
}

fn safe_basename(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<input>")
        .to_owned()
}

enum BoundedLine {
    Complete(Vec<u8>),
    Oversized,
}

fn read_bounded_line(reader: &mut impl BufRead) -> Result<Option<BoundedLine>> {
    let mut bytes = Vec::new();
    let read = {
        let mut limited = std::io::Read::take(&mut *reader, (MAX_RECORD_BYTES + 2) as u64);
        limited
            .read_until(b'\n', &mut bytes)
            .context("could not read input")?
    };
    if read == 0 {
        return Ok(None);
    }
    let delimiter_bytes = if bytes.ends_with(b"\r\n") {
        2
    } else if bytes.ends_with(b"\n") {
        1
    } else {
        0
    };
    let oversized = bytes.len().saturating_sub(delimiter_bytes) > MAX_RECORD_BYTES;
    if oversized && !bytes.ends_with(b"\n") {
        drain_to_newline(reader)?;
    }
    if oversized {
        Ok(Some(BoundedLine::Oversized))
    } else {
        Ok(Some(BoundedLine::Complete(bytes)))
    }
}

fn drain_to_newline(reader: &mut impl BufRead) -> Result<()> {
    loop {
        let buffer = reader
            .fill_buf()
            .context("could not drain oversized record")?;
        if buffer.is_empty() {
            return Ok(());
        }
        let consumed = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        let found_newline = consumed <= buffer.len() && buffer.get(consumed - 1) == Some(&b'\n');
        reader.consume(consumed);
        if found_newline {
            return Ok(());
        }
    }
}

fn finding(
    report: &mut Report,
    code: &'static str,
    severity: Severity,
    line: Option<u64>,
    message: &'static str,
) -> Result<()> {
    if report.findings.len() >= MAX_FINDINGS {
        bail!("diagnostic limit reached before the audit completed");
    }
    report.findings.push(Finding {
        code,
        severity,
        line,
        message,
    });
    Ok(())
}
