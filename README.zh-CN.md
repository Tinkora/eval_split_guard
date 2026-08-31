# Eval Split Guard

[English](README.md)

一个隐私优先、完全离线的评测数据集划分精确泄漏检查工具。

Eval Split Guard 在 Agent 评测运行前审计显式、带版本的 JSONL 清单，检测重复样本标识、精确内容重复和调用方声明的同源变体组。它不会下载数据集、执行评测、进行模糊匹配，也不会输出内容衍生值。

## 安装

下载 Release 归档，或使用 Rust 1.85 及以上版本构建：

```bash
cargo build --release --locked
```

## 快速开始

创建 UTF-8 JSONL 清单。每条记录必须包含 `schema_version`、`split`、`sample_id`，并且 `content` 与 `content_sha256` 必须且只能提供一个；`group_id` 可选。

```json
{"schema_version":1,"split":"train","sample_id":"train-1","content":"example","group_id":"source-7"}
{"schema_version":1,"split":"test","sample_id":"test-1","content_sha256":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}
```

显式声明哪些跨 split 关系应被视为泄漏：

```bash
eval_split_guard audit manifest.jsonl --leakage-pair train:test --leakage-pair validation:test
eval_split_guard audit manifest.jsonl --leakage-pair train:test --format json
```

退出码：完整且无发现为 `0`，完整但有发现为 `1`，输入或资源限制导致无法完成审计为 `2`。

JSON 报告包含 `schema_version: 1`、`kind: "eval_split_guard"` 和 `complete: true`。当 `--format json` 无法完成审计时，退出码 `2` 会输出隐私安全的 JSON envelope，其中包含 `complete: false`、固定 `error_code` `incomplete_audit` 和固定消息。文本模式错误仍写入 stderr。

## 发现代码

| 代码 | 含义 | 严重性 |
| --- | --- | --- |
| `ESG001` | JSONL 记录格式错误、为空或超限 | Error |
| `ESG002` | 版本化 schema 或字段约束不满足 | Error |
| `ESG003` | 同一 split 内 `sample_id` 重复 | Error |
| `ESG004` | 同一 split 内精确内容重复 | Warning |
| `ESG005` | 精确内容跨越显式声明的泄漏对 | Error |
| `ESG006` | 同一 split 内 `group_id` 重复 | Warning |
| `ESG007` | `group_id` 跨越显式声明的泄漏对 | Error |

## 安全边界与限制

- 只接受本地普通文件，拒绝符号链接。
- 不联网、不加载数据集、不执行评测，也不使用 embedding、LLM 或模糊匹配。
- 对 `content` 的精确 UTF-8 bytes 计算 SHA-256；预哈希必须是 64 位小写十六进制。
- 输出仅包含输入文件名、行号、固定发现代码、严重性和固定消息；绝不包含内容、`sample_id`、`group_id`、hash 或绝对路径。
- 输入最大 64 MiB，单条记录最大 1 MiB，最多 100,000 条记录、10,000 条诊断，估算跟踪内存上限 64 MiB。
- 达到全局资源上限返回退出码 `2`；单条记录超限产生 `ESG001` 并继续扫描。
- `--leakage-pair` 中的每个 split 都必须至少出现在一条有效记录中，否则审计返回退出码 `2`。

## 项目状态

`v0.1.0-alpha.2` 有意保持窄边界。精确相等和调用方提供的分组能产生确定性证据，但不能证明模型训练污染或语义相似。

## 社区

请参阅[贡献指南](CONTRIBUTING.zh-CN.md)、[安全策略](SECURITY.zh-CN.md)、[支持说明](SUPPORT.zh-CN.md)和[行为准则](CODE_OF_CONDUCT.zh-CN.md)。

如果本项目为你节省了时间，可以在 [Ko-fi](https://ko-fi.com/tinkora) 支持 Tinkora。

## 许可证

MIT
