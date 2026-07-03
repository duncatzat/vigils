//! Manifest schema:首次启动下载所需的元数据描述。
//!
//! 简化版本设计(v0.5 P2):整文件 sha256(非 chunk 级 hash),三件套文件各一条
//! `ManifestFile` 记录(model_q4f16.onnx + tokenizer.json + config.json)。
//!
//! v0.5.1 计划:`primary_url` / `fallback_urls` / `sha256` 字段由 release 流水线
//! 注入真实 Vigil mirror + HF CDN 地址与 sha256 摘要;此轮先用 `<placeholder-v0.5.1>`
//! 字符串占位,便于 grep 一次性替换。

use std::path::{Path, PathBuf};

/// 单文件下载元数据。
///
/// 一个完整 Manifest 含 3 条(三件套):model_q4f16.onnx / tokenizer.json / config.json。
///
/// `Default` derive(v0.7-α3 加):便于测试 spread 语法 `Manifest {..Default::default()}`,
/// 不影响生产路径(生产 manifest 必有真实字段值)。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct ManifestFile {
    /// 文件名(相对 target_dir 的 basename),与 [`crate::engine`] OrtEngine::from_env
    /// 三件套约定一致:`model_q4f16.onnx` / `tokenizer.json` / `config.json`。
    pub name: String,
    /// 文件字节大小(用于 chunk_size 切分;HEAD 返回的 Content-Length 必须与之一致)。
    pub size_bytes: u64,
    /// 整文件 sha256(hex,小写)。**整文件**校验,不做 chunk 级 hash。
    pub sha256: String,
    /// 主下载 URL(Vigil mirror)。v0.5.1 注入真值。
    pub primary_url: String,
    /// fallback URL 列表(HF CDN 等)。primary 失败按顺序重试;不并发触发限流。
    pub fallback_urls: Vec<String>,
}

/// 模型下载 manifest:含模型标识 + 三件套元数据。
///
/// **v0.7-α3 Phase 3 Design 扩展**(ADR 0017 § 2.3):新增三层 pin 字段
/// (`model_id` / `label_space_version` / `default`),全部走 serde default
/// 兼容老 schema(v0.5/v0.6/v0.6.1 现有 manifest 缺这些字段也可正常反序列化)。
///
/// `Default` derive(v0.7-α3 加):便于测试 spread 语法
/// `Manifest { specific_fields, ..Default::default() }`,生产路径不受影响
/// (生产 manifest 始终给实参,placeholder_manifest 显式列全)。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct Manifest {
    /// 模型逻辑名(如 `privacy-filter`),与 target_dir 路径段拼接用。
    pub model_name: String,
    /// 模型版本(语义化,与 vigil-redaction crate 解耦),与 target_dir 路径段拼接用。
    pub version: String,
    /// 单文件并发 chunk 数。v0.5 P2 默认 16(ADR 0012 §3.4),v0.5.x 可调。
    pub chunk_count: u32,
    /// 三件套文件列表(顺序无关,但本模块按 name 索引)。
    pub files: Vec<ManifestFile>,

    // ─── v0.7-α3 Phase 3 Design(ADR 0017 § 2.3)新增三层 pin ───
    /// 模型 selection key,对账 [`crate::model_descriptor::ModelDescriptor::model_id`]。
    /// 与 [`Self::model_name`] 互补:`model_name` 是 logical/UI 名(如
    /// "privacy-filter"),`model_id` 是 selection key(如
    /// "openai-privacy-filter-v1")。老 schema 缺此字段时,serde default 填空串
    /// `""`,运行时由 caller 兜底(沿用 model_name 作为 id)。
    #[serde(default)]
    pub model_id: String,
    /// label-space-version,对账 [`crate::model_descriptor::ModelDescriptor::label_space_version`]。
    /// 任何变化即 breaking,启动失败(沿用 ADR 0012 fail-fast 模式)。
    /// 老 schema 缺此字段时,serde default 填空串 `""`,启动期 caller 决策是否
    /// 拒入(v0.7-α3 Phase 3 Design 暂时容忍空值,避免破坏 v0.5/v0.6 老 manifest)。
    #[serde(default)]
    pub label_space_version: String,
    /// 是否 default selection(同 [`MultiModelManifest`] 内多 manifest 时的 fallback)。
    /// 单模型 manifest 自然 default;老 schema 缺此字段即 default = false,
    /// 由 [`MultiModelManifest`] 反序列化路径自动设 true(单元素 array 必为 default)。
    #[serde(default)]
    pub default: bool,
}

/// v0.7-α3 Phase 3 Design(ADR 0017 § 2.3)— 多模型顶层容器。
///
/// **向前兼容**:反序列化时优先尝试新 schema(顶层 `models: [...]`),失败降级
/// 解老 schema(单 [`Manifest`])并自动包成单元素 array。
///
/// **使用路径**(P3-spike 之后启用,本 Phase 3 Design 仅暴露类型):
/// - bootstrap 加载 manifest.json → 调 [`Self::deserialize_compat`] 拿到 array
/// - selection 按 `FirewallConfig.model_id` / `VIGIL_MODEL_ID` / `default == true`
///   选 entry
/// - 单 entry array 自然兼容 v0.5/v0.6/v0.6.1 老 manifest
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MultiModelManifest {
    /// 多模型 array;单元素时等价老 schema 单 manifest
    pub models: Vec<Manifest>,
}

impl MultiModelManifest {
    /// 反序列化兼容路径:先试新 schema,失败降级老 schema。
    ///
    /// **不变量**:
    /// - 老 schema(单 [`Manifest`])→ 自动包成单元素 array,且强制 `default = true`
    /// - 新 schema(顶层 `models: [...]`)→ 直接用,不强加 default(由 caller 检查)
    /// - 双侧都解析失败 → 返 `serde_json::Error`(诊断用,不含敏感数据)
    pub fn deserialize_compat(json: &str) -> Result<Self, serde_json::Error> {
        // 优先尝试新 schema(顶层 models 数组)
        if let Ok(multi) = serde_json::from_str::<MultiModelManifest>(json) {
            return Ok(multi);
        }
        // 降级:解老 schema 包成单元素 array;强制 default = true
        let single: Manifest = serde_json::from_str(json)?;
        Ok(MultiModelManifest {
            models: vec![Manifest {
                default: true,
                ..single
            }],
        })
    }

    /// 按 model_id 选 entry;空 id 选 `default == true` 的(若有,否则第一条)。
    ///
    /// **fail-fast**:返 `None` 表示 selection miss,caller 应转 `ModelNotFound`
    /// 拒启动(沿用 ADR 0012 fail-fast)。
    pub fn select(&self, model_id: Option<&str>) -> Option<&Manifest> {
        match model_id {
            Some(id) if !id.is_empty() => self.models.iter().find(|m| m.model_id == id),
            _ => self
                .models
                .iter()
                .find(|m| m.default)
                .or(self.models.first()),
        }
    }
}

/// 三件套就绪后的绝对路径句柄,供 [`crate::engine::OrtEngine::from_env`] 消费。
///
/// 字段名与 engine.rs:203-205 三件套变量一致,便于 caller 既可走 env var
/// (`VIGIL_PRIVACY_FILTER_MODEL_DIR`)桥接,也可未来直接用 `OrtEngine::from_paths`。
#[derive(Debug, Clone)]
pub struct ModelPaths {
    /// `model_q4f16.onnx` 绝对路径
    pub onnx: PathBuf,
    /// `tokenizer.json` 绝对路径
    pub tokenizer: PathBuf,
    /// `config.json` 绝对路径
    pub config: PathBuf,
}

impl ModelPaths {
    /// 三件套所在目录(三个文件必然同 parent;由 `ensure_model_available` 保证)。
    ///
    /// 用于 `std::env::set_var("VIGIL_PRIVACY_FILTER_MODEL_DIR", paths.dir())` 桥接旧接口。
    pub fn dir(&self) -> &Path {
        // safety:三件套构造时父目录由 `target_dir` 注入,必然 Some。
        // 退化情况(根目录)虽不现实但 unwrap 仍可能 panic,这里用 expect 给清晰诊断。
        self.onnx
            .parent()
            .expect("ModelPaths.onnx 必有父目录(由 ensure_model_available 保证)")
    }
}

/// 占位 Manifest 构造函数(v0.5 P2)。
///
/// **不**写成 `const`:Manifest 含 `String` / `Vec<String>` 字段,常量构造受限;
/// 函数返回值同样支持调用点 grep `<placeholder-v0.5.1>` 一次性替换。
///
/// v0.15(2026-06-02):公开 crates.io 发布 scrub —— primary_url 从内部 mirror 切到
/// **官方 HuggingFace 公开端点** `huggingface.co/openai/privacy-filter`(OpenAI Privacy Filter,
/// Apache 2.0;4 文件 sha256/size 实测与本 manifest 字节一致)。无 fallback(HF CDN/xet 可靠;
/// 用户可经 `VIGIL_MODEL_MIRROR` env 覆盖为自有镜像)。真 sha256 + 真 size_bytes for 4 个 model
/// files(`model_q4f16.onnx` + `model_q4f16.onnx_data` + tokenizer + config)。
///
/// 测试场景由 tests.rs 自构 Manifest 覆盖(独立 fixture,不依赖本函数真值)。
pub fn placeholder_manifest() -> Manifest {
    // v0.6 修补:OpenAI Privacy Filter ONNX 用 external-data 格式,model_q4f16.onnx
    // 仅含 graph(~ 162 KB),真权重在 model_q4f16.onnx_data(~ 772 MB);
    // ORT runtime 加载时自动从同目录读 .onnx_data,因此 manifest 必须含 4 文件。
    // 注入工具:scripts/inject-model-manifest.mjs(支持真值 + http/https URL)
    Manifest {
        model_name: "privacy-filter".to_string(),
        version: "0.5.1".to_string(),
        chunk_count: 16,
        // v0.7-α3 Phase 3 Design 新字段(ADR 0017):
        // - 单模型场景 model_id 沿用现行 OpenAIPrivacyFilterDescriptor.model_id()
        // - label_space_version 对账 OpenAIPrivacyFilterDescriptor.label_space_version()
        // - default = true(单 manifest 自然 default)
        model_id: "openai-privacy-filter-v1".to_string(),
        label_space_version: "8class-v1".to_string(),
        default: true,
        // v0.3 A1 现代化(2026-06-21):加 vigils.ai 自有镜像作 fallback(L2 单源 HF 风险 ——
        // 此前 fallback_urls 全空)。primary 仍为 HF 官方权威源;HF 失败/被屏蔽区域按序回落
        // vigils.ai。整文件 sha256 校验在两源都生效,镜像服务错文件即 fail-closed,不会污染。
        // 镜像路径约定 = `https://vigils.ai/models/<model_name>-<version>/<filename>`(与本地
        // cache dir `resolve_target_dir` 同款命名);owner 须把下列 4 文件按此路径上传 vigils.ai。
        files: vec![
            ManifestFile {
                name: "model_q4f16.onnx".to_string(),
                size_bytes: 165744,
                sha256: "eaae4e83cf1345a60abe333ed882b55fe5775d1dfbf34b9b269e5e5416f45e5b".to_string(),
                primary_url: "https://huggingface.co/openai/privacy-filter/resolve/main/onnx/model_q4f16.onnx".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/privacy-filter-0.5.1/model_q4f16.onnx".to_string(),
                ],
            },
            // ONNX external-data weights(~ 772 MB);ORT 加载 model.onnx 时
            // 同目录自动找此文件;manifest 需独立列出确保 bootstrap 下载完整
            ManifestFile {
                name: "model_q4f16.onnx_data".to_string(),
                size_bytes: 809061992,
                sha256: "6d4dde787e03ace283c45d4e32a94eec32b6cfcc242e7219bea96f5b4c13569d".to_string(),
                primary_url: "https://huggingface.co/openai/privacy-filter/resolve/main/onnx/model_q4f16.onnx_data".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/privacy-filter-0.5.1/model_q4f16.onnx_data".to_string(),
                ],
            },
            ManifestFile {
                name: "tokenizer.json".to_string(),
                size_bytes: 27868174,
                sha256: "0614fe83cadab421296e664e1f48f4261fa8fef6e03e63bb75c20f38e37d07d3".to_string(),
                primary_url: "https://huggingface.co/openai/privacy-filter/resolve/main/tokenizer.json".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/privacy-filter-0.5.1/tokenizer.json".to_string(),
                ],
            },
            ManifestFile {
                name: "config.json".to_string(),
                size_bytes: 3039,
                sha256: "b2b26a4a4a000639ad30b0c264adbefe365bdb567fbd7bb27303b8c438375bd1".to_string(),
                primary_url: "https://huggingface.co/openai/privacy-filter/resolve/main/config.json".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/privacy-filter-0.5.1/config.json".to_string(),
                ],
            },
        ],
    }
}

/// DeBERTa prompt-injection 分类器下载 manifest(Slice B)。
///
/// 模型:`protectai/deberta-v3-base-prompt-injection-v2`(Apache-2.0),HF 官方
/// `onnx/` 子目录 **FP32** 现成导出(不自量化)。三件套布局与 OpenAI Privacy Filter
/// 不同:onnx 文件名是 `model.onnx`(非 `model_q4f16.onnx`),且**无** external-data
/// 旁文件(单文件 738 MB,FP32 权重全在 model.onnx 内)。
///
/// size / sha256 为 **实测值**(2026-06-12 `curl` HF resolve + `sha256sum` + `stat`):
/// - `model.onnx` 738,563,188 B,sha256 `f0ea7f23…`(与 HF lfs oid 对账一致)
/// - `tokenizer.json` 8,648,886 B
/// - `config.json` 1,014 B
///
/// 注:DeBERTa fast tokenizer.json 自包含 vocab,运行时不依赖 spm.model,故 manifest
/// **不含** spm.model(InjectionClassifier 只读 tokenizer.json / config.json / model.onnx)。
pub fn injection_classifier_manifest() -> Manifest {
    Manifest {
        model_name: "deberta-injection".to_string(),
        version: "v2".to_string(),
        chunk_count: 16,
        model_id: "deberta-v3-base-prompt-injection-v2".to_string(),
        // 二分类 SAFE/INJECTION 自成 label space,与 8class PII label space 解耦
        label_space_version: "injection-binary-v1".to_string(),
        default: false,
        // v0.3 A1(2026-06-21):vigils.ai 镜像 fallback,同 placeholder_manifest 约定。
        // 镜像路径 = `https://vigils.ai/models/deberta-injection-v2/<filename>`;owner 须上传下列 3 文件。
        files: vec![
            ManifestFile {
                name: "model.onnx".to_string(),
                size_bytes: 738563188,
                sha256: "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c".to_string(),
                primary_url: "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model.onnx".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/deberta-injection-v2/model.onnx".to_string(),
                ],
            },
            ManifestFile {
                name: "tokenizer.json".to_string(),
                size_bytes: 8648886,
                sha256: "752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f".to_string(),
                primary_url: "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/tokenizer.json".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/deberta-injection-v2/tokenizer.json".to_string(),
                ],
            },
            ManifestFile {
                name: "config.json".to_string(),
                size_bytes: 1014,
                sha256: "3093743035223c46b1497a72e939e56fa0a50afbd7bafbf7eb8aad060b8d23f8".to_string(),
                primary_url: "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/config.json".to_string(),
                fallback_urls: vec![
                    "https://vigils.ai/models/deberta-injection-v2/config.json".to_string(),
                ],
            },
        ],
    }
}

/// `ModelPaths.onnx` slot 接受的 onnx 文件名(OpenAI q4f16 量化 / DeBERTa FP32 两套布局共用)。
///
/// **SSOT**:下载 assign([`super::ensure_with_manifest`])与就绪检查
/// ([`super::verify::check_existing`])都经此判定,杜绝文件名 match 两处漂移 —— 曾因
/// check_existing 漏 `model.onnx`(只认 `model_q4f16.onnx`)导致 deberta 每次 serve 启动
/// check_existing 返 None → 重下载 738MB。新增模型的 onnx 文件名只改这一处。
pub(crate) fn is_onnx_artifact(name: &str) -> bool {
    matches!(name, "model_q4f16.onnx" | "model.onnx")
}

// ─────────────────────────── v0.7-α3 Phase 3 Design 守门测试 ───────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests_v07_alpha3 {
    use super::*;

    /// 老 schema(单 Manifest,缺 model_id / label_space_version / default)deser
    /// 应成功,新字段走 serde default 填空串 / false。
    #[test]
    fn legacy_single_manifest_deserialize_compatible() {
        let legacy_json = r#"{
            "model_name": "privacy-filter",
            "version": "0.5.1",
            "chunk_count": 16,
            "files": []
        }"#;
        let m: Manifest =
            serde_json::from_str(legacy_json).expect("老 schema(无三层 pin 字段)应能正常 deser");
        assert_eq!(m.model_name, "privacy-filter");
        assert_eq!(m.model_id, "", "缺字段应走 serde default 空串");
        assert_eq!(m.label_space_version, "");
        assert!(!m.default, "缺字段应 default = false");
    }

    /// SSOT 守门:is_onnx_artifact 覆盖两套布局的 onnx 文件名(OpenAI q4f16 + DeBERTa FP32),
    /// 拒绝其它。mod.rs 下载 assign 与 verify::check_existing 都依赖它 —— 漏任一名字会让对应
    /// 模型每次 serve 重下载 738MB(deberta model.onnx 曾踩此坑)。
    #[test]
    fn is_onnx_artifact_covers_both_layouts() {
        assert!(is_onnx_artifact("model_q4f16.onnx"), "OpenAI q4f16 onnx");
        assert!(is_onnx_artifact("model.onnx"), "DeBERTa FP32 onnx");
        assert!(!is_onnx_artifact("tokenizer.json"));
        assert!(!is_onnx_artifact("config.json"));
        assert!(!is_onnx_artifact("model.bin"));
    }

    /// 新 schema(顶层 models array)deser 应直接走新路径。
    #[test]
    fn new_schema_multi_model_deserialize() {
        let new_json = r#"{
            "models": [
                {
                    "model_name": "privacy-filter",
                    "version": "1.0.0",
                    "chunk_count": 16,
                    "model_id": "openai-privacy-filter-v1",
                    "label_space_version": "8class-v1",
                    "default": true,
                    "files": []
                },
                {
                    "model_name": "xlm-r-pii",
                    "version": "1.0.0",
                    "chunk_count": 16,
                    "model_id": "xlm-r-pii-v1",
                    "label_space_version": "8class-v1",
                    "default": false,
                    "files": []
                }
            ]
        }"#;
        let multi = MultiModelManifest::deserialize_compat(new_json)
            .expect("新 schema 顶层 models array 应能 deser");
        assert_eq!(multi.models.len(), 2);
        assert_eq!(multi.models[0].model_id, "openai-privacy-filter-v1");
        assert!(multi.models[0].default);
        assert!(!multi.models[1].default);
    }

    /// 老 schema 通过 deserialize_compat 自动包成单元素 array,且强制 default = true。
    #[test]
    fn legacy_schema_via_compat_wraps_to_single_array_with_default() {
        let legacy_json = r#"{
            "model_name": "privacy-filter",
            "version": "0.5.1",
            "chunk_count": 16,
            "files": []
        }"#;
        let multi = MultiModelManifest::deserialize_compat(legacy_json)
            .expect("老 schema 通过 compat 应包成单元素 array");
        assert_eq!(multi.models.len(), 1, "老 schema 应包成单元素 array");
        assert!(
            multi.models[0].default,
            "compat 路径强制 default = true(单元素必为默认)"
        );
        assert_eq!(multi.models[0].model_name, "privacy-filter");
    }

    /// select(Some(id)) 显式选;不存在返 None(caller fail-fast)。
    #[test]
    fn select_by_explicit_id_finds_or_none() {
        let multi = MultiModelManifest {
            models: vec![
                Manifest {
                    model_name: "a".to_string(),
                    version: "1".to_string(),
                    chunk_count: 16,
                    model_id: "id-a".to_string(),
                    label_space_version: "v1".to_string(),
                    default: false,
                    files: vec![],
                },
                Manifest {
                    model_name: "b".to_string(),
                    version: "1".to_string(),
                    chunk_count: 16,
                    model_id: "id-b".to_string(),
                    label_space_version: "v1".to_string(),
                    default: true,
                    files: vec![],
                },
            ],
        };
        assert_eq!(multi.select(Some("id-a")).unwrap().model_name, "a");
        assert_eq!(multi.select(Some("id-b")).unwrap().model_name, "b");
        assert!(multi.select(Some("id-nonexistent")).is_none());
    }

    /// select(None) 走 default fallback;若无 default → 第一条。
    #[test]
    fn select_default_or_first() {
        let mut multi = MultiModelManifest {
            models: vec![
                Manifest {
                    model_name: "first".to_string(),
                    version: "1".to_string(),
                    chunk_count: 16,
                    model_id: "id-first".to_string(),
                    label_space_version: "v1".to_string(),
                    default: false,
                    files: vec![],
                },
                Manifest {
                    model_name: "default".to_string(),
                    version: "1".to_string(),
                    chunk_count: 16,
                    model_id: "id-default".to_string(),
                    label_space_version: "v1".to_string(),
                    default: true,
                    files: vec![],
                },
            ],
        };
        // 有 default → 命中 default
        assert_eq!(multi.select(None).unwrap().model_name, "default");
        // 无 default → 第一条
        multi.models[1].default = false;
        assert_eq!(multi.select(None).unwrap().model_name, "first");
        // 空 string id 等价 None
        assert_eq!(multi.select(Some("")).unwrap().model_name, "first");
    }

    /// placeholder_manifest 现包含三层 pin 真值(对账 OpenAIPrivacyFilterDescriptor)
    #[test]
    fn placeholder_manifest_three_pin_values() {
        let m = placeholder_manifest();
        assert_eq!(m.model_id, "openai-privacy-filter-v1");
        assert_eq!(m.label_space_version, "8class-v1");
        assert!(m.default, "单模型 placeholder 应 default = true");
    }

    /// Slice B:DeBERTa 注入分类器 manifest 结构守门 —— 三件套 + deberta 文件名
    /// (model.onnx 而非 model_q4f16.onnx)+ HF resolve URL + 非空 sha256。
    #[test]
    fn injection_classifier_manifest_three_files_with_deberta_layout() {
        let m = injection_classifier_manifest();
        assert_eq!(m.model_id, "deberta-v3-base-prompt-injection-v2");
        assert_eq!(m.label_space_version, "injection-binary-v1");
        assert!(!m.default, "注入分类器非默认 PII 模型,default = false");
        assert_eq!(
            m.files.len(),
            3,
            "deberta 三件套:model.onnx/tokenizer/config"
        );

        let names: Vec<&str> = m.files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"model.onnx"), "onnx 文件名应为 model.onnx");
        assert!(names.contains(&"tokenizer.json"));
        assert!(names.contains(&"config.json"));
        // 不得误带 OpenAI 的 q4f16 文件名(布局区分守门)
        assert!(!names.contains(&"model_q4f16.onnx"));

        for f in &m.files {
            assert!(f.size_bytes > 0, "{} size 必须实测非 0", f.name);
            assert_eq!(f.sha256.len(), 64, "{} sha256 应是 64 hex", f.name);
            assert!(
                f.primary_url.starts_with(
                    "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/"
                ),
                "{} URL 应指向官方 HF 仓库",
                f.name
            );
        }
    }
}
