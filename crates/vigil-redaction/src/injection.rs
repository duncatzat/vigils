//! Slice A — DeBERTa prompt-injection 序列二分类引擎(feature = "ort")。
//!
//! # 与 [`crate::engine::OrtEngine`] 的区别
//!
//! `OrtEngine` 是 **token 级 NER**(BIOES span 解码 → PII findings);本模块的
//! [`InjectionClassifier`] 是 **序列级二分类**:整段文本 → 单个 `p_injection`
//! 概率(0..1)。两者 ONNX I/O 形态不同(NER 输出 `[1, seq, num_labels]`,
//! 二分类输出 `[1, 2]`),解码逻辑无法复用,故**独立**实现,**不**接 `RedactionEngine`
//! trait(那个 trait 返回 `Vec<Finding>`,语义是 PII span;注入分类返回标量概率)。
//!
//! # 模型
//!
//! `protectai/deberta-v3-base-prompt-injection-v2`(Apache-2.0):
//! - id2label:`0 = SAFE`,`1 = INJECTION`
//! - ONNX 输入(实测 model.onnx protobuf 头):`input_ids` + `attention_mask`
//!   两个,**无** `token_type_ids`(config.json `type_vocab_size = 0`,DeBERTa-v2
//!   不用段嵌入)
//! - ONNX 输出:`logits`,shape `[1, 2]`,FP32(官方 onnx/ 现成导出,未自量化)
//!
//! # 线程模型
//!
//! 与 `OrtEngine` 一致:rc.12 `Session::run` 需 `&mut self`,故 `session` 持
//! `Mutex<Session>`,公共 [`InjectionClassifier::classify`] 保持 `&self`。锁开销
//! 纳秒级,推理本体几十~几百 ms。

#![cfg(feature = "ort")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ort::execution_providers::CPUExecutionProvider;
use ort::inputs;
use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Value;
use tokenizers::Tokenizer;

use crate::engine::EngineError;

/// DeBERTa 序列二分类输入序列上限。DeBERTa-v3-base `max_position_embeddings = 512`,
/// 超长文本截断到 511 token + [SEP]。注入检测关注开头的指令注入,截断尾部可接受。
const MAX_SEQ_LEN: usize = 512;

/// `protectai/deberta-v3-base-prompt-injection-v2` prompt-injection 序列分类器。
///
/// 装载 ONNX session + tokenizer,对单段文本输出注入概率 `p_injection ∈ [0, 1]`。
/// caller 自定阈值(常用 0.5)把概率二值化为 inject / safe 决策。
pub struct InjectionClassifier {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    /// INJECTION label 在 logits 末维的 index(由 config.json `label2id` 解析得;
    /// 标准导出为 1,但显式解析避免对标签顺序的隐式假设)。
    injection_idx: usize,
    /// 仅供 `Debug` / 诊断;不参与推理逻辑。
    #[allow(dead_code)]
    model_dir: PathBuf,
}

impl std::fmt::Debug for InjectionClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectionClassifier")
            .field("model_dir", &self.model_dir)
            .field("injection_idx", &self.injection_idx)
            .finish_non_exhaustive()
    }
}

impl InjectionClassifier {
    /// 从模型目录构造分类器。目录必须含 `model.onnx` / `tokenizer.json` /
    /// `config.json` 三件套(deberta onnx/ 子目录布局)。
    ///
    /// # Errors
    /// - `EngineError::ModelNotFound`:三件套任一缺失
    /// - `EngineError::TokenizerLoad` / `EngineError::SessionInit` /
    ///   `EngineError::Internal`:底层 init / config 解析失败
    pub fn from_model_dir(dir: &Path) -> Result<Self, EngineError> {
        let dir_str = dir.to_string_lossy().into_owned();
        let model_dir = dir.to_path_buf();
        let onnx_path = model_dir.join("model.onnx");
        let tok_path = model_dir.join("tokenizer.json");
        let cfg_path = model_dir.join("config.json");
        for p in [&onnx_path, &tok_path, &cfg_path] {
            if !p.exists() {
                return Err(EngineError::ModelNotFound {
                    dir: dir_str.clone(),
                });
            }
        }

        let tokenizer = Tokenizer::from_file(&tok_path)
            .map_err(|e| EngineError::TokenizerLoad(e.to_string()))?;
        let injection_idx = parse_injection_idx(&cfg_path)?;

        // 与 OrtEngine 同口径:多次 init 无副作用,load-dynamic 运行时找 onnxruntime
        let _ = ort::init()
            .with_name("vigil-injection-classifier")
            .with_execution_providers([CPUExecutionProvider::default().build()])
            .commit();

        let session = Session::builder()
            .map_err(|e| EngineError::SessionInit(e.to_string()))?
            .with_optimization_level(GraphOptimizationLevel::Level1)
            .map_err(|e| EngineError::SessionInit(e.to_string()))?
            .with_intra_threads(4)
            .map_err(|e| EngineError::SessionInit(e.to_string()))?
            .commit_from_file(&onnx_path)
            .map_err(|e| EngineError::SessionInit(e.to_string()))?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            injection_idx,
            model_dir,
        })
    }

    /// 对 `text` 做注入检测,返回 INJECTION 类的 softmax 概率 `p_injection ∈ [0, 1]`。
    ///
    /// 接近 1 = 高度疑似 prompt injection;接近 0 = 正常文本。caller 自定阈值判定。
    ///
    /// # Errors
    /// - `EngineError::InferRun`:tokenize / session.run 失败
    /// - `EngineError::DecodeShape`:logits shape 不是 `[1, 2]` 或张量提取失败
    /// - `EngineError::Internal`:Mutex poisoned
    pub fn classify(&self, text: &str) -> Result<f32, EngineError> {
        // ─── 1. tokenize(截断到 512;DeBERTa 位置编码上限）───
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| EngineError::InferRun(e.to_string()))?;
        let mut ids: Vec<i64> = enc.get_ids().iter().map(|&i| i as i64).collect();
        let mut mask: Vec<i64> = enc.get_attention_mask().iter().map(|&m| m as i64).collect();
        if ids.len() > MAX_SEQ_LEN {
            ids.truncate(MAX_SEQ_LEN);
            mask.truncate(MAX_SEQ_LEN);
        }
        let seq_len = ids.len();
        if seq_len == 0 {
            // tokenizer 理论上至少给 [CLS]/[SEP];空序列保守返 0(非注入)
            return Ok(0.0);
        }

        // ─── 2. 构 Value(与 OrtEngine 同形态:[1, seq_len] i64）───
        let input_ids_val = Value::from_array((vec![1i64, seq_len as i64], ids))
            .map_err(|e| EngineError::DecodeShape(e.to_string()))?;
        let mask_val = Value::from_array((vec![1i64, seq_len as i64], mask))
            .map_err(|e| EngineError::DecodeShape(e.to_string()))?;

        // ─── 3. session.run + 提取 logits（锁内取 owned 副本后即释放锁）───
        let (shape, data): (Vec<i64>, Vec<f32>) = {
            let mut session = self
                .session
                .lock()
                .map_err(|e| EngineError::Internal(format!("session mutex poisoned: {e}")))?;
            let outputs = session
                .run(inputs![
                    "input_ids" => input_ids_val,
                    "attention_mask" => mask_val,
                ])
                .map_err(|e| EngineError::InferRun(e.to_string()))?;
            let (_name, logits_val) = outputs
                .iter()
                .next()
                .ok_or_else(|| EngineError::DecodeShape("no output tensor".to_string()))?;
            let (raw_shape, raw_data) = logits_val
                .try_extract_tensor::<f32>()
                .map_err(|e| EngineError::DecodeShape(e.to_string()))?;
            (raw_shape.to_vec(), raw_data.to_vec())
        };

        // ─── 4. 校验 shape = [1, 2]（二分类）───
        // 兼容 [1, 2] 与 [2]（部分导出省略 batch 维）；末维必须 ≥ 2 且含 injection_idx
        let num_labels = match shape.as_slice() {
            [1, n] => *n as usize,
            [n] => *n as usize,
            _ => {
                return Err(EngineError::DecodeShape(format!(
                    "unexpected logits shape (want [1,2] or [2]): {shape:?}"
                )));
            }
        };
        if num_labels < 2 || self.injection_idx >= num_labels || data.len() < num_labels {
            return Err(EngineError::DecodeShape(format!(
                "logits len/labels mismatch: shape={shape:?} data_len={}",
                data.len()
            )));
        }

        // ─── 5. max-shifted softmax，取 INJECTION 概率 ───
        // 减最大值防 exp 上溢（数值稳定的标准做法）
        let logits = &data[..num_labels];
        let max_logit = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let sum_exp: f32 = logits.iter().map(|&v| (v - max_logit).exp()).sum();
        if sum_exp <= 0.0 {
            return Ok(0.0);
        }
        let p_injection = (logits[self.injection_idx] - max_logit).exp() / sum_exp;
        Ok(p_injection)
    }

    /// 预热 session：用 1-token 短文本触发 cold-path（graph optimize / kernel JIT /
    /// arena 分配）一次性开销，把首调延迟前移到启动期。失败可忽略（fire-and-forget）。
    ///
    /// # Errors
    /// 同 [`classify`](Self::classify)；caller 通常 `let _ = c.warmup();` 忽略。
    pub fn warmup(&self) -> Result<(), EngineError> {
        let _ = self.classify("a")?;
        Ok(())
    }
}

/// 从 `config.json` 的 `label2id` 解析 `INJECTION` 的 index。
/// 标准导出 `{"INJECTION": 1, "SAFE": 0}`；缺失或非法时 fail-fast 返
/// [`EngineError::Internal`]（不静默 fallback，避免标签错位导致概率取反）。
fn parse_injection_idx(cfg_path: &Path) -> Result<usize, EngineError> {
    let raw = std::fs::read_to_string(cfg_path)
        .map_err(|e| EngineError::Internal(format!("read config.json: {e}")))?;
    let cfg: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| EngineError::Internal(format!("parse config.json: {e}")))?;
    // 优先 label2id["INJECTION"]；否则反查 id2label 里值为 "INJECTION" 的 key
    if let Some(idx) = cfg
        .get("label2id")
        .and_then(|v| v.get("INJECTION"))
        .and_then(|v| v.as_u64())
    {
        return Ok(idx as usize);
    }
    if let Some(obj) = cfg.get("id2label").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if v.as_str() == Some("INJECTION") {
                if let Ok(idx) = k.parse::<usize>() {
                    return Ok(idx);
                }
            }
        }
    }
    Err(EngineError::Internal(
        "config.json missing INJECTION label in label2id/id2label".to_string(),
    ))
}

// 编译期 Send + Sync 守门（--features ort 路径）
#[cfg(test)]
mod injection_static_assertions {
    use super::*;
    fn _assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn _check() {
        _assert_send_sync::<InjectionClassifier>();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    /// from_model_dir 在 dir 不存在/三件套缺失时返 ModelNotFound 不 panic。
    #[test]
    fn from_model_dir_missing_returns_modelnotfound() {
        let r = InjectionClassifier::from_model_dir(Path::new("/nonexistent/vigil/deberta"));
        assert!(
            matches!(r, Err(EngineError::ModelNotFound { .. })),
            "缺三件套应返 ModelNotFound,实际: {:?}",
            r.map(|_| "Ok")
        );
    }

    /// parse_injection_idx 正确解析标准 deberta config（label2id 路径）。
    #[test]
    fn parse_injection_idx_from_label2id() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.json");
        let mut f = std::fs::File::create(&cfg).unwrap();
        write!(
            f,
            r#"{{"id2label":{{"0":"SAFE","1":"INJECTION"}},"label2id":{{"SAFE":0,"INJECTION":1}}}}"#
        )
        .unwrap();
        assert_eq!(parse_injection_idx(&cfg).unwrap(), 1);
    }

    /// parse_injection_idx 在缺 label2id 时退回 id2label 反查。
    #[test]
    fn parse_injection_idx_fallback_id2label() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.json");
        let mut f = std::fs::File::create(&cfg).unwrap();
        // 故意把 INJECTION 放到 index 0,验证不是硬编码 1
        write!(f, r#"{{"id2label":{{"0":"INJECTION","1":"SAFE"}}}}"#).unwrap();
        assert_eq!(parse_injection_idx(&cfg).unwrap(), 0);
    }

    /// 缺 INJECTION 标签 → fail-fast Internal,不静默默认。
    #[test]
    fn parse_injection_idx_missing_label_fails() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.json");
        let mut f = std::fs::File::create(&cfg).unwrap();
        write!(f, r#"{{"id2label":{{"0":"FOO","1":"BAR"}}}}"#).unwrap();
        assert!(matches!(
            parse_injection_idx(&cfg),
            Err(EngineError::Internal(_))
        ));
    }
}
