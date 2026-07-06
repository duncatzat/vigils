//! daemon [`WireFinding`] 的安全应用原语(自 `vigil-hub-cli` hook.rs 抽出,纯移动)。
//!
//! 这些纯函数承载两条已修安全不变量,**任何 daemon 客户端(hook / native-host)必须共用**,
//! 防各自重实现漂移:
//!
//! - **VIGIL-SEC-OVERLAP(并集合并)**:daemon 可能对相邻实体吐嵌套/重叠 span;
//!   「重叠跳过」式实现会让外层 span 独有的 PII 前缀明文残留。[`apply_wire_spans`]
//!   先并集合并成互不重叠区间,保证被任一 span 命中的字节都落入某替换区间。
//! - **VIGIL-SEC-OVERLAP-PH(受保护区减法)**:daemon 在已脱敏(含 `[REDACTED …]`
//!   占位符)文本上扫描时,ML span 可 over-capture 延伸进占位符;直接替换会把真实
//!   占位符切碎成破碎嵌套。`protected` 携带脱敏流程**自产**的占位符字节区间,
//!   [`apply_wire_spans`] 对每个 ML 并集区间做 [`subtract_ranges`] 减法,只替换露在
//!   占位符之外的子区间。**安全**:不靠正则识别占位符形态(不可信文本可伪造假占位符
//!   把 PII 包进去)——只信调用方自产区间,伪造占位符包裹的真 PII 仍被替换。

use crate::protocol::WireFinding;

/// 字节 `cap` 处向下取整到 UTF-8 char boundary,返回 `&s[..n]`(`n ≤ cap`),避免切碎多字节字符。
pub fn cap_to_char_boundary(s: &str, cap: usize) -> &str {
    if s.len() <= cap {
        return s;
    }
    let mut n = cap;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// label 来自 daemon [`WireFinding`](应为 `PrivacyLabel` 闭集);防御性 sanitize:仅留 ascii 字母
/// 数字 + 下划线、截断 ≤32、空则 `pii`。**绝不**把 daemon 响应原样嵌进任何输出
/// (untrusted-input-not-in-errors 同理:即便 R1 已验对端,响应内容仍按不可信处理)。
pub fn safe_label(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "pii".to_string()
    } else {
        cleaned
    }
}

/// 把 daemon 的 [`WireFinding`] span(相对前 `scanned_len` 字节前缀)应用到 `seg`,命中处替换为
/// `[REDACTED <label>]`。空/逆序、越出扫描前缀、非 char-boundary 的 span 先剔除(防 panic + 防御),
/// **并集合并**成互不重叠区间,再减去 `protected`(真实占位符区间)后右→左替换露出的子区间。
///
/// 返回 `(替换后文本, 实际替换的子区间数)`;计数为 0 表示无任何改写(调用方据此决定
/// changed/审计标记)。并集/减法语义见模块级文档(VIGIL-SEC-OVERLAP / -PH)。
pub fn apply_wire_spans(
    seg: &str,
    scanned_len: usize,
    findings: &[WireFinding],
    protected: &[(usize, usize)],
) -> (String, usize) {
    // 剔除非法 span(空/逆序、越出扫描前缀、非 char-boundary),保留 (start, end, label)。
    let mut spans: Vec<(usize, usize, &str)> = findings
        .iter()
        .filter(|f| {
            f.start < f.end
                && f.end <= scanned_len
                && seg.is_char_boundary(f.start)
                && seg.is_char_boundary(f.end)
        })
        .map(|f| (f.start, f.end, f.label.as_str()))
        .collect();
    if spans.is_empty() {
        return (seg.to_string(), 0);
    }
    // start 升序、同 start 时 end 降序(长 span 作并集代表名)。
    spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    // 并集合并成互不重叠区间(代表 label 取并集内 start 最小→最长者)。
    let mut merged: Vec<(usize, usize, &str)> = Vec::with_capacity(spans.len());
    for (start, end, label) in spans {
        match merged.last_mut() {
            Some(last) if start < last.1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end, label)),
        }
    }
    // 受保护区减法(VIGIL-SEC-OVERLAP-PH):从每个 ML 并集区间减去真实占位符区间,只替换**露在占位符
    // 之外**的子区间。安全不变量:① 任何不在 protected 内、且被某 ML span 命中的字节,必落入某个被替换
    // 子区间(真 PII 不漏);② protected 内字节永不被 replace_range 触碰(已脱敏占位符不切碎)。
    let mut final_spans: Vec<(usize, usize, &str)> = Vec::new();
    for &(start, end, label) in &merged {
        for (ss, se) in subtract_ranges(start, end, protected) {
            final_spans.push((ss, se, label));
        }
    }
    // final_spans 全局升序(merged 升序且互不重叠 + 每个减法子区间升序)→ 右→左替换不漂移 index。
    let mut hits = 0usize;
    let mut out = seg.to_string();
    for &(start, end, label) in final_spans.iter().rev() {
        // 锁定 char-boundary 不变量:子区间端点来自 ML span(已过 is_char_boundary 滤)与 protected
        // 占位符端点(均为 push_str 处 len() 采样 → 必落 char 边界),故 replace_range 不会切碎多字节
        // 字符。debug_assert 防未来 protected 改由偏移算术得出(可能落 mid-char)而静默重引 panic 风险。
        debug_assert!(
            seg.is_char_boundary(start) && seg.is_char_boundary(end),
            "apply_wire_spans 子区间非 char-boundary: ({start},{end}) in {seg:?}"
        );
        out.replace_range(start..end, &format!("[REDACTED {}]", safe_label(label)));
        hits += 1;
    }
    (out, hits)
}

/// 返回 `[start, end)` 减去 `protected` 中所有区间后剩余的子区间(升序、互不重叠)。
/// `protected` 为脱敏流程自产的真实占位符区间(可乱序/重叠,内部先 clamp 到 `[start,end)` 再规整)。
/// 用于 [`apply_wire_spans`] 把 ML 并集区间裁掉与已脱敏占位符重叠的部分(VIGIL-SEC-OVERLAP-PH)。
pub fn subtract_ranges(
    start: usize,
    end: usize,
    protected: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    if start >= end {
        return Vec::new();
    }
    // 取与 [start,end) 相交的受保护区间(clamp 到窗口内),按 start 升序。
    let mut blocks: Vec<(usize, usize)> = protected
        .iter()
        .map(|&(a, b)| (a.max(start), b.min(end)))
        .filter(|&(a, b)| a < b)
        .collect();
    if blocks.is_empty() {
        return vec![(start, end)];
    }
    blocks.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut out = Vec::new();
    let mut cursor = start;
    for (a, b) in blocks {
        if a > cursor {
            out.push((cursor, a)); // 占位符之前露出的段
        }
        if b > cursor {
            cursor = b; // 跳过占位符(含重叠部分),游标前移到其右界
        }
    }
    if cursor < end {
        out.push((cursor, end)); // 末尾露出段
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{apply_wire_spans, cap_to_char_boundary, safe_label, subtract_ranges};
    use crate::protocol::WireFinding;

    fn wf(label: &str, start: usize, end: usize) -> WireFinding {
        WireFinding {
            label: label.to_string(),
            start,
            end,
        }
    }

    #[test]
    fn apply_wire_spans_single_span_redacts_with_label() {
        let (out, hits) =
            apply_wire_spans("alice@example.com here", 22, &[wf("email", 0, 17)], &[]);
        assert_eq!(out, "[REDACTED email] here");
        assert_eq!(hits, 1);
    }

    #[test]
    fn apply_wire_spans_multiple_spans_right_to_left_keep_offsets() {
        // 两个 span 降序应用,不挪未处理前缀 offset。
        let seg = "a alice@x.io b bob@y.io c";
        let (out, hits) = apply_wire_spans(
            seg,
            seg.len(),
            &[wf("email", 2, 12), wf("email", 15, 23)],
            &[],
        );
        assert_eq!(out, "a [REDACTED email] b [REDACTED email] c");
        assert_eq!(hits, 2);
    }

    #[test]
    fn apply_wire_spans_out_of_bounds_and_beyond_scanned_skipped() {
        let seg = "hello world";
        // end > scanned_len(5) / end > seg.len() / start>=end(逆序)→ 全跳过。
        let (out, hits) = apply_wire_spans(
            seg,
            5,
            &[wf("x", 0, 9), wf("y", 100, 200), wf("z", 4, 2)],
            &[],
        );
        assert_eq!(out, "hello world");
        assert_eq!(hits, 0);
    }

    #[test]
    fn apply_wire_spans_non_char_boundary_skipped() {
        // "héllo":é(U+00E9)= 2 字节占 [1,3);byte 2 落 é 中间 → 非 boundary → 跳过(防 panic)。
        let seg = "héllo";
        let (out, hits) = apply_wire_spans(seg, seg.len(), &[wf("x", 0, 2)], &[]);
        assert_eq!(out, seg);
        assert_eq!(hits, 0);
    }

    #[test]
    fn apply_wire_spans_overlap_union_merged_no_leak() {
        // 重叠 span 并集合并(VIGIL-SEC-OVERLAP):[3,7) 与 [5,9) → 并集 [3,9),全覆盖。
        // 旧"重叠跳过"实现会留下 [3,7) 独有的 "de"(残留泄漏 "abcde[REDACTED a]j");并集后无残留。
        let seg = "abcdefghij";
        let (out, hits) = apply_wire_spans(seg, seg.len(), &[wf("a", 5, 9), wf("b", 3, 7)], &[]);
        assert_eq!(out, "abc[REDACTED b]j", "重叠应并集为单一占位符,覆盖 [3,9)");
        assert!(!out.contains("de"), "[3,7) 独有前缀 de 不得残留:{out}");
        assert_eq!(hits, 1);
    }

    #[test]
    fn apply_wire_spans_nested_no_leak() {
        // 嵌套 span:外 [0,40] 套内 [15,40](内层长)。旧右→左 + 重叠跳过会跳过外层 →
        // 外层前缀 "Jonathan Whitfi" 明文泄漏("Jonathan Whitfi[REDACTED person]")。
        let seg = "Jonathan Whitfield Robert Smith Junior!!"; // 40 字节(ASCII)
        let (out, hits) = apply_wire_spans(
            seg,
            seg.len(),
            &[wf("person", 0, 40), wf("person", 15, 40)],
            &[],
        );
        assert!(!out.contains("Jonathan"), "外层 PII 前缀泄漏:{out}");
        assert_eq!(out, "[REDACTED person]", "嵌套应并集为单一占位符");
        assert_eq!(hits, 1);
    }

    #[test]
    fn apply_wire_spans_subtracts_protected_no_split() {
        // VIGIL-SEC-OVERLAP-PH:ML span over-capture 延伸进真实占位符 → 减法只替换露出部分,占位符不切碎。
        let seg = "x [REDACTED email] y"; // 占位符 "[REDACTED email]" 在 [2,18)
        let (out, hits) = apply_wire_spans(seg, seg.len(), &[wf("address", 0, 10)], &[(2, 18)]);
        assert_eq!(out, "[REDACTED address][REDACTED email] y");
        assert!(out.contains("[REDACTED email]"), "真实占位符不得被切碎");
        assert_eq!(hits, 1);
    }

    #[test]
    fn apply_wire_spans_span_fully_in_protected_dropped() {
        // ML span 完全落在真实占位符内 → 减法后空 → 不替换,占位符原样、无 hit。
        let seg = "x [REDACTED email] y";
        let (out, hits) = apply_wire_spans(seg, seg.len(), &[wf("pii", 4, 12)], &[(2, 18)]);
        assert_eq!(out, seg);
        assert_eq!(hits, 0);
    }

    #[test]
    fn apply_wire_spans_span_spanning_protected_splits() {
        // ML span 跨越整个占位符 → 减法切成左右两段各替换,占位符夹中间完整。
        let seg = "aa [REDACTED email] bb"; // 占位符 [3,19)
        let (out, hits) = apply_wire_spans(seg, seg.len(), &[wf("p", 0, 22)], &[(3, 19)]);
        assert_eq!(out, "[REDACTED p][REDACTED email][REDACTED p]");
        assert_eq!(hits, 2);
    }

    #[test]
    fn apply_wire_spans_forged_placeholder_not_protected() {
        // 不可信文本伪造 `[REDACTED x]` 包裹真 PII。伪造占位符**不在** protected(只含脱敏自产区间)→
        // ML span 命中其中真 PII 仍被替换,伪造无法让 ML 跳过(绕过脱敏)。
        let seg = "[REDACTED x]alice@evil.com[REDACTED y]"; // 真 PII alice@evil.com 在 [12,26)
        let (out, hits) = apply_wire_spans(seg, seg.len(), &[wf("email", 12, 26)], &[]);
        assert!(
            !out.contains("alice@evil.com"),
            "伪造占位符不得保护其包裹的真 PII"
        );
        assert!(out.contains("[REDACTED email]"));
        assert_eq!(hits, 1);
    }

    #[test]
    fn subtract_ranges_cases() {
        let empty = Vec::<(usize, usize)>::new();
        assert_eq!(subtract_ranges(0, 10, &[]), vec![(0, 10)]); // 无保护 → 原区间
        assert_eq!(subtract_ranges(0, 10, &[(2, 5)]), vec![(0, 2), (5, 10)]); // 中间挖洞
        assert_eq!(subtract_ranges(0, 10, &[(0, 10)]), empty); // 全保护 → 空
        assert_eq!(subtract_ranges(0, 10, &[(0, 4)]), vec![(4, 10)]); // 头部
        assert_eq!(subtract_ranges(0, 10, &[(6, 10)]), vec![(0, 6)]); // 尾部
        assert_eq!(
            subtract_ranges(0, 10, &[(3, 5), (6, 8)]),
            vec![(0, 3), (5, 6), (8, 10)]
        ); // 多洞
        assert_eq!(
            subtract_ranges(0, 10, &[(2, 6), (4, 8)]),
            vec![(0, 2), (8, 10)]
        ); // 重叠 block
        assert_eq!(subtract_ranges(0, 10, &[(5, 5), (8, 4)]), vec![(0, 10)]); // 空/逆序 block 过滤
        assert_eq!(subtract_ranges(5, 5, &[]), empty); // 空窗口
        assert_eq!(subtract_ranges(2, 8, &[(0, 4), (6, 20)]), vec![(4, 6)]); // protected 越界 → clamp
    }

    #[test]
    fn cap_to_char_boundary_floors_to_boundary() {
        assert_eq!(cap_to_char_boundary("hello", 100), "hello");
        assert_eq!(cap_to_char_boundary("hello", 3), "hel");
        // "aéb":é 占 [1,3);cap=2 落 é 中间 → 退到 1 → "a"。
        assert_eq!(cap_to_char_boundary("aéb", 2), "a");
    }

    #[test]
    fn safe_label_sanitizes_and_caps() {
        assert_eq!(safe_label("email"), "email");
        assert_eq!(safe_label("private_phone"), "private_phone");
        // 非白名单字符(空格/分号/方括号/连字符)全过滤(防把 daemon 响应原样嵌进输出)。
        assert_eq!(safe_label("e]mail[injection"), "emailinjection");
        assert_eq!(safe_label("a b;c"), "abc");
        assert_eq!(safe_label("na-me"), "name");
        assert_eq!(safe_label(""), "pii");
        assert_eq!(safe_label("!!!"), "pii");
        assert_eq!(safe_label(&"x".repeat(100)).len(), 32);
    }
}
