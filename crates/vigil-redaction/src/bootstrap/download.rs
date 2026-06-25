//! 16-chunk byte-range 并发下载 + ETag/304 短路。
//!
//! # 关键算法(ADR 0012 §3.4)
//!
//! 1. **HEAD 探测**:拿 Content-Length(必须与 manifest 一致)+ ETag。
//! 2. **ETag 持久化**:按 URL 维度写 `target_dir/.etag.<url_short_hash>`,避免 mirror
//!    与 HF CDN ETag 误判 304(两端 ETag 不互通)。
//! 3. **If-None-Match**:GET 请求带本地 ETag,服务端返 304 表示对象未变 →
//!    上层用本地落盘三件套,**不**触发 16-chunk 并发。
//! 4. **200 全量**:`chunk_size = (total + 15) / 16`,16 worker 各持一个 Range
//!    `bytes={start}-{end}`(inclusive)写到 `.partial.<idx>`。
//!
//! # 故障处理
//!
//! - 单 chunk timeout 30s + 1 次 retry,失败转 [`BootstrapError::DownloadFailed`]。
//! - 同一 URL 任一 chunk 终态失败 → 整轮放弃,切 fallback URL 重新跑 16 worker。
//! - 全部 URL 用尽 → [`BootstrapError::NetworkUnreachable`] 含完整 tried_urls。

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_LENGTH, ETAG, IF_NONE_MATCH, RANGE};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};

use super::error::BootstrapError;

/// 控制类小请求超时(ETag 短路 GET `Range: 0-0` 等轻请求)。
/// 注:**chunk 体下载**不再用此固定值 —— 见 [`chunk_timeout`](按 chunk 大小动态定)。
const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

// chunk 体下载的动态超时参数。
//
// 根因复盘(v0.4.0 Linux 真机):16 chunk **并发共享带宽**,~48 MB/chunk 在 ~11.5 MB/s 链路上
// 单 chunk 实测 ~65s;旧固定 30s **总请求**超时会中途砍断 body 读取(reqwest
// "error decoding response body")→ 整下载失败,而 curl(无超时)同链路 70s 跑完。
// 旧注释"30s 在 5 MB/s 慢线够"忽略了 16 路并发每路只剩 ~0.7 MB/s。
// 改:按 chunk 字节数 / 最低可接受吞吐换算超时,使"慢但持续推进"的链路也能成功;
// truly-dead 连接由 `connect_timeout`(10s)兜底,极端中途 stall 由 ceil 上限收敛。
const MIN_CHUNK_BYTES_PER_SEC: u64 = 128 * 1024; // 128 KiB/s/chunk(≈ 2 MiB/s 聚合 @16）
const CHUNK_TIMEOUT_FLOOR_SECS: u64 = 60;
const CHUNK_TIMEOUT_CEIL_SECS: u64 = 900; // 与单流路径 900s 上限一致

/// 按本 chunk 大小推导**下载体**总超时,夹逼到 `[floor, ceil]`。
fn chunk_timeout(chunk_bytes: u64) -> Duration {
    let secs =
        (chunk_bytes / MIN_CHUNK_BYTES_PER_SEC).clamp(CHUNK_TIMEOUT_FLOOR_SECS, CHUNK_TIMEOUT_CEIL_SECS);
    Duration::from_secs(secs)
}

/// HEAD 探测同样 30s 上限(轻请求,正常 < 1s)。
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// chunk 失败重试次数(共 1 + 1 = 2 次尝试)。
const RETRY_PER_CHUNK: u32 = 1;

// 注:WORKER_COUNT 不写常量;manifest.chunk_count 是 SSOT(ADR 0012 §3.4 默认 16),
// 由 caller 通过 chunk_count 参数注入,避免双源真相。

/// 下载结果:成功路径返写入磁盘的最终文件路径(已串接 + 已 sha256 校验)。
///
/// **本函数职责边界**:只做"下载 + 串接"。整文件 sha256 校验由 [`super::verify`] 串接后调用,
/// 因为 chunk 串接与 sha256 校验语义独立(可分别测试)。
#[derive(Debug)]
pub struct DownloadOutcome {
    /// 串接产出的最终文件绝对路径(target_dir/<file_name>)。已含全部字节。
    pub final_path: PathBuf,
    /// 本次实际触发了网络下载(false = ETag 304 短路命中,0 chunk 请求)。
    pub downloaded: bool,
}

/// 主入口:下载单个 manifest 文件到 target_dir。
///
/// # 流程
///
/// 1. 按 urls 顺序尝试 HEAD 探测;首个成功的 URL 进入下载流程。
/// 2. 检查 `.etag.<url_short_hash>` 存在 + final_path 存在 → GET If-None-Match
///    收到 304 立即返 `downloaded: false`(由 caller decide 是否再算 sha256)。
/// 3. 否则按 `chunk_count` 切分,16 worker 并发 GET Range,各写 `.partial.<idx>`。
/// 4. 串接 .partial.0..N 为最终文件,写新 ETag(若 HEAD 给了)。
/// 5. 任一 URL 全失败 → 切下一个;全部 URL 失败 → NetworkUnreachable。
///
/// # 不做的事
///
/// - 整文件 sha256 校验(caller 调 [`super::verify::verify_sha256_streaming`])
/// - .partial.* 残留预清扫(caller 调 [`super::verify::cleanup_partials`])
pub fn download_with_chunks(
    urls: &[String],
    target_dir: &Path,
    file_name: &str,
    expected_size: u64,
    chunk_count: u32,
) -> Result<DownloadOutcome, BootstrapError> {
    if urls.is_empty() {
        return Err(BootstrapError::NetworkUnreachable {
            tried_urls: Vec::new(),
            last_error: "no urls provided".to_string(),
        });
    }

    let final_path = target_dir.join(file_name);
    let mut tried: Vec<String> = Vec::with_capacity(urls.len());
    let mut last_err: String = String::new();

    for url in urls {
        tried.push(url.clone());

        let client = match build_client(CHUNK_TIMEOUT) {
            Ok(c) => c,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };

        // 1. ETag 短路:本地 etag 文件 + final 文件都在 → GET If-None-Match
        let etag_path = etag_path_for(target_dir, url);
        if final_path.exists() {
            if let Some(stored_etag) = read_existing_etag(&etag_path) {
                match try_etag_short_circuit(&client, url, &stored_etag) {
                    Ok(true) => {
                        return Ok(DownloadOutcome {
                            final_path,
                            downloaded: false,
                        });
                    }
                    Ok(false) => { /* 200 → 走全量 */ }
                    Err(_e) => {
                        // ETag 探测失败不致命,降级到 HEAD + 全量;
                        // 不覆盖 last_err(后续 HEAD 失败会写它,这里写了也读不到)
                    }
                }
            }
        }

        // 2. HEAD 探测(Content-Length + ETag)
        let head_client = match build_client(HEAD_TIMEOUT) {
            Ok(c) => c,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };
        let (server_size, etag_opt) = match head_probe(&head_client, url) {
            Ok(v) => v,
            Err(e) => {
                last_err = format!("HEAD {url}: {e}");
                continue;
            }
        };
        // server 给了 size 就严格校对;给 0(未声明)则跳过 size check 用 manifest size
        if server_size != 0 && server_size != expected_size {
            last_err = format!(
                "HEAD {url}: Content-Length={server_size} 与 manifest size={expected_size} 不符"
            );
            continue;
        }

        // 3. 下载策略选择(byte-range 支持探测)。
        //    16-chunk 并发依赖 server 对 Range 返 206 Partial Content。但 CF/nginx 会对
        //    `application/json` 这类 Content-Type 做 on-the-fly 压缩/动态处理 → 压缩响应不可
        //    range → server 对 Range 请求返 **200 全量**。16 worker 各拿全量会写出 16× 损坏
        //    → sha256 mismatch。真机镜像 fallback 验证暴露(vigils.ai tokenizer.json)。
        //    故先探测:支持 range → 16-chunk;否则单流(reqwest 自解压得正确字节)。
        let _ = client; // 主 client 不复用,每 worker 自建(避免跨线程共享 Client 的复杂性)
        if url_supports_ranges(url) {
            match download_all_chunks(url, target_dir, expected_size, chunk_count) {
                Ok(()) => {}
                Err(e) => {
                    last_err = format!("download chunks from {url}: {e}");
                    // 失败时清掉这个 URL 产出的 .partial.*(避免污染下一 URL)
                    let _ = super::verify::cleanup_partials(target_dir);
                    continue;
                }
            }

            // 4. 串接 .partial.0..N → final_path(此处不做 sha256;由 caller 调 verify)
            if let Err(e) = super::verify::assemble_chunks(target_dir, chunk_count, file_name) {
                last_err = format!("assemble chunks: {e}");
                let _ = super::verify::cleanup_partials(target_dir);
                continue;
            }
        } else {
            // 单流 GET → final_path(不分块)。caller 仍做整文件 sha256 校验,损坏即 fail-closed。
            if let Err(e) = download_single_stream(url, &final_path) {
                last_err = format!("single-stream from {url}: {e}");
                let _ = fs::remove_file(&final_path);
                continue;
            }
        }

        // 5. 持久化新 ETag(若 server 给了),供下次启动 304 短路
        if let Some(etag) = etag_opt {
            if let Err(e) = fs::write(&etag_path, etag.as_bytes()) {
                // ETag 写失败不致命(下次走全量),但记一下 stderr 便于诊断
                eprintln!(
                    "[vigil-bootstrap] warn: persist etag failed: {} ({})",
                    etag_path.display(),
                    e
                );
            }
        }

        return Ok(DownloadOutcome {
            final_path,
            downloaded: true,
        });
    }

    Err(BootstrapError::NetworkUnreachable {
        tried_urls: tried,
        last_error: last_err,
    })
}

/// 构造 reqwest blocking Client(每次构造,避免 Send 跨线程的复杂性;reqwest
/// blocking client 内部已是 Arc,构造廉价)。
fn build_client(timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .build()
}

/// HEAD 探测:返 (Content-Length, ETag)。
/// Content-Length 缺失或不可解析返 0(让 caller 跳过 size check)。
fn head_probe(client: &Client, url: &str) -> Result<(u64, Option<String>), reqwest::Error> {
    let resp = client.head(url).send()?;
    let status = resp.status();
    if !status.is_success() {
        // 把 HTTP 错误转 reqwest::Error 比较绕(reqwest 本身没暴露构造函数);
        // 用 error_for_status 间接构造同样诊断意义的 Err。
        return Err(resp.error_for_status().unwrap_err());
    }
    let len = resp
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    Ok((len, etag))
}

/// byte-range 支持探测:`GET Range: bytes=0-0` + `Accept-Encoding: identity`。
///
/// 返 `true` 仅当 server 返 **206 Partial Content**(真支持 range)。任何非 206
/// (尤其 CF 对压缩/动态资源返 200 全量)→ `false` → caller 走单流,避免 16-chunk
/// 对不可 range 资源的 16× 全量损坏。`identity` 避免 server gzip 后再无视 range。
/// 探测自身出错也返 `false`(单流恒安全;真不可达由后续单流/HEAD 暴露)。
fn url_supports_ranges(url: &str) -> bool {
    let client = match build_client(HEAD_TIMEOUT) {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .get(url)
        .header(RANGE, "bytes=0-0")
        .header(ACCEPT_ENCODING, "identity")
        .send()
    {
        Ok(resp) => resp.status() == StatusCode::PARTIAL_CONTENT,
        Err(_) => false,
    }
}

/// 单流下载:`GET url` → 流式写 `final_path`(不经 `.partial` 分块)。
///
/// 用于 server 不支持 byte-range 的 mirror(CF 压缩 JSON 等 [`url_supports_ranges`] 返 false)。
/// 允许默认编码:reqwest 解压后落盘即正确字节;sha256 由 caller 整文件校验。流式 `copy_to`
/// 避免把 ~800 MB weights 全读进内存。timeout 给足(900s)兼顾慢线大文件单流。
fn download_single_stream(url: &str, final_path: &Path) -> Result<(), BootstrapError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(900))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| BootstrapError::DownloadFailed {
            url: url.to_string(),
            status: 0,
            source: e,
        })?;
    let mut resp = client
        .get(url)
        .send()
        .map_err(|e| BootstrapError::DownloadFailed {
            url: url.to_string(),
            status: 0,
            source: e,
        })?;
    let status = resp.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        return Err(BootstrapError::DownloadFailed {
            url: url.to_string(),
            status: status_code,
            // 非 2xx → error_for_status 必返 Err(与 fetch_chunk_once 同惯用法)
            source: resp.error_for_status().unwrap_err(),
        });
    }
    let mut f = File::create(final_path).map_err(|e| BootstrapError::DiskFull {
        path: final_path.to_path_buf(),
        source: e,
    })?;
    resp.copy_to(&mut f)
        .map_err(|e| BootstrapError::DownloadFailed {
            url: url.to_string(),
            status: status.as_u16(),
            source: e,
        })?;
    Ok(())
}

/// 试用 If-None-Match 探测 304。
///
/// 返 `Ok(true)` = 304(可复用本地);`Ok(false)` = 200(需全量);Err = 网络/HTTP 错误。
fn try_etag_short_circuit(
    client: &Client,
    url: &str,
    stored_etag: &str,
) -> Result<bool, reqwest::Error> {
    let resp = client
        .get(url)
        .header(IF_NONE_MATCH, stored_etag)
        // 限制只读 header(避免 server 真返完整 body 浪费带宽);加 Range 0-0
        .header(RANGE, "bytes=0-0")
        .send()?;
    Ok(resp.status() == StatusCode::NOT_MODIFIED)
}

/// 16-chunk 并发下载主体。每 worker 持自己的 Client + Range GET → `.partial.<idx>`。
///
/// 用 std::thread::scope 让 worker 借用 client / target_dir / url 而无需 Arc。
/// chunk_size = (total + N - 1) / N(ceil);最后 chunk 的 end = total - 1(inclusive),
/// 含 remainder。
fn download_all_chunks(
    url: &str,
    target_dir: &Path,
    total: u64,
    chunk_count: u32,
) -> Result<(), BootstrapError> {
    if chunk_count == 0 {
        return Err(BootstrapError::DiskFull {
            path: target_dir.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "chunk_count must be > 0",
            ),
        });
    }
    let n = chunk_count as u64;
    let chunk_size = total.div_ceil(n).max(1);

    // 用 std::thread::scope 起 N worker。每 worker 算自己的 (start, end) inclusive。
    // 收集结果到 Vec<Result>,主线程汇总。
    let mut results: Vec<Result<(), BootstrapError>> = Vec::with_capacity(chunk_count as usize);
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunk_count as usize);
        for idx in 0..chunk_count {
            let start = (idx as u64) * chunk_size;
            if start >= total {
                // total 比 chunk_count 还小的极端:多余的 worker 写空文件
                handles.push(s.spawn(move || write_empty_partial(target_dir, idx)));
                continue;
            }
            let end_excl = ((idx as u64 + 1) * chunk_size).min(total);
            let end_incl = end_excl - 1;
            handles.push(
                s.spawn(move || fetch_chunk_with_retry(url, target_dir, idx, start, end_incl)),
            );
        }
        for h in handles {
            // join 永不 panic 用 ok_or 兜底(线程内 panic 转 chunk 失败)
            let r = h.join().unwrap_or_else(|_| {
                Err(BootstrapError::NetworkUnreachable {
                    tried_urls: vec![url.to_string()],
                    last_error: "worker thread panicked".to_string(),
                })
            });
            results.push(r);
        }
    });

    // 任一 chunk 失败即整轮失败(由 caller 切 fallback URL)
    for r in results {
        r?;
    }
    Ok(())
}

/// 单 chunk 下载 + 1 次 retry。
fn fetch_chunk_with_retry(
    url: &str,
    target_dir: &Path,
    idx: u32,
    start: u64,
    end_incl: u64,
) -> Result<(), BootstrapError> {
    let mut last: Option<BootstrapError> = None;
    for _attempt in 0..=RETRY_PER_CHUNK {
        match fetch_chunk_once(url, target_dir, idx, start, end_incl) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| BootstrapError::NetworkUnreachable {
        tried_urls: vec![url.to_string()],
        last_error: "all retries exhausted (no error captured)".to_string(),
    }))
}

/// 真正的 chunk 下载:GET Range bytes=start-end → 写 .partial.<idx>。
fn fetch_chunk_once(
    url: &str,
    target_dir: &Path,
    idx: u32,
    start: u64,
    end_incl: u64,
) -> Result<(), BootstrapError> {
    // 按本 chunk 大小定**下载体**超时(见 chunk_timeout):16 路并发共享带宽时,大 chunk
    // 合法地需要 >30s;固定 30s 总超时会砍断进行中的 body 读取(v0.4.0 Linux 真机失败根因)。
    let client = build_client(chunk_timeout(end_incl - start + 1)).map_err(|e| {
        BootstrapError::DownloadFailed {
            url: url.to_string(),
            status: 0,
            source: e,
        }
    })?;
    let range_val = format!("bytes={start}-{end_incl}");
    // Accept-Encoding: identity 必须与 url_supports_ranges 探测一致 —— 否则探测(identity)
    // 见 206、实际 chunk(默认编码)若被 server 压缩成 200/压缩-206 即损坏或失败。同 header
    // 保证"探测判定可 range"对实际下载成立(Codex review FIX-REQUIRED)。
    let resp = client
        .get(url)
        .header(RANGE, &range_val)
        .header(ACCEPT_ENCODING, "identity")
        .send()
        .map_err(|e| BootstrapError::DownloadFailed {
            url: url.to_string(),
            status: 0,
            source: e,
        })?;
    let status = resp.status();
    // 严格只接受 206 Partial Content。200 = server 无视 Range 返全量(CF 压缩/动态资源);
    // 接受它会把整文件写进单个 .partial.<idx> → 16-chunk 组装 16× 损坏(真机镜像 fallback
    // 验证 tokenizer.json 暴露)。正常流由 download_file 的 url_supports_ranges 预探测把不可
    // range 资源路由到单流;此处严格化兜底:rangeable URL 某 chunk 中途翻车也立即失败,不污染。
    if status != StatusCode::PARTIAL_CONTENT {
        let status_code = status.as_u16();
        // 4xx/5xx 有 reqwest::Error 源;200(无视 range)无错误源 → NetworkUnreachable 表达
        if let Err(src) = resp.error_for_status() {
            return Err(BootstrapError::DownloadFailed {
                url: url.to_string(),
                status: status_code,
                source: src,
            });
        }
        return Err(BootstrapError::NetworkUnreachable {
            tried_urls: vec![url.to_string()],
            last_error: format!(
                "url={url} 对 Range 返 {status_code}(非 206);mirror 不支持 byte-range"
            ),
        });
    }
    let bytes = resp.bytes().map_err(|e| BootstrapError::DownloadFailed {
        url: url.to_string(),
        status: status.as_u16(),
        source: e,
    })?;

    let partial_path = target_dir.join(format!(".partial.{idx}"));
    let mut f = File::create(&partial_path).map_err(|e| BootstrapError::DiskFull {
        path: partial_path.clone(),
        source: e,
    })?;
    f.write_all(&bytes).map_err(|e| BootstrapError::DiskFull {
        path: partial_path.clone(),
        source: e,
    })?;
    f.flush().map_err(|e| BootstrapError::DiskFull {
        path: partial_path,
        source: e,
    })?;
    Ok(())
}

/// 写空 .partial.<idx>(total < chunk_count 时填充用)。
fn write_empty_partial(target_dir: &Path, idx: u32) -> Result<(), BootstrapError> {
    let partial_path = target_dir.join(format!(".partial.{idx}"));
    File::create(&partial_path)
        .map_err(|e| BootstrapError::DiskFull {
            path: partial_path,
            source: e,
        })
        .map(|_| ())
}

/// ETag 旁文件路径:`<target_dir>/.etag.<short_hash>`。
///
/// short_hash = sha256(url) 前 8 字符(hex)。够区分常见 URL,文件名不超长。
fn etag_path_for(target_dir: &Path, url: &str) -> PathBuf {
    let digest = Sha256::digest(url.as_bytes());
    let hex_full = hex::encode(digest);
    let short = &hex_full[..8];
    target_dir.join(format!(".etag.{short}"))
}

/// 读取已存在的 ETag(若失败 / 不存在返 None)。
fn read_existing_etag(etag_path: &Path) -> Option<String> {
    fs::read_to_string(etag_path).ok().and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod chunk_math_tests {
    //! chunk_size 边界数学单测(不依赖网络)。
    //!
    //! Range header 必须严格 inclusive bytes=start-end,且最后一 chunk 含 remainder。

    #[test]
    fn chunk_size_total_100_n_16_last_chunk_has_remainder() {
        // ceil(100/16) = 7;chunks: 0..7, 7..14, ..., 91..98, 98..100(最后 2 字节)
        let total: u64 = 100;
        let n: u64 = 16;
        let chunk = total.div_ceil(n);
        assert_eq!(chunk, 7);
        // 最后非空 chunk:idx 14 → start = 98,end_excl = min(105, 100) = 100,end_incl = 99
        let idx: u64 = 14;
        let start = idx * chunk;
        let end_excl = ((idx + 1) * chunk).min(total);
        let end_incl = end_excl - 1;
        assert_eq!(start, 98);
        assert_eq!(end_incl, 99);
        // idx 15 应进 start >= total 分支(15*7 = 105 >= 100)
        assert!(15 * chunk >= total);
    }

    #[test]
    fn chunk_size_total_15_n_16_only_15_active_workers() {
        let total: u64 = 15;
        let n: u64 = 16;
        let chunk = total.div_ceil(n).max(1); // = 1
        assert_eq!(chunk, 1);
        // idx 15 → start = 15 >= 15 → 空 partial
        assert_eq!(15u64 * chunk, total);
    }

    #[test]
    fn chunk_size_total_1_n_16_only_first_active() {
        let total: u64 = 1;
        let n: u64 = 16;
        let chunk = total.div_ceil(n).max(1); // = 1
        assert_eq!(chunk, 1);
        // idx 0:start=0, end_incl=0 → 单字节;idx 1+:start>=1 → 空 partial
    }

    #[test]
    fn chunk_timeout_scales_with_size_and_clamps() {
        use super::{chunk_timeout, CHUNK_TIMEOUT_CEIL_SECS, CHUNK_TIMEOUT_FLOOR_SECS};
        // 小请求 → floor(不让 3 KB config 等 900s)
        assert_eq!(chunk_timeout(1024).as_secs(), CHUNK_TIMEOUT_FLOOR_SECS);
        // ~48 MiB chunk(真机失败规模):远超旧 30s,且 < ceil → 慢链路也能跑完
        let secs = chunk_timeout(50_566_375).as_secs();
        assert!(secs > 300, "48MB chunk timeout should comfortably exceed 65s real time, got {secs}");
        assert!(secs <= CHUNK_TIMEOUT_CEIL_SECS);
        // 超大 → ceil 收敛
        assert_eq!(chunk_timeout(u64::MAX).as_secs(), CHUNK_TIMEOUT_CEIL_SECS);
    }
}
