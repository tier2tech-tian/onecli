//! 旁路读取模型回复里的 token 用量，补进同一条额度用量记录（`quota_usage`）。
//!
//! 隔离原则（大杰 10-31：出异常不能影响主流程、不能把网关搞挂）：
//! - 转发路径上只做一件事：把每段回复的 `Bytes` 引用计数克隆一份、`try_send` 给旁路任务。
//!   不改、不拦、不等任何字节；旁路队列满或已关就停止投递，转发照旧。
//! - 解压、拆行、解析 JSON 全在独立的旁路任务里做。解析失败、数据不完整、压缩格式不认识，
//!   一律只是"这条记录没有 token 数"，额度那几列照常写。
//! - 网关 release 编译是 `panic = "abort"`，`catch_unwind` 兜不住，所以本模块按"不可能 panic"写：
//!   不用 unwrap / expect / 下标切片，数值一律 checked / saturating，锁中毒照常取用，缓冲区全部有上限。
//!
//! 数据来源（10-31 经网关实测）：Claude Code 带 `Accept-Encoding: gzip, deflate, br, zstd`，
//! Anthropic 回 `Content-Encoding: gzip` 的 SSE。用量在 `message_start.message.usage`（输入/缓存）
//! 和 `message_delta.usage`（累计值，含输出）里；非流式回复是整段 JSON 的顶层 `usage`。
use futures_util::StreamExt;
use hyper::body::Bytes;
use hyper::HeaderMap;
use std::io::Write;
use tokio::sync::mpsc;
use tracing::debug;

use super::hooks::BodyStream;

/// 旁路队列能积压多少段（一段通常几百字节到几 KB）；满了说明旁路跟不上，直接放弃这条的 token
const CHANNEL_CAP: usize = 256;
/// 解压后最多看多少字节，防压缩炸弹
const MAX_DECODED: usize = 64 * 1024 * 1024;
/// SSE 单行最长；超长行（正文大块文字）直接跳过，不会是用量行
const MAX_LINE: usize = 1024 * 1024;
/// 非流式 JSON 最多缓存多少
const MAX_JSON: usize = 4 * 1024 * 1024;

/// 一条回复的 token 用量。字段缺失就是 None。
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct TokenUsage {
    pub model: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cache_creation_input_tokens: Option<i64>,
    pub cache_read_input_tokens: Option<i64>,
}

impl TokenUsage {
    fn is_empty(&self) -> bool {
        self.input_tokens.is_none()
            && self.output_tokens.is_none()
            && self.cache_creation_input_tokens.is_none()
            && self.cache_read_input_tokens.is_none()
    }

    /// 合并一个 usage 对象：出现的字段覆盖旧值（message_delta 里是累计值，后到的就是最终值）
    fn merge_usage(&mut self, usage: &serde_json::Value) {
        let field = |k: &str| {
            usage
                .get(k)
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| i64::try_from(v).ok())
        };
        if let Some(v) = field("input_tokens") {
            self.input_tokens = Some(v);
        }
        if let Some(v) = field("output_tokens") {
            self.output_tokens = Some(v);
        }
        if let Some(v) = field("cache_creation_input_tokens") {
            self.cache_creation_input_tokens = Some(v);
        }
        if let Some(v) = field("cache_read_input_tokens") {
            self.cache_read_input_tokens = Some(v);
        }
    }

    fn merge_model(&mut self, model: Option<&serde_json::Value>) {
        if let Some(m) = model.and_then(serde_json::Value::as_str) {
            if !m.is_empty() && m.len() <= 200 {
                self.model = Some(m.to_owned());
            }
        }
    }

    /// 一个 SSE 事件或整段 JSON
    fn merge_event(&mut self, v: &serde_json::Value) {
        match v.get("type").and_then(serde_json::Value::as_str) {
            Some("message_start") => {
                if let Some(msg) = v.get("message") {
                    self.merge_model(msg.get("model"));
                    if let Some(u) = msg.get("usage") {
                        self.merge_usage(u);
                    }
                }
            }
            // message_delta；以及非流式回复（type=message，顶层就有 model/usage）
            _ => {
                self.merge_model(v.get("model"));
                if let Some(u) = v.get("usage") {
                    self.merge_usage(u);
                }
            }
        }
    }
}

enum Decoder {
    Identity,
    Gzip(Box<flate2::write::GzDecoder<Vec<u8>>>),
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Format {
    Sse,
    Json,
}

/// 纯同步的解析器：喂压缩/未压缩的分段，产出用量。任何异常只把自己标成 broken。
struct Parser {
    decoder: Decoder,
    format: Format,
    buf: Vec<u8>,
    /// 当前行超长，丢到下一个换行为止
    skipping_line: bool,
    decoded: usize,
    broken: bool,
    usage: TokenUsage,
}

impl Parser {
    fn new(decoder: Decoder, format: Format) -> Self {
        Self {
            decoder,
            format,
            buf: Vec::new(),
            skipping_line: false,
            decoded: 0,
            broken: false,
            usage: TokenUsage::default(),
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        if self.broken {
            return;
        }
        let plain = match &mut self.decoder {
            Decoder::Identity => chunk.to_vec(),
            Decoder::Gzip(d) => {
                if d.write_all(chunk).is_err() {
                    self.broken = true;
                    return;
                }
                std::mem::take(d.get_mut())
            }
        };
        self.decoded = self.decoded.saturating_add(plain.len());
        if self.decoded > MAX_DECODED {
            self.broken = true;
            return;
        }
        match self.format {
            Format::Sse => self.feed_sse(&plain),
            Format::Json => {
                if self.buf.len().saturating_add(plain.len()) > MAX_JSON {
                    self.broken = true;
                    return;
                }
                self.buf.extend_from_slice(&plain);
            }
        }
    }

    fn feed_sse(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match data.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    let (head, rest) = data.split_at(pos);
                    // rest 以 '\n' 开头，去掉它
                    data = rest.get(1..).unwrap_or(&[]);
                    if self.skipping_line {
                        self.skipping_line = false;
                        self.buf.clear();
                        continue;
                    }
                    if self.buf.len().saturating_add(head.len()) > MAX_LINE {
                        self.buf.clear();
                        continue;
                    }
                    self.buf.extend_from_slice(head);
                    let line = std::mem::take(&mut self.buf);
                    self.line(&line);
                }
                None => {
                    if !self.skipping_line {
                        if self.buf.len().saturating_add(data.len()) > MAX_LINE {
                            self.buf.clear();
                            self.skipping_line = true;
                        } else {
                            self.buf.extend_from_slice(data);
                        }
                    }
                    data = &[];
                }
            }
        }
    }

    fn line(&mut self, line: &[u8]) {
        let Some(payload) = line.strip_prefix(b"data:") else {
            return;
        };
        // 只解析带 usage 的行，正文增量行直接跳过
        if !contains(payload, b"\"usage\"") {
            return;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload.trim_ascii()) {
            self.usage.merge_event(&v);
        }
    }

    /// 回复结束（或客户端断开）。返回有数的用量；一个数都没有就 None。
    fn finish(mut self) -> Option<TokenUsage> {
        if !self.broken {
            if let Decoder::Gzip(d) = &mut self.decoder {
                // 把解压器里剩余的吐出来；流被截断时这里会报错，已解析的照样算
                if d.try_finish().is_ok() {
                    let rest = std::mem::take(d.get_mut());
                    match self.format {
                        Format::Sse => self.feed_sse(&rest),
                        Format::Json => {
                            if self.buf.len().saturating_add(rest.len()) <= MAX_JSON {
                                self.buf.extend_from_slice(&rest);
                            }
                        }
                    }
                }
            }
            match self.format {
                // 最后一行可能没有换行
                Format::Sse if !self.skipping_line && !self.buf.is_empty() => {
                    let line = std::mem::take(&mut self.buf);
                    self.line(&line);
                }
                Format::Json => {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&self.buf) {
                        self.usage.merge_event(&v);
                    }
                }
                _ => {}
            }
        }
        (!self.usage.is_empty()).then_some(self.usage)
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

/// 按回复头决定怎么解析；认不出的压缩或内容类型返回 None（这条只记额度，不记 token）
fn parser_for(headers: &HeaderMap) -> Option<Parser> {
    let ct = header_str(headers, "content-type")?.to_ascii_lowercase();
    let format = if ct.starts_with("text/event-stream") {
        Format::Sse
    } else if ct.starts_with("application/json") {
        Format::Json
    } else {
        return None;
    };
    let decoder = match header_str(headers, "content-encoding").map(str::to_ascii_lowercase) {
        None => Decoder::Identity,
        Some(e) if e.is_empty() || e == "identity" => Decoder::Identity,
        Some(e) if e == "gzip" || e == "x-gzip" => {
            Decoder::Gzip(Box::new(flate2::write::GzDecoder::new(Vec::new())))
        }
        Some(_) => return None,
    };
    Some(Parser::new(decoder, format))
}

/// 转发出口调用：把回复流原样交回，同时（仅当这条回复有待补 token 的额度记录时）旁路读用量。
/// 没有待补记录、格式不认识时直接返回原流，零开销。
pub(super) fn wrap(stream: BodyStream, host: &str, path: &str, headers: &HeaderMap) -> BodyStream {
    if !super::cooldown::applies(host, path) {
        return stream;
    }
    let Some(request_id) = header_str(headers, "request-id") else {
        return stream;
    };
    let Some(held) = super::quota_usage::take_held(request_id) else {
        return stream;
    };
    let Some(mut parser) = parser_for(headers) else {
        debug!(
            content_type = ?header_str(headers, "content-type"),
            content_encoding = ?header_str(headers, "content-encoding"),
            "回复格式不认识，只记额度不记 token"
        );
        super::quota_usage::complete(held, None);
        return stream;
    };
    let (tx, mut rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
    tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            parser.feed(&chunk);
        }
        // 发送端随回复流一起释放（正常结束、客户端断开、上游出错都一样）→ 收尾写记录
        super::quota_usage::complete(held, parser.finish());
    });
    let mut tx = Some(tx);
    Box::pin(stream.inspect(move |item| {
        let Ok(frame) = item else {
            return;
        };
        let Some(data) = frame.data_ref() else {
            return;
        };
        if let Some(sender) = &tx {
            if sender.try_send(data.clone()).is_err() {
                // 旁路跟不上或已退出：不再投递，这条 token 数会不完整，转发不受影响
                debug!("token 旁路队列已满，放弃这条回复的 token 统计");
                tx = None;
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const STREAM_GZ: &[u8] = include_bytes!("testdata/anthropic_stream.sse.gz");
    const MESSAGE_GZ: &[u8] = include_bytes!("testdata/anthropic_message.json.gz");

    fn gunzip(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(b)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn run(decoder: Decoder, format: Format, data: &[u8], chunk: usize) -> Option<TokenUsage> {
        let mut p = Parser::new(decoder, format);
        for c in data.chunks(chunk) {
            p.feed(c);
        }
        p.finish()
    }

    fn gz() -> Decoder {
        Decoder::Gzip(Box::new(flate2::write::GzDecoder::new(Vec::new())))
    }

    fn expected_stream() -> TokenUsage {
        TokenUsage {
            model: Some("claude-haiku-4-5-20251001".into()),
            input_tokens: Some(18),
            output_tokens: Some(177),
            cache_creation_input_tokens: Some(0),
            cache_read_input_tokens: Some(0),
        }
    }

    #[test]
    fn real_gzip_stream_any_chunking() {
        // 真实 Anthropic gzip 流，按任意大小切段（含逐字节）结果都一样
        for chunk in [1, 2, 3, 7, 64, 500, 100_000] {
            assert_eq!(
                run(gz(), Format::Sse, STREAM_GZ, chunk),
                Some(expected_stream()),
                "chunk={chunk}"
            );
        }
    }

    #[test]
    fn plain_stream_any_chunking() {
        let plain = gunzip(STREAM_GZ);
        for chunk in [1, 5, 300, 100_000] {
            assert_eq!(
                run(Decoder::Identity, Format::Sse, &plain, chunk),
                Some(expected_stream())
            );
        }
    }

    #[test]
    fn real_gzip_json_message() {
        assert_eq!(
            run(gz(), Format::Json, MESSAGE_GZ, 10),
            Some(TokenUsage {
                model: Some("claude-haiku-4-5-20251001".into()),
                input_tokens: Some(13),
                output_tokens: Some(4),
                cache_creation_input_tokens: Some(0),
                cache_read_input_tokens: Some(0),
            })
        );
    }

    #[test]
    fn truncated_stream_keeps_what_was_seen() {
        // 客户端中途断开：只拿到 message_start，输入数仍然记下
        let plain = gunzip(STREAM_GZ);
        let cut = plain.len() / 3;
        let u = run(
            Decoder::Identity,
            Format::Sse,
            plain.get(..cut).unwrap(),
            50,
        )
        .unwrap();
        assert_eq!(u.input_tokens, Some(18));
        // gzip 截断同理，不报错
        let u = run(
            gz(),
            Format::Sse,
            STREAM_GZ.get(..STREAM_GZ.len() / 2).unwrap(),
            9,
        );
        assert!(u.is_none() || u.unwrap().input_tokens == Some(18));
    }

    #[test]
    fn garbage_never_panics() {
        let junk: Vec<u8> = (0..20_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert_eq!(run(gz(), Format::Sse, &junk, 17), None);
        assert_eq!(run(Decoder::Identity, Format::Sse, &junk, 17), None);
        assert_eq!(run(Decoder::Identity, Format::Json, &junk, 17), None);
        // 坏 JSON 的用量行、类型不对的数字
        let bad = b"data: {\"usage\":\n data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":-3,\"input_tokens\":\"9\"}}\n";
        assert_eq!(run(Decoder::Identity, Format::Sse, bad, 4), None);
        // 超出 i64 的数字丢弃
        let huge = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":18446744073709551615,\"input_tokens\":5}}\n";
        let u = run(Decoder::Identity, Format::Sse, huge, 8).unwrap();
        assert_eq!((u.input_tokens, u.output_tokens), (Some(5), None));
    }

    #[test]
    fn oversized_lines_and_bodies_are_bounded() {
        // 超长正文行跳过，后面的用量行照样读到
        let mut data = b"data: ".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_LINE + 10));
        data.extend_from_slice(
            b"\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n",
        );
        let u = run(Decoder::Identity, Format::Sse, &data, 4096).unwrap();
        assert_eq!(u.output_tokens, Some(7));
        // 非流式超过上限：放弃
        let big = vec![b' '; MAX_JSON + 1];
        assert_eq!(run(Decoder::Identity, Format::Json, &big, 65536), None);
    }

    #[test]
    fn decompression_bomb_capped() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![b'\n'; 1024 * 1024];
        for _ in 0..(MAX_DECODED / zeros.len() + 2) {
            enc.write_all(&zeros).unwrap();
        }
        let bomb = enc.finish().unwrap();
        let mut p = Parser::new(gz(), Format::Sse);
        for c in bomb.chunks(4096) {
            p.feed(c);
        }
        assert!(p.broken);
        assert_eq!(p.finish(), None);
    }

    #[test]
    fn parser_selection_by_headers() {
        let h = |pairs: &[(&str, &str)]| {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.insert(
                    k.parse::<hyper::header::HeaderName>().unwrap(),
                    v.parse().unwrap(),
                );
            }
            m
        };
        let p = parser_for(&h(&[
            ("content-type", "text/event-stream; charset=utf-8"),
            ("content-encoding", "gzip"),
        ]))
        .unwrap();
        assert!(matches!(p.decoder, Decoder::Gzip(_)) && p.format == Format::Sse);
        let p = parser_for(&h(&[("content-type", "application/json")])).unwrap();
        assert!(matches!(p.decoder, Decoder::Identity) && p.format == Format::Json);
        assert!(parser_for(&h(&[
            ("content-type", "text/event-stream"),
            ("content-encoding", "br")
        ]))
        .is_none());
        assert!(parser_for(&h(&[("content-type", "text/html")])).is_none());
        assert!(parser_for(&h(&[])).is_none());
    }
}

#[cfg(test)]
mod wrap_tests {
    use super::*;
    use futures_util::stream;
    use hyper::body::Frame;

    const STREAM_GZ: &[u8] = include_bytes!("testdata/anthropic_stream.sse.gz");

    fn upstream(data: &[u8], chunk: usize) -> BodyStream {
        let frames: Vec<Result<Frame<Bytes>, reqwest::Error>> = data
            .chunks(chunk)
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        Box::pin(stream::iter(frames))
    }

    fn headers(rid: &str, ct: &str, enc: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("request-id", rid.parse().unwrap());
        h.insert("content-type", ct.parse().unwrap());
        if let Some(e) = enc {
            h.insert("content-encoding", e.parse().unwrap());
        }
        h
    }

    /// 造一条暂存的观测（走真实 record 入口）
    fn hold(rid: &str, secret: &str) {
        let resp = reqwest::Response::from(
            hyper::Response::builder()
                .status(200)
                .header("request-id", rid)
                .header("anthropic-ratelimit-unified-5h-utilization", "0.3")
                .body(Vec::<u8>::new())
                .unwrap(),
        );
        super::super::quota_usage::record(Some(secret), "api.anthropic.com", "/v1/messages", &resp);
    }

    async fn collect(s: BodyStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut s = s;
        while let Some(item) = s.next().await {
            if let Ok(f) = item {
                if let Some(d) = f.data_ref() {
                    out.extend_from_slice(d);
                }
            }
        }
        out
    }

    async fn completed(secret: &str) -> Vec<Option<TokenUsage>> {
        // 旁路任务异步收尾，稍等一下
        for _ in 0..100 {
            let got = super::super::quota_usage::drain_for_test(secret);
            if !got.is_empty() {
                return got;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Vec::new()
    }

    #[tokio::test]
    async fn bytes_pass_through_unchanged_and_tokens_recorded() {
        hold("req_wrap_1", "wrap1");
        let h = headers(
            "req_wrap_1",
            "text/event-stream; charset=utf-8",
            Some("gzip"),
        );
        let out = collect(wrap(
            upstream(STREAM_GZ, 37),
            "api.anthropic.com",
            "/v1/messages",
            &h,
        ))
        .await;
        assert_eq!(out, STREAM_GZ, "转发出去的字节必须和上游一模一样");
        let rows = completed("wrap1").await;
        assert_eq!(rows.len(), 1);
        let t = rows[0].clone().unwrap();
        assert_eq!((t.input_tokens, t.output_tokens), (Some(18), Some(177)));
    }

    #[tokio::test]
    async fn client_disconnect_mid_stream_still_records() {
        hold("req_wrap_2", "wrap2");
        let h = headers("req_wrap_2", "text/event-stream", Some("gzip"));
        let mut s = wrap(
            upstream(STREAM_GZ, 64),
            "api.anthropic.com",
            "/v1/messages",
            &h,
        );
        // 只读前几段就丢掉（客户端断开）
        for _ in 0..5 {
            s.next().await;
        }
        drop(s);
        let rows = completed("wrap2").await;
        assert_eq!(rows.len(), 1, "断开也要写一行（额度列不丢）");
    }

    #[tokio::test]
    async fn unknown_encoding_records_quota_only_and_passes_through() {
        hold("req_wrap_3", "wrap3");
        let h = headers("req_wrap_3", "text/event-stream", Some("br"));
        let out = collect(wrap(
            upstream(b"whatever", 3),
            "api.anthropic.com",
            "/v1/messages",
            &h,
        ))
        .await;
        assert_eq!(out, b"whatever");
        assert_eq!(completed("wrap3").await, vec![None]);
    }

    #[tokio::test]
    async fn not_held_or_other_host_is_untouched() {
        let h = headers("req_never_held", "text/event-stream", None);
        let out = collect(wrap(
            upstream(b"abc", 1),
            "api.anthropic.com",
            "/v1/messages",
            &h,
        ))
        .await;
        assert_eq!(out, b"abc");
        hold("req_wrap_4", "wrap4");
        let h = headers("req_wrap_4", "text/event-stream", None);
        let out = collect(wrap(
            upstream(b"abc", 1),
            "api.openai.com",
            "/v1/messages",
            &h,
        ))
        .await;
        assert_eq!(out, b"abc");
        // 别的 host 不认领，暂存还在
        assert!(super::super::quota_usage::take_held("req_wrap_4").is_some());
    }

    #[tokio::test]
    async fn upstream_error_mid_stream_is_forwarded_and_recorded() {
        hold("req_wrap_5", "wrap5");
        let h = headers("req_wrap_5", "text/event-stream", Some("gzip"));
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err();
        let half = STREAM_GZ.get(..STREAM_GZ.len() / 2).unwrap();
        let frames: Vec<Result<Frame<Bytes>, reqwest::Error>> =
            vec![Ok(Frame::data(Bytes::copy_from_slice(half))), Err(err)];
        let mut s = wrap(
            Box::pin(stream::iter(frames)),
            "api.anthropic.com",
            "/v1/messages",
            &h,
        );
        assert!(matches!(s.next().await, Some(Ok(_))));
        assert!(
            matches!(s.next().await, Some(Err(_))),
            "上游错误原样交给调用方"
        );
        assert!(s.next().await.is_none());
        drop(s);
        assert_eq!(completed("wrap5").await.len(), 1);
    }
}
