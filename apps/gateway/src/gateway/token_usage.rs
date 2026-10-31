//! 旁路读取模型回复里的 token 用量，补进同一条额度用量记录（`quota_usage`）。
//!
//! 隔离原则（大杰 10-31：出异常不能影响主流程、不能把网关搞挂；6号评审两项 P1 后重做）：
//! - 转发路径上只做两件事：把数据帧复制成独立小块 + 非阻塞 `try_send` 给一个**独立系统线程**（不是 Tokio 任务）。
//!   不改、不拦、不等任何字节，也不在 Tokio 工作线程上做解压/解析，转发调度不受影响。
//! - 全部有全局硬上限，超了就放弃这条的 token 统计（额度列照常写）：同时统计的回复数 `MAX_ACTIVE`、
//!   通道消息数 `QUEUE_MSGS`、已投递未解析的字节 `MAX_INFLIGHT`（含每条消息开销）、每条解压总量 `MAX_DECODED`、
//!   每段解压输出 `MAX_FEED_OUT`（写入前检查，不先分配再检查）、SSE 单行 `MAX_LINE`、非流式 JSON `MAX_JSON`。
//!   缓冲区容量也受上限约束（`append_capped`，不随 extend 倍增）。最坏内存量级：在途 32MB、
//!   通道约 0.2MB、256 条 ×（JSON 1MB + 解压器约 64KB）、单段解压输出 4MB，合计约 310MB；另有 JSON 解析临时值与额度记录队列未计入，是有限上界而非精确保证；日常是 KB 级。
//! - 解析失败、数据不完整、压缩格式不认识、旁路线程起不来：一律只是"这条没有 token 数"。
//! - 网关 release 编译是 `panic = "abort"`，`catch_unwind` 兜不住，所以本模块按"不可能 panic"写：
//!   不用 unwrap / expect / 下标切片，数值一律 saturating，缓冲区全部有上限。
//!
//! 数据来源（10-31 经网关实测）：Claude Code 带 `Accept-Encoding: gzip, deflate, br, zstd`，
//! Anthropic 回 `Content-Encoding: gzip` 的 SSE。用量在 `message_start.message.usage`（输入/缓存）
//! 和 `message_delta.usage`（累计值，含输出）里；非流式回复是整段 JSON 的顶层 `usage`。
use futures_util::Stream;
use hyper::body::{Bytes, Frame};
use hyper::HeaderMap;
use std::{
    collections::HashMap,
    io::{self, Write},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, OnceLock,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

use super::hooks::BodyStream;
use super::quota_usage::Observation;

/// 同时统计 token 的回复数上限；超了新回复只记额度
const MAX_ACTIVE: usize = 256;
/// 所有回复已投递给旁路线程、还没解析完的字节上限；超了放弃当前这条
const MAX_INFLIGHT: usize = 32 * 1024 * 1024;
/// 每条回复解压后最多看多少字节，防压缩炸弹
const MAX_DECODED: usize = 64 * 1024 * 1024;
/// 一段压缩数据最多解压出多少（写入前检查）
const MAX_FEED_OUT: usize = 4 * 1024 * 1024;
/// SSE 单行最长；超长行（正文大块文字）直接跳过，不会是用量行
const MAX_LINE: usize = 256 * 1024;
/// 非流式 JSON 最多缓存多少
const MAX_JSON: usize = 1024 * 1024;

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

/// 追加数据，且容量也不超过上限（6号三审 P2：extend 会倍增容量，只限 len 不等于限住内存）。
/// 调用方已保证 `buf.len() + data.len() <= cap`。
fn append_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize) {
    let need = buf.len().saturating_add(data.len());
    if buf.capacity() < need {
        let target = buf
            .capacity()
            .saturating_mul(2)
            .max(need)
            .min(cap.max(need));
        buf.reserve_exact(target.saturating_sub(buf.len()));
    }
    buf.extend_from_slice(data);
}

/// 解压输出的落点：写入**前**检查上限，超了直接报错、不扩容（6号 P1-1：不先分配再检查）
struct CappedSink {
    buf: Vec<u8>,
    total: usize,
}

impl Write for CappedSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let total = self.total.saturating_add(data.len());
        if total > MAX_DECODED || self.buf.len().saturating_add(data.len()) > MAX_FEED_OUT {
            return Err(io::Error::other("token 旁路解压超出上限"));
        }
        append_capped(&mut self.buf, data, MAX_FEED_OUT);
        self.total = total;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Decoder {
    Identity { seen: usize },
    Gzip(Box<flate2::write::GzDecoder<CappedSink>>),
}

fn gzip_decoder() -> Decoder {
    Decoder::Gzip(Box::new(flate2::write::GzDecoder::new(CappedSink {
        buf: Vec::new(),
        total: 0,
    })))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Format {
    Sse,
    Json,
}

/// 纯同步的解析器：喂压缩/未压缩的分段，产出用量。任何异常只把自己标成 broken 并释放缓冲。
struct Parser {
    decoder: Decoder,
    format: Format,
    buf: Vec<u8>,
    /// 当前行超长，丢到下一个换行为止
    skipping_line: bool,
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
            broken: false,
            usage: TokenUsage::default(),
        }
    }

    /// 出错：标记并立即释放解压器和缓冲
    fn fail(&mut self) {
        self.broken = true;
        self.decoder = Decoder::Identity { seen: 0 };
        self.buf = Vec::new();
    }

    fn feed(&mut self, chunk: &[u8]) {
        if self.broken {
            return;
        }
        match &mut self.decoder {
            Decoder::Identity { seen } => {
                *seen = seen.saturating_add(chunk.len());
                if *seen > MAX_DECODED {
                    self.fail();
                    return;
                }
                self.consume(chunk);
            }
            Decoder::Gzip(d) => {
                if d.write_all(chunk).is_err() {
                    self.fail();
                    return;
                }
                let plain = std::mem::take(&mut d.get_mut().buf);
                self.consume(&plain);
            }
        }
    }

    fn consume(&mut self, plain: &[u8]) {
        match self.format {
            Format::Sse => self.feed_sse(plain),
            Format::Json => {
                if self.buf.len().saturating_add(plain.len()) > MAX_JSON {
                    self.fail();
                    return;
                }
                append_capped(&mut self.buf, plain, MAX_JSON);
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
                    append_capped(&mut self.buf, head, MAX_LINE);
                    let line = std::mem::take(&mut self.buf);
                    self.line(&line);
                }
                None => {
                    if !self.skipping_line {
                        if self.buf.len().saturating_add(data.len()) > MAX_LINE {
                            self.buf = Vec::new();
                            self.skipping_line = true;
                        } else {
                            append_capped(&mut self.buf, data, MAX_LINE);
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

    /// 回复结束（或客户端断开）。返回有数的用量；出过错或一个数都没有就 None。
    fn finish(mut self) -> Option<TokenUsage> {
        if self.broken {
            return None;
        }
        if let Decoder::Gzip(d) = &mut self.decoder {
            // 把解压器里剩余的吐出来（同样受上限约束）；流被截断时这里会报错，已解析的照样算
            if d.try_finish().is_ok() {
                let rest = std::mem::take(&mut d.get_mut().buf);
                self.consume(&rest);
            }
        }
        if self.broken {
            return None;
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
        None => Decoder::Identity { seen: 0 },
        Some(e) if e.is_empty() || e == "identity" => Decoder::Identity { seen: 0 },
        Some(e) if e == "gzip" || e == "x-gzip" => gzip_decoder(),
        Some(_) => return None,
    };
    Some(Parser::new(decoder, format))
}

// ── 旁路线程 ─────────────────────────────────────────────────────────────
//
// 内存硬上限（6号复审 P1）：通道有界（QUEUE_MSGS 条），每段数据复制成独立的小块（不持有上游大块底层内存），
// 按"字节数 + 每条消息开销"计入 MAX_INFLIGHT；空帧不投递。投递一律 try_send，满了就放弃这条统计。
// 收尾不靠消息（消息可能因队列满发不出去）：每条回复一个共享的 Ctl，转发侧在 Drop 时置 ended、
// 放弃时置 stop；旁路线程处理完已投递的段后自己收尾，并定期巡检（6号复审 P2：失败后转发侧立即停止投递）。

/// 通道里最多积压多少条消息
const QUEUE_MSGS: usize = 4096;
/// 每条消息按这么多额外字节计费（消息节点、Bytes 头等）
const MSG_OVERHEAD: usize = 128;
/// 旁路线程巡检间隔
const SCAN_EVERY: Duration = Duration::from_millis(200);

/// 一条回复在转发侧与旁路线程之间共享的状态
#[derive(Default)]
struct Ctl {
    /// 放弃统计（解析失败、额度不够、队列满）；转发侧看到后不再投递
    stop: AtomicBool,
    /// 回复流已释放（正常结束、客户端断开、上游出错都一样）
    ended: AtomicBool,
    /// 成功投递的段数
    sent: AtomicU64,
}

enum Msg {
    Start {
        id: u64,
        parser: Box<Parser>,
        obs: Box<Observation>,
        ctl: Arc<Ctl>,
    },
    Chunk {
        id: u64,
        data: Bytes,
    },
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// 旁路线程里还没收尾的回复数（Start 前占位，收尾时释放）
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// 已投递未解析的字节（含每条消息开销）
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static WORKER: OnceLock<Option<mpsc::SyncSender<Msg>>> = OnceLock::new();

/// 归还在途字节；饱和减，记账万一不对称也不会回绕成"永远超限"
fn release_inflight(cost: usize) {
    let _ = INFLIGHT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(cost))
    });
}

/// 懒启动唯一的旁路系统线程；起不来就整个功能关闭（只记额度）
fn worker() -> Option<&'static mpsc::SyncSender<Msg>> {
    WORKER
        .get_or_init(|| {
            let (tx, rx) = mpsc::sync_channel::<Msg>(QUEUE_MSGS);
            match std::thread::Builder::new()
                .name("token-usage".into())
                .spawn(move || Worker::default().run(rx))
            {
                Ok(_) => {
                    info!("token 用量旁路线程已启动");
                    Some(tx)
                }
                Err(e) => {
                    warn!(error = %e, "token 用量旁路线程启动失败，本次运行只记额度不记 token");
                    None
                }
            }
        })
        .as_ref()
}

struct Tracked {
    parser: Box<Parser>,
    obs: Box<Observation>,
    ctl: Arc<Ctl>,
    processed: u64,
}

#[derive(Default)]
struct Worker {
    streams: HashMap<u64, Tracked>,
}

impl Worker {
    fn run(mut self, rx: mpsc::Receiver<Msg>) {
        let mut last_scan = Instant::now();
        loop {
            match rx.recv_timeout(SCAN_EVERY) {
                Ok(msg) => self.on_msg(msg),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if last_scan.elapsed() >= SCAN_EVERY {
                self.scan();
                last_scan = Instant::now();
            }
        }
    }

    fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Start {
                id,
                parser,
                obs,
                ctl,
            } => {
                self.streams.insert(
                    id,
                    Tracked {
                        parser,
                        obs,
                        ctl,
                        processed: 0,
                    },
                );
            }
            Msg::Chunk { id, data } => {
                let cost = data.len().saturating_add(MSG_OVERHEAD);
                if let Some(t) = self.streams.get_mut(&id) {
                    t.processed = t.processed.saturating_add(1);
                    if !t.ctl.stop.load(Ordering::Relaxed) {
                        t.parser.feed(&data);
                        if t.parser.broken {
                            debug!("token 旁路解析出错或超限，这条只记额度");
                            t.ctl.stop.store(true, Ordering::Release);
                        }
                    }
                }
                drop(data);
                release_inflight(cost);
                self.try_finish(id);
            }
        }
    }

    /// 能收尾就收尾：放弃了 → 只记额度；流已释放且投递的段都处理完 → 带 token
    fn try_finish(&mut self, id: u64) {
        // 先读 ended 再读 stop（6号三审 P2）：转发侧放弃时先置 stop 再 Drop 置 ended，
        // 这样看到 ended 就一定看得到此前的 stop，不会把放弃的半截数据当完整 token 记下
        let ready = match self.streams.get(&id) {
            Some(t) => {
                let ended = t.ctl.ended.load(Ordering::Acquire);
                if t.ctl.stop.load(Ordering::Acquire) {
                    Some(true)
                } else if ended {
                    (t.processed >= t.ctl.sent.load(Ordering::Acquire)).then_some(false)
                } else {
                    None
                }
            }
            None => None,
        };
        let Some(give_up) = ready else {
            return;
        };
        if let Some(t) = self.streams.remove(&id) {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            let tokens = if give_up { None } else { t.parser.finish() };
            super::quota_usage::complete(*t.obs, tokens);
        }
    }

    fn scan(&mut self) {
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            self.try_finish(id);
        }
    }
}

/// 包在回复流外面：原样交回每一项，数据帧顺手复制一份投给旁路线程
struct Tap {
    inner: BodyStream,
    id: u64,
    ctl: Arc<Ctl>,
    /// None = 已放弃统计，之后不再投递
    tx: Option<mpsc::SyncSender<Msg>>,
}

impl Tap {
    fn give_up(&mut self) {
        self.ctl.stop.store(true, Ordering::Release);
        self.tx = None;
    }

    fn offer(&mut self, data: &Bytes) {
        if self.tx.is_none() || data.is_empty() {
            return;
        }
        if self.ctl.stop.load(Ordering::Relaxed) {
            self.tx = None;
            return;
        }
        let cost = data.len().saturating_add(MSG_OVERHEAD);
        let before = INFLIGHT.fetch_add(cost, Ordering::Relaxed);
        if before.saturating_add(cost) > MAX_INFLIGHT {
            release_inflight(cost);
            debug!("token 旁路在途字节超限，放弃这条回复的 token 统计");
            self.give_up();
            return;
        }
        // 复制成独立小块：不让旁路持有上游可能大得多的底层缓冲
        let msg = Msg::Chunk {
            id: self.id,
            data: Bytes::copy_from_slice(data),
        };
        let sent = self.tx.as_ref().map(|tx| tx.try_send(msg).is_ok());
        if sent == Some(true) {
            self.ctl.sent.fetch_add(1, Ordering::Release);
        } else {
            release_inflight(cost);
            debug!("token 旁路队列已满，放弃这条回复的 token 统计");
            self.give_up();
        }
    }
}

impl Stream for Tap {
    type Item = Result<Frame<Bytes>, reqwest::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let poll = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll {
            if let Some(data) = frame.data_ref() {
                this.offer(data);
            }
        }
        poll
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        // 不发消息（可能发不出去）：置标记，旁路线程处理完已投递的段后自己收尾
        self.ctl.ended.store(true, Ordering::Release);
    }
}

/// 转发出口调用：把回复流原样交回，同时（仅当这条回复有待补 token 的额度记录时）旁路读用量。
/// 没有待补记录时直接返回原流，零开销；任何资源不够都退化成只记额度。
pub(super) fn wrap(
    stream: BodyStream,
    host: &str,
    path: &str,
    headers: &HeaderMap,
    request_id: uuid::Uuid,
) -> BodyStream {
    if !super::cooldown::applies(host, path) {
        return stream;
    }
    let Some(held) = super::quota_usage::take_held(request_id) else {
        return stream;
    };
    let Some(parser) = parser_for(headers) else {
        debug!(
            content_type = ?header_str(headers, "content-type"),
            content_encoding = ?header_str(headers, "content-encoding"),
            "回复格式不认识，只记额度不记 token"
        );
        super::quota_usage::complete(held, None);
        return stream;
    };
    if ACTIVE.fetch_add(1, Ordering::Relaxed) >= MAX_ACTIVE {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        debug!("同时统计 token 的回复数已满，这条只记额度");
        super::quota_usage::complete(held, None);
        return stream;
    }
    let Some(tx) = worker() else {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        super::quota_usage::complete(held, None);
        return stream;
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let ctl = Arc::new(Ctl::default());
    if let Err(e) = tx.try_send(Msg::Start {
        id,
        parser: Box::new(parser),
        obs: Box::new(held),
        ctl: ctl.clone(),
    }) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        let msg = match e {
            mpsc::TrySendError::Full(m) | mpsc::TrySendError::Disconnected(m) => m,
        };
        if let Msg::Start { obs, .. } = msg {
            super::quota_usage::complete(*obs, None);
        }
        return stream;
    }
    Box::pin(Tap {
        inner: stream,
        id,
        ctl,
        tx: Some(tx.clone()),
    })
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

    fn ident() -> Decoder {
        Decoder::Identity { seen: 0 }
    }

    fn run(decoder: Decoder, format: Format, data: &[u8], chunk: usize) -> Option<TokenUsage> {
        let mut p = Parser::new(decoder, format);
        for c in data.chunks(chunk) {
            p.feed(c);
        }
        p.finish()
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

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn real_gzip_stream_any_chunking() {
        // 真实 Anthropic gzip 流，按任意大小切段（含逐字节）结果都一样
        for chunk in [1, 2, 3, 7, 64, 500, 100_000] {
            assert_eq!(
                run(gzip_decoder(), Format::Sse, STREAM_GZ, chunk),
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
                run(ident(), Format::Sse, &plain, chunk),
                Some(expected_stream())
            );
        }
    }

    #[test]
    fn real_gzip_json_message() {
        assert_eq!(
            run(gzip_decoder(), Format::Json, MESSAGE_GZ, 10),
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
        let u = run(
            ident(),
            Format::Sse,
            plain.get(..plain.len() / 3).unwrap(),
            50,
        )
        .unwrap();
        assert_eq!(u.input_tokens, Some(18));
        // gzip 截断同理，不报错
        let u = run(
            gzip_decoder(),
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
        assert_eq!(run(gzip_decoder(), Format::Sse, &junk, 17), None);
        assert_eq!(run(ident(), Format::Sse, &junk, 17), None);
        assert_eq!(run(ident(), Format::Json, &junk, 17), None);
        // 坏 JSON 的用量行、类型不对的数字
        let bad = b"data: {\"usage\":\n data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":-3,\"input_tokens\":\"9\"}}\n";
        assert_eq!(run(ident(), Format::Sse, bad, 4), None);
        // 超出 i64 的数字丢弃
        let huge = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":18446744073709551615,\"input_tokens\":5}}\n";
        let u = run(ident(), Format::Sse, huge, 8).unwrap();
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
        let u = run(ident(), Format::Sse, &data, 4096).unwrap();
        assert_eq!(u.output_tokens, Some(7));
        // 非流式超过上限：放弃
        let big = vec![b' '; MAX_JSON + 1];
        assert_eq!(run(ident(), Format::Json, &big, 65536), None);
    }

    #[test]
    fn buffer_capacity_never_exceeds_cap() {
        // 6号三审 P2：先 MAX_JSON-1 再 1 字节，容量不能倍增到 2MB
        let mut p = Parser::new(ident(), Format::Json);
        p.feed(&vec![b' '; MAX_JSON - 1]);
        p.feed(b" ");
        assert_eq!(p.buf.len(), MAX_JSON);
        assert!(
            p.buf.capacity() <= MAX_JSON,
            "capacity={}",
            p.buf.capacity()
        );
        let mut v = Vec::new();
        for _ in 0..655 {
            append_capped(&mut v, &[1; 100], 64 * 1024);
        }
        assert_eq!(v.len(), 65_500);
        assert!(v.capacity() <= 64 * 1024, "capacity={}", v.capacity());
    }

    #[test]
    fn capped_sink_rejects_before_allocating() {
        // 6号 P1-1：超限的写入在扩容前就被拒，缓冲不增长
        let mut sink = CappedSink {
            buf: Vec::new(),
            total: 0,
        };
        assert!(sink.write(&vec![0u8; MAX_FEED_OUT + 1]).is_err());
        assert_eq!((sink.buf.len(), sink.buf.capacity(), sink.total), (0, 0, 0));
        assert!(sink.write(&[1, 2, 3]).is_ok());
        sink.total = MAX_DECODED - 2;
        sink.buf.clear();
        assert!(sink.write(&[1, 2, 3]).is_err(), "总量上限同样写入前检查");
    }

    #[test]
    fn decompression_bomb_released_on_first_chunk() {
        // 单个 13 万字节的压缩块能解出 128MB：一段就超限、立刻释放，不会先攒满再检查
        let bomb = gzip_bytes(&vec![b'\n'; 128 * 1024 * 1024]);
        let mut p = Parser::new(gzip_decoder(), Format::Sse);
        p.feed(&bomb);
        assert!(p.broken);
        assert!(
            matches!(p.decoder, Decoder::Identity { .. }),
            "解压器已释放"
        );
        assert_eq!(p.buf.capacity(), 0);
        assert_eq!(p.finish(), None);
    }

    #[test]
    fn trailing_garbage_after_gzip_releases_decoder() {
        // 6号 P1-1：write_all 报错路径也要释放，不能带着解压器继续等
        let mut data = STREAM_GZ.to_vec();
        data.extend_from_slice(b"\x00garbage-not-gzip");
        let mut p = Parser::new(gzip_decoder(), Format::Sse);
        p.feed(&data);
        if p.broken {
            assert!(matches!(p.decoder, Decoder::Identity { .. }));
            assert_eq!(p.buf.capacity(), 0);
        }
        // 不论 flate2 把尾巴当错误还是忽略，都不能 panic，结果要么完整要么 None
        let r = p.finish();
        assert!(r.is_none() || r == Some(expected_stream()));
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
        assert!(matches!(p.decoder, Decoder::Identity { .. }) && p.format == Format::Json);
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
    use futures_util::{stream, StreamExt};
    use std::time::{Duration, Instant};

    const STREAM_GZ: &[u8] = include_bytes!("testdata/anthropic_stream.sse.gz");

    fn upstream(data: &[u8], chunk: usize) -> BodyStream {
        let frames: Vec<Result<Frame<Bytes>, reqwest::Error>> = data
            .chunks(chunk)
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        Box::pin(stream::iter(frames))
    }

    fn headers(ct: &str, enc: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("content-type", ct.parse().unwrap());
        if let Some(e) = enc {
            h.insert("content-encoding", e.parse().unwrap());
        }
        h
    }

    /// 造一条暂存的观测（走真实 record 入口），返回网关请求编号
    fn hold(secret: &str) -> uuid::Uuid {
        let rid = uuid::Uuid::new_v4();
        let resp = reqwest::Response::from(
            hyper::Response::builder()
                .status(200)
                .header("anthropic-ratelimit-unified-5h-utilization", "0.3")
                .body(Vec::<u8>::new())
                .unwrap(),
        );
        super::super::quota_usage::record(
            Some(secret),
            "api.anthropic.com",
            "/v1/messages",
            &resp,
            Some(rid),
        );
        rid
    }

    async fn collect(mut s: BodyStream) -> Vec<u8> {
        let mut out = Vec::new();
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
        // 旁路线程异步收尾，稍等一下
        for _ in 0..300 {
            let got = super::super::quota_usage::drain_for_test(secret);
            if !got.is_empty() {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Vec::new()
    }

    fn wrap_msg(s: BodyStream, h: &HeaderMap, rid: uuid::Uuid) -> BodyStream {
        wrap(s, "api.anthropic.com", "/v1/messages", h, rid)
    }

    #[tokio::test]
    async fn bytes_pass_through_unchanged_and_tokens_recorded() {
        let _serial = super::tests_support::SERIAL.lock().await;
        let rid = hold("wrap1");
        let h = headers("text/event-stream; charset=utf-8", Some("gzip"));
        let out = collect(wrap_msg(upstream(STREAM_GZ, 37), &h, rid)).await;
        assert_eq!(out, STREAM_GZ, "转发出去的字节必须和上游一模一样");
        let rows = completed("wrap1").await;
        assert_eq!(rows.len(), 1);
        let t = rows.first().cloned().flatten().unwrap();
        assert_eq!((t.input_tokens, t.output_tokens), (Some(18), Some(177)));
    }

    #[tokio::test]
    async fn client_disconnect_mid_stream_still_records() {
        let _serial = super::tests_support::SERIAL.lock().await;
        let rid = hold("wrap2");
        let h = headers("text/event-stream", Some("gzip"));
        let mut s = wrap_msg(upstream(STREAM_GZ, 64), &h, rid);
        for _ in 0..5 {
            s.next().await;
        }
        drop(s);
        assert_eq!(
            completed("wrap2").await.len(),
            1,
            "断开也要写一行（额度列不丢）"
        );
    }

    #[tokio::test]
    async fn unknown_encoding_records_quota_only_and_passes_through() {
        let _serial = super::tests_support::SERIAL.lock().await;
        let rid = hold("wrap3");
        let h = headers("text/event-stream", Some("br"));
        let out = collect(wrap_msg(upstream(b"whatever", 3), &h, rid)).await;
        assert_eq!(out, b"whatever");
        assert_eq!(completed("wrap3").await, vec![None]);
    }

    #[tokio::test]
    async fn not_held_or_other_host_is_untouched() {
        let _serial = super::tests_support::SERIAL.lock().await;
        let h = headers("text/event-stream", None);
        let out = collect(wrap_msg(upstream(b"abc", 1), &h, uuid::Uuid::new_v4())).await;
        assert_eq!(out, b"abc");
        let rid = hold("wrap4");
        let out = collect(wrap(
            upstream(b"abc", 1),
            "api.openai.com",
            "/v1/messages",
            &h,
            rid,
        ))
        .await;
        assert_eq!(out, b"abc");
        // 别的 host 不认领，暂存还在
        assert!(super::super::quota_usage::take_held(rid).is_some());
    }

    #[tokio::test]
    async fn upstream_error_mid_stream_is_forwarded_and_recorded() {
        let _serial = super::tests_support::SERIAL.lock().await;
        let rid = hold("wrap5");
        let h = headers("text/event-stream", Some("gzip"));
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err();
        let half = STREAM_GZ.get(..STREAM_GZ.len() / 2).unwrap();
        let frames: Vec<Result<Frame<Bytes>, reqwest::Error>> =
            vec![Ok(Frame::data(Bytes::copy_from_slice(half))), Err(err)];
        let mut s = wrap_msg(Box::pin(stream::iter(frames)), &h, rid);
        assert!(matches!(s.next().await, Some(Ok(_))));
        assert!(
            matches!(s.next().await, Some(Err(_))),
            "上游错误原样交给调用方"
        );
        assert!(s.next().await.is_none());
        drop(s);
        assert_eq!(completed("wrap5").await.len(), 1);
    }

    #[tokio::test]
    async fn inflight_budget_exceeded_gives_up_but_forwards() {
        let _serial = super::tests_support::SERIAL.lock().await;
        // 一帧就超过全局在途字节上限：放弃这条的 token，字节照样全部转发
        let rid = hold("wrap6");
        let h = headers("text/event-stream", None);
        let big = vec![b'x'; MAX_INFLIGHT + 1];
        let out = collect(wrap_msg(upstream(&big, MAX_INFLIGHT + 1), &h, rid)).await;
        assert_eq!(out.len(), big.len());
        assert_eq!(completed("wrap6").await, vec![None]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn heavy_parsing_does_not_stall_tokio_workers() {
        let _serial = super::tests_support::SERIAL.lock().await;
        // 6号 P1-2：两条各解压 60MB 的回复同时在跑，同一运行时里 10ms 的计时器不能被拖慢
        let line =
            b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"xxxxxxxxxxxxxxxx\"}}\n";
        let mut plain = Vec::with_capacity(60 * 1024 * 1024);
        while plain.len() < 60 * 1024 * 1024 {
            plain.extend_from_slice(line);
        }
        plain.extend_from_slice(
            b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n",
        );
        let gz = Bytes::from(super::tests_support::gzip(&plain));
        let h = headers("text/event-stream", Some("gzip"));
        let mut tasks = Vec::new();
        for name in ["heavy1", "heavy2"] {
            let rid = hold(name);
            let s = wrap_msg(upstream(&gz, 16 * 1024), &h, rid);
            tasks.push(tokio::spawn(collect(s)));
        }
        let mut worst = Duration::ZERO;
        for _ in 0..20 {
            let t = Instant::now();
            tokio::time::sleep(Duration::from_millis(10)).await;
            worst = worst.max(t.elapsed());
        }
        for t in tasks {
            assert_eq!(t.await.unwrap().len(), gz.len());
        }
        assert!(
            worst < Duration::from_millis(60),
            "计时器最坏延迟 {worst:?}"
        );
        for name in ["heavy1", "heavy2"] {
            let rows = completed(name).await;
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows.first()
                    .cloned()
                    .flatten()
                    .and_then(|t| t.output_tokens),
                Some(42)
            );
        }
    }
}

#[cfg(test)]
mod tests_support {
    use std::io::Write;
    /// 旁路的在途字节/活跃数是全局的：动到它们的测试串行跑，免得互相挤占额度
    pub(super) static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    pub(super) fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }
}

#[cfg(test)]
mod channel_tests {
    use super::*;
    use futures_util::{stream, StreamExt};

    fn tap_over(frames: Vec<Bytes>, cap: usize) -> (Tap, mpsc::Receiver<Msg>) {
        let (tx, rx) = mpsc::sync_channel::<Msg>(cap);
        let items: Vec<Result<Frame<Bytes>, reqwest::Error>> =
            frames.into_iter().map(|b| Ok(Frame::data(b))).collect();
        let tap = Tap {
            inner: Box::pin(stream::iter(items)),
            id: 7,
            ctl: Arc::new(Ctl::default()),
            tx: Some(tx),
        };
        (tap, rx)
    }

    fn chunks(rx: &mpsc::Receiver<Msg>) -> Vec<Bytes> {
        rx.try_iter()
            .filter_map(|m| match m {
                Msg::Chunk { data, .. } => {
                    release_inflight(data.len() + MSG_OVERHEAD);
                    Some(data)
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn empty_frames_skipped_and_data_copied() {
        let _serial = super::tests_support::SERIAL.lock().await;
        // 6号复审 P1：空帧不投递；投递的是独立复制的小块，不持有上游大块底层内存
        let big = Bytes::from(vec![b'a'; 1024 * 1024]);
        let small = big.slice(10..13);
        let (mut tap, rx) = tap_over(vec![Bytes::new(), small.clone(), Bytes::new()], 16);
        let mut out = Vec::new();
        while let Some(Ok(f)) = tap.next().await {
            out.push(f.into_data().unwrap());
        }
        assert_eq!(out.len(), 3, "空帧照样转发给调用方");
        let got = chunks(&rx);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], small);
        assert_ne!(got[0].as_ptr(), small.as_ptr(), "旁路拿到的是复制品");
        assert_eq!(tap.ctl.sent.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn full_queue_gives_up_and_stops_sending() {
        let _serial = super::tests_support::SERIAL.lock().await;
        // 队列满：放弃统计、置 stop，后面的帧照样转发但不再投递
        let frames: Vec<Bytes> = (0..10).map(|i| Bytes::from(vec![i as u8; 4])).collect();
        let (mut tap, rx) = tap_over(frames, 2);
        let mut n = 0;
        while let Some(Ok(_)) = tap.next().await {
            n += 1;
        }
        assert_eq!(n, 10, "转发不受影响");
        assert!(tap.ctl.stop.load(Ordering::Relaxed));
        assert!(tap.tx.is_none());
        assert_eq!(chunks(&rx).len(), 2, "只进了队列容量那么多");
        assert_eq!(tap.ctl.sent.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn stop_set_by_worker_halts_tap() {
        let _serial = super::tests_support::SERIAL.lock().await;
        // 6号复审 P2：旁路判定失败后，存活的转发侧立即停止投递
        let frames: Vec<Bytes> = (0..5).map(|_| Bytes::from_static(b"xyz")).collect();
        let (mut tap, rx) = tap_over(frames, 16);
        tap.next().await;
        tap.ctl.stop.store(true, Ordering::Relaxed);
        while tap.next().await.is_some() {}
        assert_eq!(chunks(&rx).len(), 1);
        assert!(tap.tx.is_none());
    }

    #[test]
    fn worker_finishes_on_failure_and_on_end_after_all_chunks() {
        let _serial = super::tests_support::SERIAL.blocking_lock();
        let rid = uuid::Uuid::new_v4();
        let resp = |secret: &str| {
            super::super::quota_usage::record(
                Some(secret),
                "api.anthropic.com",
                "/v1/messages",
                &reqwest::Response::from(
                    hyper::Response::builder()
                        .status(200)
                        .header("anthropic-ratelimit-unified-5h-utilization", "0.3")
                        .body(Vec::<u8>::new())
                        .unwrap(),
                ),
                Some(rid),
            )
        };
        let mut w = Worker::default();
        // 坏 gzip：第一段就失败 → 置 stop、立即收尾（只记额度），释放占位
        resp("wk1");
        let ctl = Arc::new(Ctl::default());
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        w.on_msg(Msg::Start {
            id: 1,
            parser: Box::new(Parser::new(gzip_decoder(), Format::Sse)),
            obs: Box::new(super::super::quota_usage::take_held(rid).unwrap()),
            ctl: ctl.clone(),
        });
        let junk = Bytes::from_static(b"this is definitely not a gzip stream at all");
        INFLIGHT.fetch_add(junk.len() + MSG_OVERHEAD, Ordering::Relaxed);
        w.on_msg(Msg::Chunk { id: 1, data: junk });
        assert!(ctl.stop.load(Ordering::Relaxed));
        assert!(w.streams.is_empty());
        assert_eq!(super::super::quota_usage::drain_for_test("wk1"), vec![None]);

        // 正常：ended 但还有已投递未处理的段 → 等处理完才收尾
        let rid2 = uuid::Uuid::new_v4();
        super::super::quota_usage::record(
            Some("wk2"),
            "api.anthropic.com",
            "/v1/messages",
            &reqwest::Response::from(
                hyper::Response::builder()
                    .status(200)
                    .header("anthropic-ratelimit-unified-5h-utilization", "0.3")
                    .body(Vec::<u8>::new())
                    .unwrap(),
            ),
            Some(rid2),
        );
        let ctl = Arc::new(Ctl::default());
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        w.on_msg(Msg::Start {
            id: 2,
            parser: Box::new(Parser::new(Decoder::Identity { seen: 0 }, Format::Sse)),
            obs: Box::new(super::super::quota_usage::take_held(rid2).unwrap()),
            ctl: ctl.clone(),
        });
        let line = Bytes::from_static(
            b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n",
        );
        ctl.sent.store(2, Ordering::Release);
        ctl.ended.store(true, Ordering::Release);
        let start_len =
            b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n"
                .len();
        INFLIGHT.fetch_add(start_len + line.len() + 2 * MSG_OVERHEAD, Ordering::Relaxed);
        w.on_msg(Msg::Chunk {
            id: 2,
            data: Bytes::from_static(b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n"),
        });
        w.scan();
        assert_eq!(w.streams.len(), 1, "还有 1 段没处理，不能收尾");
        w.on_msg(Msg::Chunk { id: 2, data: line });
        assert!(w.streams.is_empty());
        let rows = super::super::quota_usage::drain_for_test("wk2");
        let t = rows.first().cloned().flatten().unwrap();
        assert_eq!((t.input_tokens, t.output_tokens), (Some(3), Some(5)));
        // 收尾后再来的段（不存在的 id）只归还额度，不出错
        INFLIGHT.fetch_add(3 + MSG_OVERHEAD, Ordering::Relaxed);
        w.on_msg(Msg::Chunk {
            id: 2,
            data: Bytes::from_static(b"abc"),
        });
    }
}
