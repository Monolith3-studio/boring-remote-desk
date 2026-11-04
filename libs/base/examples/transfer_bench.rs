//! boring-remote (v1.7 t27): loopback file transfer bench. Real TCP sockets, real secretbox keys,
//! real files, and the real engine (`base::fs` TransferJob and handle_read_jobs, `file_speed`).
//! The select loops are copies of the arms in src/server/connection.rs, src/client/io_loop.rs and
//! src/ui_cm_interface.rs, because those live in the app crate, which this can't link.
//!
//!   make:  transfer_bench make <incompressible|compressible> <gib> <path>
//!   run:   transfer_bench run <file> <dest dir> [--mode tick|pump] [--direction up|down] [--link-mib N]
//!   cost:  transfer_bench cost   (one core's speed at each per-block step, on this machine)
//!   peers: transfer_bench peer-send <path> <port> [--mode tick|pump]   then
//!          transfer_bench peer-recv <dest> <port>
//!          Two processes, so a raw checkout's build (upstream's engine, as a 1.6.x peer has) can
//!          face a patched one in either direction.
//!
//! `--mode tick` is upstream's loop: one block per 1 ms tick, a connection-manager log per tick,
//! a log per block on the CM, no credit. `--mode pump` is what v1.7 ships.
//! `--direction up` is Controller to Target (Target writes through the CM, one extra local socket);
//! `--direction down` is Target to Controller (Controller writes in its loop).
//! `--link-mib 110` passes the socket through a relay held to that rate, as a 1 Gb port would.
//! It prints MiB/s, how the two select loops kept up and the peer's echo time, then checks the copy
//! byte for byte. Build it --release: a debug build measures the optimiser's absence. Upstream's
//! fs.rs and hbb_common until boring/rebrand.py patches them, so measure on a patched tree.

use std::{
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use base::{fs, message_proto::*};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures::{SinkExt, StreamExt},
    protobuf::Message as _,
    sodiumoxide::crypto::secretbox,
    tokio::{self, net::TcpListener, sync::mpsc, time},
    tokio_util::codec::Framed,
    ResultType, Stream,
};

#[allow(dead_code)]
#[path = "../src/file_speed.rs"]
mod file_speed;

const MIB: f64 = 1024.0 * 1024.0;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Tick,
    Pump,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Direction {
    Up,
    Down,
}

/// Upstream's src/common.rs ThrottledInterval, which is in the app crate.
struct Throttled {
    interval: time::Interval,
    next_tick: Instant,
    min_interval: Duration,
}

impl Throttled {
    fn new(period: Duration) -> Self {
        Self {
            interval: time::interval(period),
            next_tick: Instant::now(),
            min_interval: Duration::from_secs_f64(period.as_secs_f64() * 0.9),
        }
    }

    async fn tick(&mut self) {
        loop {
            self.interval.tick().await;
            let now = Instant::now();
            if self.next_tick <= now {
                self.next_tick = now + self.min_interval;
                return;
            }
            tokio::task::yield_now().await;
        }
    }
}

/// How late a 5 ms arm in a select loop runs: the wait an input or video arm would see.
#[derive(Default)]
struct Lag {
    samples: Vec<u32>,
    last: Option<Instant>,
}

impl Lag {
    fn hit(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last {
            let late = now.duration_since(last).saturating_sub(Duration::from_millis(5));
            self.samples.push(late.as_micros() as u32);
        }
        self.last = Some(now);
    }

    fn line(&mut self) -> String {
        self.samples.sort_unstable();
        let n = self.samples.len();
        if n == 0 {
            return "no samples".to_string();
        }
        let at = |p: f64| self.samples[((n - 1) as f64 * p) as usize] as f64 / 1000.0;
        format!(
            "p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms ({} samples)",
            at(0.5),
            at(0.99),
            at(1.0),
            n
        )
    }
}

fn test_delay(time: i64, from_client: bool) -> Message {
    let mut msg = Message::new();
    msg.set_test_delay(TestDelay {
        time,
        from_client,
        ..Default::default()
    });
    msg
}

fn now_micros(start: Instant) -> i64 {
    start.elapsed().as_micros() as i64
}

struct SenderReport {
    lag: Lag,
    echo: Lag,
}

/// The sending loop: read jobs on a timer, and an arm for each thing the real loops also wait on.
async fn run_sender(
    mode: Mode,
    mut stream: Stream,
    mut job: fs::TransferJob,
    direction: Direction,
    log_sink: mpsc::UnboundedSender<String>,
) -> ResultType<SenderReport> {
    let start = Instant::now();
    let mut timer = Throttled::new(Duration::from_millis(1));
    let mut probe = time::interval(Duration::from_millis(5));
    let mut echo_timer = time::interval(Duration::from_millis(50));
    let mut lag = Lag::default();
    let mut echoes = Vec::new();
    let mut log_gate = file_speed::Every::default();
    job.is_remote = direction == Direction::Down;
    let mut jobs = vec![job];
    loop {
        tokio::select! {
            res = stream.next() => {
                let Some(Ok(bytes)) = res else { hbb_common::bail!("receiver went away") };
                let msg = Message::parse_from_bytes(&bytes)?;
                match msg.union {
                    Some(message::Union::TestDelay(t)) if t.from_client => {
                        echoes.push((now_micros(start) - t.time) as u32);
                    }
                    Some(message::Union::FileAction(fa)) => {
                        if let Some(file_action::Union::SendConfirm(r)) = fa.union {
                            if let Some(job) = fs::get_job(r.id, &mut jobs) {
                                job.confirm(&r).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ = timer.tick() => {
                if jobs.is_empty() {
                    break;
                }
                // Only the Target's connection logs to its CM while reading.
                let log_this_tick = direction == Direction::Down
                    && (mode == Mode::Tick || log_gate.ready(file_speed::LOG_EVERY));
                if log_this_tick {
                    log_sink.send(fs::serialize_transfer_jobs(&jobs)).ok();
                }
                let log = match mode {
                    Mode::Tick => fs::handle_read_jobs(&mut jobs, &mut stream).await?,
                    Mode::Pump => file_speed::pump_read_jobs(&mut jobs, &mut stream).await?,
                };
                if !log.is_empty() && direction == Direction::Down {
                    log_sink.send(log).ok();
                }
            }
            _ = probe.tick() => lag.hit(),
            _ = echo_timer.tick() => {
                // from_client = true means: please send this back.
                stream.send(&test_delay(now_micros(start), true)).await?;
            }
        }
    }
    let mut echo = Lag::default();
    echo.samples = echoes;
    Ok(SenderReport { lag, echo })
}

struct WriteTarget {
    job: fs::TransferJob,
}

impl WriteTarget {
    fn new(dest: PathBuf, files: Vec<FileEntry>) -> ResultType<Self> {
        Ok(Self {
            job: fs::TransferJob::new_write(
                1,
                fs::JobType::Generic,
                String::new(),
                fs::DataSource::FilePath(dest),
                0,
                false,
                true,
                true,
            )
            .with_files(files)?,
        })
    }
}

/// Controller's loop: the block is written in the loop itself.
async fn run_controller_receiver(mut stream: Stream, mut w: WriteTarget) -> ResultType<Lag> {
    let mut probe = time::interval(Duration::from_millis(5));
    let mut lag = Lag::default();
    loop {
        tokio::select! {
            res = stream.next() => {
                let Some(Ok(bytes)) = res else { hbb_common::bail!("sender went away") };
                let msg = Message::parse_from_bytes(&bytes)?;
                match msg.union {
                    Some(message::Union::TestDelay(t)) => stream.send(&test_delay(t.time, t.from_client)).await?,
                    Some(message::Union::FileResponse(fr)) => match fr.union {
                        Some(file_response::Union::Digest(d)) => {
                            stream.send(&fs::new_send_confirm(FileTransferSendConfirmRequest {
                                id: d.id,
                                file_num: d.file_num,
                                union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                                ..Default::default()
                            })).await?;
                            w.job.confirm(&FileTransferSendConfirmRequest {
                                id: d.id,
                                file_num: d.file_num,
                                union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                                ..Default::default()
                            }).await;
                        }
                        Some(file_response::Union::Block(block)) => w.job.write(block).await?,
                        Some(file_response::Union::Done(_)) => {
                            w.job.modify_time();
                            drop(w);
                            return Ok(lag);
                        }
                        Some(file_response::Union::Error(e)) => hbb_common::bail!("peer error: {}", e.error),
                        _ => {}
                    },
                    _ => {}
                }
            }
            _ = probe.tick() => lag.hit(),
        }
    }
}

enum ToCm {
    Block { file_num: i32, data: Bytes, compressed: bool },
    Digest(FileTransferDigest),
    Done,
}

/// Target's connection loop, its IPC task and the CM loop, joined by a real local socket with the
/// header-then-raw framing src/ipc.rs uses. Tick mode has upstream's unbounded queue; pump mode
/// stops reading the peer while the CM is behind, and resumes as it acks.
async fn run_target_receiver(
    mode: Mode,
    mut stream: Stream,
    w: WriteTarget,
    peak_queue: Arc<AtomicU64>,
) -> ResultType<Lag> {
    let (ipc_a, ipc_b) = local_socket_pair().await?;
    let (tx_to_cm, mut rx_to_cm) = mpsc::unbounded_channel::<ToCm>();
    let (tx_ack, mut rx_ack) = mpsc::unbounded_channel::<usize>();
    let queued = Arc::new(AtomicU64::new(0));

    // The IPC task: the local socket pushes back here, and the queue in front of it doesn't.
    let queued2 = queued.clone();
    let ipc_task = tokio::spawn(async move {
        let mut ipc = Framed::new(ipc_a, BytesCodec::new());
        while let Some(m) = rx_to_cm.recv().await {
            let res: std::io::Result<()> = async {
                match m {
                    ToCm::Block { file_num, data, compressed } => {
                        let head = format!(r#"{{"t":"FS","c":{{"WriteBlock":{{"id":1,"file_num":{file_num},"compressed":{compressed}}}}}}}"#);
                        ipc.send(Bytes::from(head)).await?;
                        let n = data.len() as u64;
                        ipc.send(data).await?;
                        queued2.fetch_sub(n, Ordering::Relaxed);
                    }
                    ToCm::Digest(d) => {
                        let head = format!(r#"{{"t":"Digest","c":{{"id":{},"file_num":{},"size":{},"modified":{}}}}}"#, d.id, d.file_num, d.file_size, d.last_modified);
                        ipc.send(Bytes::from(head)).await?;
                    }
                    ToCm::Done => ipc.send(Bytes::from_static(br#"{"t":"Done"}"#)).await?,
                }
                Ok(())
            }.await;
            if res.is_err() {
                break;
            }
        }
    });

    // The CM loop. Upstream serialises the write jobs and calls the UI handler per block.
    let cm: tokio::task::JoinHandle<ResultType<()>> = tokio::spawn(async move {
        let mut ipc = Framed::new(ipc_b, BytesCodec::new());
        let mut job = w.job;
        let mut log_gate = file_speed::Every::default();
        let mut log_bytes = 0usize;
        let mut acks = file_speed::AckBatch::default();
        while let Some(Ok(head)) = ipc.next().await {
            let v: hbb_common::serde_json::Value = hbb_common::serde_json::from_slice(&head)?;
            match v["t"].as_str() {
                Some("FS") => {
                    let c = &v["c"]["WriteBlock"];
                    let Some(Ok(data)) = ipc.next().await else { break };
                    let n = data.len();
                    let block = FileTransferBlock {
                        id: 1,
                        file_num: c["file_num"].as_i64().unwrap_or(0) as i32,
                        data: data.into(),
                        compressed: c["compressed"].as_bool().unwrap_or(false),
                        ..Default::default()
                    };
                    job.write(block).await?;
                    if mode == Mode::Tick || log_gate.ready(file_speed::LOG_EVERY) {
                        log_bytes += fs::serialize_transfer_jobs(std::slice::from_ref(&job)).len();
                    }
                    if mode == Mode::Pump {
                        if let Some(bytes) = acks.add(n) {
                            tx_ack.send(bytes).ok();
                        }
                    }
                }
                Some("Digest") => {
                    job.confirm(&FileTransferSendConfirmRequest {
                        id: 1,
                        file_num: v["c"]["file_num"].as_i64().unwrap_or(0) as i32,
                        union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                        ..Default::default()
                    }).await;
                }
                Some("Done") => {
                    job.modify_time();
                    break;
                }
                _ => {}
            }
        }
        std::hint::black_box(log_bytes);
        Ok(())
    });

    let mut probe = time::interval(Duration::from_millis(5));
    let mut lag = Lag::default();
    let mut window = file_speed::CmWindow::default();
    let mut finished = false;
    while !finished {
        tokio::select! {
            res = stream.next(), if mode == Mode::Tick || window.has_room() => {
                let Some(Ok(bytes)) = res else { hbb_common::bail!("sender went away") };
                let msg = Message::parse_from_bytes(&bytes)?;
                match msg.union {
                    Some(message::Union::TestDelay(t)) => stream.send(&test_delay(t.time, t.from_client)).await?,
                    Some(message::Union::FileResponse(fr)) => match fr.union {
                        Some(file_response::Union::Digest(d)) => {
                            let r = FileTransferSendConfirmRequest {
                                id: d.id,
                                file_num: d.file_num,
                                union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                                ..Default::default()
                            };
                            tx_to_cm.send(ToCm::Digest(d)).ok();
                            stream.send(&fs::new_send_confirm(r)).await?;
                        }
                        Some(file_response::Union::Block(block)) => {
                            let n = block.data.len();
                            let q = queued.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                            peak_queue.fetch_max(q, Ordering::Relaxed);
                            if mode == Mode::Pump {
                                window.spend(n);
                            }
                            tx_to_cm.send(ToCm::Block { file_num: block.file_num, data: block.data, compressed: block.compressed }).ok();
                        }
                        Some(file_response::Union::Done(_)) => {
                            tx_to_cm.send(ToCm::Done).ok();
                            finished = true;
                        }
                        Some(file_response::Union::Error(e)) => hbb_common::bail!("peer error: {}", e.error),
                        _ => {}
                    },
                    _ => {}
                }
            }
            Some(bytes) = rx_ack.recv() => window.refund(bytes),
            _ = probe.tick() => lag.hit(),
        }
    }
    drop(tx_to_cm);
    cm.await??;
    ipc_task.abort();
    Ok(lag)
}

#[cfg(unix)]
async fn local_socket_pair() -> ResultType<(tokio::net::UnixStream, tokio::net::UnixStream)> {
    Ok(tokio::net::UnixStream::pair()?)
}

#[cfg(not(unix))]
async fn local_socket_pair() -> ResultType<(tokio::net::TcpStream, tokio::net::TcpStream)> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let a = tokio::net::TcpStream::connect(l.local_addr()?).await?;
    let (b, _) = l.accept().await?;
    Ok((a, b))
}

async fn tcp_pair() -> ResultType<(tokio::net::TcpStream, tokio::net::TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let a = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    let (b, _) = listener.accept().await?;
    a.set_nodelay(true)?;
    b.set_nodelay(true)?;
    Ok((a, b))
}

/// One way of a link held to `mib_per_s`. The socket behind it fills, so the sender feels it.
async fn limited_copy(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    mib_per_s: f64,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    let (started, mut sent) = (Instant::now(), 0f64);
    while let Ok(n) = from.read(&mut buf).await {
        if n == 0 || to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        sent += n as f64;
        let due = Duration::from_secs_f64(sent / (mib_per_s * MIB));
        if let Some(wait) = due.checked_sub(started.elapsed()) {
            time::sleep(wait).await;
        }
    }
}

async fn socket_pair(key: &secretbox::Key, link_mib: Option<f64>) -> ResultType<(Stream, Stream)> {
    let (a, b) = tcp_pair().await?;
    let (a, b) = match link_mib {
        None => (a, b),
        Some(rate) => {
            // a <-> b is the sender's half of the link; the relay joins b to c, the receiver's.
            let (c, d) = tcp_pair().await?;
            let (b_read, b_write) = b.into_split();
            let (c_read, c_write) = c.into_split();
            tokio::spawn(limited_copy(b_read, c_write, rate));
            tokio::spawn(limited_copy(c_read, b_write, rate));
            (a, d)
        }
    };
    let addr: SocketAddr = a.local_addr()?;
    let peer: SocketAddr = b.local_addr()?;
    let mut sa = Stream::from(a, addr);
    let mut sb = Stream::from(b, peer);
    sa.set_key(key.clone());
    sb.set_key(key.clone());
    Ok((sa, sb))
}

fn make(kind: &str, gib: f64, path: &Path) -> ResultType<()> {
    let total = (gib * 1024.0 * 1024.0 * 1024.0) as u64;
    let mut f = std::io::BufWriter::with_capacity(8 << 20, std::fs::File::create(path)?);
    let mut block = vec![0u8; 1 << 20];
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut written = 0u64;
    let words = [
        "camera", "timeline", "render", "audio", "clip", "export", "frame", "color", "master",
        "proxy", "session", "take", "scene", "reel", "marker", "track",
    ];
    while written < total {
        match kind {
            "incompressible" => {
                for chunk in block.chunks_exact_mut(8) {
                    // xorshift64*: as far as zstd can tell, random.
                    s ^= s >> 12;
                    s ^= s << 25;
                    s ^= s >> 27;
                    chunk.copy_from_slice(&s.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
                }
            }
            "compressible" => {
                // Log-like text, about 4:1 at zstd level 3.
                let mut i = 0;
                while i < block.len() {
                    s ^= s >> 12;
                    s ^= s << 25;
                    s ^= s >> 27;
                    let line = format!(
                        "{:012x} {} {} {:08x}\n",
                        written + i as u64,
                        words[(s & 15) as usize],
                        words[((s >> 8) & 15) as usize],
                        (s >> 16) as u32
                    );
                    let n = line.len().min(block.len() - i);
                    block[i..i + n].copy_from_slice(&line.as_bytes()[..n]);
                    i += n;
                }
            }
            _ => hbb_common::bail!("make: incompressible or compressible"),
        }
        f.write_all(&block)?;
        written += block.len() as u64;
    }
    f.flush()?;
    println!("made {} ({written} bytes)", path.display());
    Ok(())
}

fn same_bytes(a: &Path, b: &Path) -> ResultType<bool> {
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    if fa.metadata()?.len() != fb.metadata()?.len() {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; 4 << 20], vec![0u8; 4 << 20]);
    loop {
        let n = fa.read(&mut ba)?;
        if n == 0 {
            return Ok(true);
        }
        fb.read_exact(&mut bb[..n])?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
    }
}

fn arg_after(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

async fn run(args: &[String]) -> ResultType<()> {
    let source = PathBuf::from(&args[0]);
    let dest_dir = PathBuf::from(&args[1]);
    let mode = match arg_after(args, "--mode").as_deref() {
        Some("tick") => Mode::Tick,
        _ => Mode::Pump,
    };
    let direction = match arg_after(args, "--direction").as_deref() {
        Some("down") => Direction::Down,
        _ => Direction::Up,
    };
    std::fs::create_dir_all(&dest_dir)?;
    let name = source.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
    let dest = dest_dir.join(&name);
    std::fs::remove_file(&dest).ok();
    std::fs::remove_file(format!("{}.download", dest.display())).ok();

    let key = secretbox::gen_key();
    let link_mib = arg_after(args, "--link-mib").and_then(|v| v.parse().ok());
    let (send_stream, recv_stream) = socket_pair(&key, link_mib).await?;

    let job = fs::TransferJob::new_read(
        1,
        fs::JobType::Generic,
        dest_dir.to_string_lossy().to_string(),
        fs::DataSource::FilePath(source.clone()),
        0,
        false,
        false,
        true,
    )?;
    let files = job.files().clone();
    let total = job.total_size();
    // One file is named by the destination path, with an empty relative name, as in the app.
    let target = WriteTarget::new(dest.clone(), files)?;

    // The two ends are two processes in real life, and each gets its own runtime here.
    let rt_recv = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let peak_queue = Arc::new(AtomicU64::new(0));
    let (log_tx, mut log_rx) = mpsc::unbounded_channel::<String>();
    let log_drain = tokio::spawn(async move {
        let mut n = 0usize;
        while let Some(s) = log_rx.recv().await {
            n += 1;
            std::hint::black_box(s);
        }
        n
    });

    let started = Instant::now();
    let peak = peak_queue.clone();
    let receiver = rt_recv.spawn(async move {
        match direction {
            Direction::Up => run_target_receiver(mode, recv_stream, target, peak).await,
            Direction::Down => run_controller_receiver(recv_stream, target).await,
        }
    });
    let sender = tokio::spawn(run_sender(mode, send_stream, job, direction, log_tx));
    let received = receiver.await;
    let elapsed = started.elapsed().as_secs_f64();
    let sent = sender.await;
    let logs = log_drain.await.unwrap_or(0);
    rt_recv.shutdown_background();
    let mut report = sent??;
    let mut recv_lag = received??;

    let mib = total as f64 / MIB;
    println!(
        "{name} {mode:?} {direction:?}: {mib:.0} MiB in {elapsed:.2} s = {:.1} MiB/s",
        mib / elapsed
    );
    println!("  sender loop lag:   {}", report.lag.line());
    println!("  receiver loop lag: {}", recv_lag.line());
    println!("  echo through the socket: {}", report.echo.line());
    println!(
        "  CM logs sent: {logs}; peak queue to the CM: {:.1} MiB",
        peak_queue.load(Ordering::Relaxed) as f64 / MIB
    );
    let ok = same_bytes(&source, &dest)?;
    println!("  bytes match: {ok}");
    std::fs::remove_file(&dest).ok();
    if !ok {
        hbb_common::bail!("copy differs from source");
    }
    Ok(())
}

/// Both ends of a bench pair, so the key needn't travel. Nothing real is behind it.
fn peer_key() -> secretbox::Key {
    secretbox::Key([7u8; secretbox::KEYBYTES])
}

async fn peer_send(args: &[String]) -> ResultType<()> {
    let mode = match arg_after(args, "--mode").as_deref() {
        Some("tick") => Mode::Tick,
        _ => Mode::Pump,
    };
    let listener = TcpListener::bind(("127.0.0.1", args[1].parse::<u16>()?)).await?;
    let (socket, addr) = listener.accept().await?;
    socket.set_nodelay(true)?;
    let mut stream = Stream::from(socket, addr);
    stream.set_key(peer_key());
    let job = fs::TransferJob::new_read(
        1,
        fs::JobType::Generic,
        String::new(),
        fs::DataSource::FilePath(PathBuf::from(&args[0])),
        0,
        false,
        false,
        true,
    )?;
    stream
        .send(&fs::new_receive(1, String::new(), 0, job.files().clone(), job.total_size()))
        .await?;
    let (log_tx, _log_rx) = mpsc::unbounded_channel();
    run_sender(mode, stream, job, Direction::Up, log_tx).await?;
    Ok(())
}

async fn peer_recv(args: &[String]) -> ResultType<()> {
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", args[1].parse::<u16>()?)).await?;
    socket.set_nodelay(true)?;
    let addr = socket.local_addr()?;
    let mut stream = Stream::from(socket, addr);
    stream.set_key(peer_key());
    let Some(Ok(first)) = stream.next().await else {
        hbb_common::bail!("the sender went away")
    };
    let Some(message::Union::FileAction(action)) = Message::parse_from_bytes(&first)?.union else {
        hbb_common::bail!("expected the file list first")
    };
    let Some(file_action::Union::Receive(r)) = action.union else {
        hbb_common::bail!("expected the file list first")
    };
    run_controller_receiver(stream, WriteTarget::new(PathBuf::from(&args[0]), r.files)?).await?;
    // The last write can still be on its thread as Done lands.
    time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

/// What one core manages per step of a 128 KiB block, in CPU time so a busy machine doesn't lie.
fn cost() {
    #[cfg(unix)]
    fn cpu_seconds() -> f64 {
        let mut r: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
        let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
        t(r.ru_utime) + t(r.ru_stime)
    }
    #[cfg(not(unix))]
    fn cpu_seconds() -> f64 {
        std::time::UNIX_EPOCH.elapsed().map_or(0., |t| t.as_secs_f64())
    }
    let block = vec![0x5Au8; 128 * 1024];
    let key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();
    let n = 8192; // 1 GiB
    let step = |name: &str, f: &mut dyn FnMut()| {
        let t = cpu_seconds();
        for _ in 0..n {
            f();
        }
        println!("{name}: {:.0} MiB/s of CPU", n as f64 * 128.0 / 1024.0 / (cpu_seconds() - t));
    };
    let sealed = secretbox::seal(&block, &nonce, &key);
    step("secretbox seal", &mut || {
        std::hint::black_box(secretbox::seal(&block, &nonce, &key));
    });
    step("secretbox open", &mut || {
        std::hint::black_box(secretbox::open(&sealed, &nonce, &key).ok());
    });
    let msg = fs::new_block(FileTransferBlock {
        id: 1,
        data: block.clone().into(),
        ..Default::default()
    });
    let wire = msg.write_to_bytes().unwrap();
    step("protobuf encode", &mut || {
        std::hint::black_box(msg.write_to_bytes().ok());
    });
    step("protobuf decode", &mut || {
        std::hint::black_box(Message::parse_from_bytes(&wire).ok());
    });
    step("memcpy", &mut || {
        std::hint::black_box(block.clone());
    });
}

#[tokio::main]
async fn main() -> ResultType<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("make") if args.len() == 4 => make(&args[1], args[2].parse()?, Path::new(&args[3])),
        Some("run") if args.len() >= 3 => run(&args[1..]).await,
        Some("peer-send") if args.len() >= 3 => peer_send(&args[1..]).await,
        Some("peer-recv") if args.len() >= 3 => peer_recv(&args[1..]).await,
        Some("cost") => {
            cost();
            Ok(())
        }
        _ => {
            eprintln!("usage: see the top of libs/base/examples/transfer_bench.rs");
            std::process::exit(2);
        }
    }
}
