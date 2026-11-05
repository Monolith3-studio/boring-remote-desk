//! boring-remote (v1.7 t27): file transfer at whatever the slowest link is. Upstream sends one
//! 128 KiB block per 1 ms tick; this module removes that ceiling and keeps the loop responsive.
//! Hooks into upstream (fs.rs, connection.rs, io_loop.rs, ui_cm_interface.rs, ipc.rs) are patches
//! in boring/rebrand.py. Nothing here touches the protocol.
#![allow(unexpected_cfgs)] // boring_stream_run: set by the patched libs/base/build.rs

use std::time::{Duration, Instant};

use crate::fs::{self, TransferJob};
use hbb_common::{protobuf::Message as _, ResultType};

/// How long one timer arm may hold a select loop while the socket keeps taking blocks.
pub const SLICE: Duration = Duration::from_millis(2);
/// The connection manager's progress log, which upstream sends per tick or per block.
pub const LOG_EVERY: Duration = Duration::from_millis(250);
/// Blocks sealed together in one go. The same run as [`ReadAhead`] reads per thread hop.
const RUN: usize = 8;
/// A block slower than this means the socket or the disk is what's limiting, and a run would only
/// hold the loop longer. At this pace a run holds it about 8 ms.
const RUN_IF_BLOCK_UNDER: Duration = Duration::from_millis(1);

/// What a job list has done so far: unchanged means nothing moved.
pub fn progress(jobs: &[TransferJob]) -> (usize, u64, i32) {
    jobs.iter().fold((jobs.len(), 0, 0), |(n, sent, files), j| {
        (n, sent + j.transferred(), files + j.file_num())
    })
}

/// Added to the Target's `platform_additions`: it stops reading the socket while its CM is behind
/// (see [`CmWindow`]). A Target without it queues every block in memory, so a Controller keeps
/// upstream's pace of one block per tick for it.
pub const FULL_SPEED_KEY: &str = "boring_full_speed_files";

pub fn target_takes_full_speed(platform_additions: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(platform_additions)
        .map_or(false, |v| v.get(FULL_SPEED_KEY).and_then(|k| k.as_bool()) == Some(true))
}

/// Already packed: zstd would only spend the sending loop's time on them.
/// Lower case; [`CompressGate`] lower-cases the name, since cameras write `.MOV`.
const NO_GAIN: &[&str] = &[
    // video and camera originals
    "mov", "mp4", "m4v", "mkv", "webm", "avi", "wmv", "flv", "mpg", "mpeg", "m2v", "m2ts", "mts",
    "ts", "vob", "3gp", "mxf", "braw", "r3d", "crm", "ari", "insv", "lrv",
    // stills
    "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif", "cr2", "cr3", "nef", "arw", "raf",
    "dng", "orf", "rw2",
    // audio
    "mp3", "aac", "m4a", "ogg", "opus", "flac", "wma",
    // archives and packages
    "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst", "lz4", "dmg", "pkg", "msi", "apk", "ipa",
    "jar", "deb", "rpm",
];

/// Whether to spend zstd on the next block of a file. Lives on the job, starts over per file.
#[derive(Debug, Default)]
pub struct CompressGate {
    file_num: usize,
    misses: u8,
}

impl CompressGate {
    /// This many blocks in a row saving under 5%, and the rest of the file goes as it is.
    const GIVE_UP_AFTER: u8 = 4;

    pub fn should_try(&mut self, file_num: usize, name: &str) -> bool {
        if self.file_num != file_num {
            *self = Self { file_num, misses: 0 };
        }
        if self.misses >= Self::GIVE_UP_AFTER {
            return false;
        }
        let ext = name.rsplit_once('.').map_or("", |(_, e)| e).to_ascii_lowercase();
        !NO_GAIN.contains(&ext.as_str())
    }

    pub fn saw(&mut self, raw: usize, packed: usize) {
        if packed.saturating_mul(20) >= raw.saturating_mul(19) {
            self.misses = self.misses.saturating_add(1);
        } else {
            self.misses = 0;
        }
    }
}

/// File reads a block at a time cost a thread hop each. This takes a run of blocks per hop.
#[derive(Debug, Default)]
pub struct ReadAhead {
    buf: Vec<u8>,
    at: usize,
}

impl ReadAhead {
    const SIZE: usize = 1024 * 1024;

    pub fn is_empty(&self) -> bool {
        self.at >= self.buf.len()
    }

    /// Where the next read goes. Follow it with [`Self::filled`].
    pub fn space(&mut self) -> &mut [u8] {
        self.buf.resize(Self::SIZE, 0);
        self.at = 0;
        &mut self.buf
    }

    pub fn filled(&mut self, n: usize) {
        self.buf.truncate(n);
    }

    /// Copies out as much as fits, and 0 means the read that filled it found the end of the file.
    pub fn take(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        n
    }

    /// The file moved under it: a skip, or a seek on resume.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.at = 0;
    }
}

/// Send until the socket pushes back or the slice is up, whichever is first. Returns the log line
/// of a finished job, and returns at once with it so none is lost.
pub async fn pump_read_jobs(
    jobs: &mut Vec<TransferJob>,
    stream: &mut hbb_common::Stream,
) -> ResultType<String> {
    pump_for(jobs, stream, SLICE).await
}

async fn pump_for(
    jobs: &mut Vec<TransferJob>,
    stream: &mut hbb_common::Stream,
    slice: Duration,
) -> ResultType<String> {
    let started = Instant::now();
    loop {
        let before = progress(jobs);
        let block_started = Instant::now();
        let log = fs::handle_read_jobs(jobs, stream).await?;
        let block_took = block_started.elapsed();
        let after = progress(jobs);
        // No movement means paused, or waiting on an overwrite answer: wait for the next tick.
        if !log.is_empty() || jobs.is_empty() || after == before {
            return Ok(log);
        }
        // Same file as before the call: its stream is open, so the next blocks can go as a run. A
        // new file goes back through handle_read_jobs, which opens it and asks about overwriting.
        if after.2 == before.2 && block_took < RUN_IF_BLOCK_UNDER {
            send_run(jobs, stream).await?;
        }
        if started.elapsed() >= slice {
            return Ok(log);
        }
    }
}

/// More of the file handle_read_jobs just sent from, in one go. It reads as that call does, and
/// leaves every other case (a new file, the end of a job, a question) to the next such call.
async fn send_run(jobs: &mut [TransferJob], stream: &mut hbb_common::Stream) -> ResultType<()> {
    let Some(job) = jobs.iter_mut().find(|j| !j.is_last_job) else {
        return Ok(());
    };
    let mut run = Vec::with_capacity(RUN);
    let mut failed = None;
    while run.len() < RUN {
        match job.read().await {
            Ok(Some(block)) => {
                let end_of_file = block.data.is_empty();
                run.push(fs::new_block(block).write_to_bytes()?);
                if end_of_file {
                    break;
                }
            }
            Ok(None) => break,
            Err(err) => {
                failed = Some(err);
                break;
            }
        }
    }
    #[cfg(boring_stream_run)]
    stream.send_run(run).await?;
    // A raw checkout's hbb_common, which boring/rebrand.py hasn't given send_run yet.
    #[cfg(not(boring_stream_run))]
    for msg in run {
        stream.send_raw(msg).await?;
    }
    if let Some(err) = failed {
        stream.send(&fs::new_error(job.id(), err, job.file_num())).await?;
    }
    Ok(())
}

/// True once per `period`, for logs that don't need every block.
#[derive(Default)]
pub struct Every(Option<Instant>);

impl Every {
    pub fn ready(&mut self, period: Duration) -> bool {
        let now = Instant::now();
        if self.0.map_or(true, |last| now.duration_since(last) >= period) {
            self.0 = Some(now);
            return true;
        }
        false
    }
}

/// Bytes the connection has queued for the CM and the CM hasn't written yet.
#[derive(Default)]
pub struct CmWindow(usize);

impl CmWindow {
    pub const LIMIT: usize = 32 * 1024 * 1024;

    pub fn spend(&mut self, bytes: usize) {
        self.0 += bytes;
    }

    pub fn refund(&mut self, bytes: usize) {
        self.0 = self.0.saturating_sub(bytes);
    }

    pub fn has_room(&self) -> bool {
        self.0 < Self::LIMIT
    }
}

/// The CM's side of [`CmWindow`]: ack in batches, so an ack doesn't cost an IPC message per block.
#[derive(Default)]
pub struct AckBatch(usize);

impl AckBatch {
    pub const SIZE: usize = 1024 * 1024;

    pub fn add(&mut self, bytes: usize) -> Option<usize> {
        self.0 += bytes;
        if self.0 >= Self::SIZE {
            return Some(std::mem::take(&mut self.0));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fs::*, message_proto::*};
    use hbb_common::{
        sodiumoxide::crypto::secretbox,
        tokio::{self, net::TcpListener, time},
        Stream,
    };
    use std::path::{Path, PathBuf};

    const BLOCK: u64 = 128 * 1024;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("file-speed-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn file(&self, name: &str, data: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, data).unwrap();
            p
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn noise(len: usize, mut s: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            out.extend_from_slice(&s.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    async fn pair() -> (Stream, Stream) {
        let key = secretbox::gen_key();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (b, peer) = l.accept().await.unwrap();
        a.set_nodelay(true).unwrap();
        b.set_nodelay(true).unwrap();
        let (mut sa, mut sb) = (Stream::from(a, addr), Stream::from(b, peer));
        sa.set_key(key.clone());
        sb.set_key(key);
        (sa, sb)
    }

    fn read_job(path: &Path, detect: bool) -> TransferJob {
        TransferJob::new_read(
            1,
            JobType::Generic,
            String::new(),
            DataSource::FilePath(path.to_path_buf()),
            0,
            false,
            false,
            detect,
        )
        .unwrap()
    }

    fn write_job(to: &Path, files: Vec<FileEntry>) -> TransferJob {
        TransferJob::new_write(
            1,
            JobType::Generic,
            String::new(),
            DataSource::FilePath(to.to_path_buf()),
            0,
            false,
            true,
            false,
        )
        .with_files(files)
        .unwrap()
    }

    /// The Controller's receive arm: writes blocks until Done. Answers TestDelay.
    async fn receive(mut stream: Stream, mut job: TransferJob) -> u64 {
        while let Some(Ok(bytes)) = stream.next().await {
            match Message::parse_from_bytes(&bytes).unwrap().union {
                Some(message::Union::FileResponse(fr)) => match fr.union {
                    Some(file_response::Union::Block(b)) => job.write(b).await.unwrap(),
                    Some(file_response::Union::Done(_)) => {
                        job.modify_time();
                        return job.finished_size();
                    }
                    _ => {}
                },
                Some(message::Union::TestDelay(t)) => {
                    let mut m = Message::new();
                    m.set_test_delay(t);
                    stream.send(&m).await.unwrap();
                }
                _ => {}
            }
        }
        panic!("sender went away before Done");
    }

    /// The engine's last write can still be on its thread when Done is handled, as upstream's is.
    async fn settled(path: &Path, want: &[u8]) -> Vec<u8> {
        for _ in 0..200 {
            if std::fs::metadata(path).map_or(false, |m| m.len() as usize >= want.len()) {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::read(path).unwrap()
    }

    async fn pump_to_end(jobs: &mut Vec<TransferJob>, stream: &mut Stream) {
        while !jobs.is_empty() {
            pump_read_jobs(jobs, stream).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn media_names_skip_compression_whatever_their_case() {
        for name in ["a.mov", "A001C002.MOV", "b.braw", "c.R3D", "d.mxf", "e.mp4", "f.heic", "g.zip", "dir/h.Jpg"] {
            assert!(!CompressGate::default().should_try(0, name), "{}", name);
        }
        for name in ["a.log", "b.txt", "c", "d.wav", "e.tar", "f.mov.txt"] {
            assert!(CompressGate::default().should_try(0, name), "{}", name);
        }
    }

    #[test]
    fn stops_trying_after_blocks_stop_shrinking_and_starts_over_on_the_next_file() {
        let mut g = CompressGate::default();
        for _ in 0..3 {
            assert!(g.should_try(0, "a.bin"));
            g.saw(1000, 1000);
        }
        assert!(g.should_try(0, "a.bin"));
        g.saw(1000, 960); // under 5% saved counts as no
        assert!(!g.should_try(0, "a.bin"));
        assert!(g.should_try(1, "b.bin"));
    }

    #[test]
    fn a_block_that_shrinks_resets_the_count() {
        let mut g = CompressGate::default();
        for _ in 0..3 {
            g.saw(1000, 1000);
        }
        g.saw(1000, 300);
        for _ in 0..3 {
            g.saw(1000, 1000);
        }
        assert!(g.should_try(0, "a.bin"));
    }

    #[test]
    fn read_ahead_hands_out_what_was_read_and_then_asks_again() {
        let mut r = ReadAhead::default();
        assert!(r.is_empty());
        r.space()[..5].copy_from_slice(b"hello");
        r.filled(5);
        assert!(!r.is_empty());
        let mut out = [0u8; 3];
        assert_eq!(r.take(&mut out), 3);
        assert_eq!(&out, b"hel");
        assert_eq!(r.take(&mut out), 2);
        assert_eq!(&out[..2], b"lo");
        assert!(r.is_empty());
        assert_eq!(r.take(&mut out), 0);
        // End of file: a fill of nothing stays empty.
        r.space();
        r.filled(0);
        assert!(r.is_empty());
        r.space()[..1].copy_from_slice(b"x");
        r.filled(1);
        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.take(&mut out), 0);
    }

    #[test]
    fn every_is_true_once_per_period() {
        let mut e = Every::default();
        assert!(e.ready(Duration::from_secs(3600)));
        assert!(!e.ready(Duration::from_secs(3600)));
        assert!(e.ready(Duration::ZERO));
    }

    #[test]
    fn the_cm_window_closes_at_the_limit_and_opens_on_acks() {
        let mut w = CmWindow::default();
        assert!(w.has_room());
        w.spend(CmWindow::LIMIT);
        assert!(!w.has_room());
        w.refund(1);
        assert!(w.has_room());
        w.refund(usize::MAX); // a stray ack can't wrap it
        w.spend(1);
        assert!(w.has_room());
    }

    #[test]
    fn acks_come_in_batches_that_add_up() {
        let mut a = AckBatch::default();
        let mut acked = 0;
        for _ in 0..16 {
            acked += a.add(BLOCK as usize).unwrap_or(0);
        }
        assert_eq!(acked, 16 * BLOCK as usize); // 8 blocks to a batch
    }

    #[test]
    fn only_a_target_that_says_so_gets_full_speed() {
        assert!(target_takes_full_speed(r#"{"boring_full_speed_files":true}"#));
        assert!(!target_takes_full_speed(r#"{"boring_remote":"1.6.4"}"#));
        assert!(!target_takes_full_speed(""));
        assert!(!target_takes_full_speed("{not json"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_multi_file_job_arrives_byte_for_byte() {
        let (src, dst) = (Dir::new("src"), Dir::new("dst"));
        let big = noise(5 * 1024 * 1024 + 17, 1);
        let text = b"the same line again\n".repeat(30_000);
        src.file("empty.bin", b"");
        src.file("big.mov", &big);
        src.file("sub/text.log", &text);
        let job = read_job(&src.0, false);
        assert_eq!(job.files().len(), 3);
        let (mut a, b) = pair().await;
        let rx = tokio::spawn(receive(b, write_job(&dst.0, job.files().clone())));
        let mut jobs = vec![job];
        pump_to_end(&mut jobs, &mut a).await;
        rx.await.unwrap();
        assert_eq!(settled(&dst.0.join("big.mov"), &big).await, big);
        assert_eq!(settled(&dst.0.join("sub/text.log"), &text).await, text);
        assert_eq!(std::fs::read(dst.0.join("empty.bin")).unwrap(), b"");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_call_sends_past_one_block_and_hands_the_loop_back() {
        let src = Dir::new("src");
        let path = src.file("big.bin", &noise(64 * 1024 * 1024, 2));
        let (mut a, mut b) = pair().await;
        tokio::spawn(async move { while let Some(Ok(_)) = b.next().await {} });
        let mut jobs = vec![read_job(&path, false)];
        // A long slice, since a debug build can spend all of the real one on a single block.
        let slice = Duration::from_millis(100);
        let t = Instant::now();
        pump_for(&mut jobs, &mut a, slice).await.unwrap();
        let (moved, took) = (jobs[0].transferred(), t.elapsed());
        assert!(moved > BLOCK, "one call moved {} bytes, the old ceiling is one block", moved);
        assert!(took >= slice && took < slice * 5, "the slice took {:?}", took);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn overwrite_question_holds_the_job_until_it_is_answered() {
        let src = Dir::new("src");
        let path = src.file("a.bin", &noise(1024 * 1024, 3));
        let (mut a, mut b) = pair().await;
        let mut jobs = vec![read_job(&path, true)];
        let t = Instant::now();
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        assert!(t.elapsed() < Duration::from_millis(250), "spun on the question");
        assert_eq!(jobs[0].transferred(), 0, "nothing goes before the answer");
        let first = b.next().await.unwrap().unwrap();
        let Some(message::Union::FileResponse(fr)) = Message::parse_from_bytes(&first).unwrap().union else {
            panic!("expected the digest")
        };
        assert!(matches!(fr.union, Some(file_response::Union::Digest(_))));
        // Still waiting, and asks only once.
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        assert_eq!(jobs[0].transferred(), 0);
        // "Overwrite":
        let answer = FileTransferSendConfirmRequest {
            id: 1,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
            ..Default::default()
        };
        jobs[0].confirm(&answer).await;
        tokio::spawn(async move { while let Some(Ok(_)) = b.next().await {} });
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        assert!(jobs[0].transferred() > 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn skip_moves_on_to_the_next_file_and_the_job_finishes() {
        let src = Dir::new("src");
        src.file("a.bin", &noise(300 * 1024, 4));
        src.file("b.bin", &noise(300 * 1024, 5));
        let mut jobs = vec![read_job(&src.0, true)];
        let (mut a, mut b) = pair().await;
        let digests = tokio::spawn(async move {
            let mut sent = 0;
            while let Some(Ok(bytes)) = b.next().await {
                if let Some(message::Union::FileResponse(fr)) = Message::parse_from_bytes(&bytes).unwrap().union {
                    match fr.union {
                        Some(file_response::Union::Block(block)) => sent += block.data.len(),
                        Some(file_response::Union::Done(_)) => return sent,
                        _ => {}
                    }
                }
            }
            sent
        });
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        let skip = |file_num| FileTransferSendConfirmRequest {
            id: 1,
            file_num,
            union: Some(file_transfer_send_confirm_request::Union::Skip(true)),
            ..Default::default()
        };
        jobs[0].confirm(&skip(0)).await;
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        jobs[0].confirm(&skip(1)).await;
        pump_to_end(&mut jobs, &mut a).await;
        assert_eq!(digests.await.unwrap(), 0, "both files were skipped");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_paused_job_stays_put_until_resumed() {
        let src = Dir::new("src");
        let path = src.file("a.bin", &noise(1024 * 1024, 6));
        let (mut a, mut b) = pair().await;
        tokio::spawn(async move { while let Some(Ok(_)) = b.next().await {} });
        let mut job = read_job(&path, false);
        job.is_last_job = true; // how the engine holds a job waiting for Resume
        let mut jobs = vec![job];
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        assert_eq!(jobs[0].transferred(), 0);
        jobs[0].is_last_job = false;
        pump_to_end(&mut jobs, &mut a).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resume_at_an_offset_sends_only_the_tail() {
        let (src, dst) = (Dir::new("src"), Dir::new("dst"));
        let data = noise(BLOCK as usize * 4 + 99, 7);
        let path = src.file("a.mov", &data);
        let offset = BLOCK as usize * 3;
        let mut job = read_job(&path, true);
        job.is_resume = true;
        let (mut a, b) = pair().await;
        let to = dst.0.join("tail.mov");
        let rx = tokio::spawn(receive(b, write_job(&to, job.files().clone())));
        let mut jobs = vec![job];
        pump_read_jobs(&mut jobs, &mut a).await.unwrap(); // sends the digest, opens the file
        jobs[0]
            .confirm(&FileTransferSendConfirmRequest {
                id: 1,
                file_num: 0,
                union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset as u32)),
                ..Default::default()
            })
            .await;
        pump_to_end(&mut jobs, &mut a).await;
        rx.await.unwrap();
        assert_eq!(settled(&to, &data[offset..]).await, &data[offset..]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_between_calls_stops_the_job_where_it_is() {
        let src = Dir::new("src");
        let path = src.file("a.bin", &noise(32 * 1024 * 1024, 8));
        let (mut a, mut b) = pair().await;
        tokio::spawn(async move { while let Some(Ok(_)) = b.next().await {} });
        let mut jobs = vec![read_job(&path, false)];
        pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        let job = remove_job(1, &mut jobs).expect("still running");
        assert!(job.transferred() < job.total_size());
        // The next tick has nothing to do, and says nothing.
        assert_eq!(pump_read_jobs(&mut jobs, &mut a).await.unwrap(), "");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_jobs_finish_and_each_finish_is_logged() {
        let src = Dir::new("src");
        let one = src.file("one.bin", &noise(BLOCK as usize, 9));
        let two = src.file("two.bin", &noise(BLOCK as usize, 10));
        let mut j2 = read_job(&two, false);
        j2.id = 2;
        let (mut a, mut b) = pair().await;
        tokio::spawn(async move { while let Some(Ok(_)) = b.next().await {} });
        let mut jobs = vec![read_job(&one, false), j2];
        let mut logs = Vec::new();
        while !jobs.is_empty() {
            let log = pump_read_jobs(&mut jobs, &mut a).await.unwrap();
            if !log.is_empty() {
                logs.push(log);
            }
        }
        assert_eq!(logs.len(), 2, "{:?}", logs);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_reader_pushes_back_and_loses_nothing() {
        let (src, dst) = (Dir::new("src"), Dir::new("dst"));
        let data = noise(8 * 1024 * 1024, 11);
        let path = src.file("a.bin", &data);
        let to = dst.0.join("a.bin");
        let job = read_job(&path, false);
        let mut w = write_job(&to, job.files().clone());
        let (mut a, mut b) = pair().await;
        let rx = tokio::spawn(async move {
            while let Some(Ok(bytes)) = b.next().await {
                let Some(message::Union::FileResponse(fr)) = Message::parse_from_bytes(&bytes).unwrap().union else {
                    continue;
                };
                match fr.union {
                    Some(file_response::Union::Block(block)) => {
                        w.write(block).await.unwrap();
                        time::sleep(Duration::from_millis(2)).await;
                    }
                    Some(file_response::Union::Done(_)) => {
                        w.modify_time();
                        return;
                    }
                    _ => {}
                }
            }
        });
        let mut jobs = vec![job];
        pump_to_end(&mut jobs, &mut a).await;
        rx.await.unwrap();
        assert_eq!(settled(&to, &data).await, data);
    }

    /// The hard requirement: a select loop running the pump keeps serving its other arms.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_select_loop_keeps_serving_input_during_a_transfer() {
        let (src, dst) = (Dir::new("src"), Dir::new("dst"));
        let path = src.file("big.bin", &noise(96 * 1024 * 1024, 12));
        let job = read_job(&path, false);
        let (mut a, b) = pair().await;
        let rx = tokio::spawn(receive(b, write_job(&dst.0.join("big.bin"), job.files().clone())));
        let mut jobs = vec![job];
        let mut timer = time::interval(Duration::from_millis(1));
        let mut input = time::interval(Duration::from_millis(5));
        input.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let mut last = Instant::now();
        let mut worst = Duration::ZERO;
        let (mut served, mut pumped, mut sent_probes, mut echoes) = (0u32, 0u32, 0i64, 0i64);
        while !jobs.is_empty() {
            tokio::select! {
                _ = timer.tick() => {
                    pump_read_jobs(&mut jobs, &mut a).await.unwrap();
                    pumped += 1;
                }
                _ = input.tick() => {
                    worst = worst.max(last.elapsed());
                    last = Instant::now();
                    served += 1;
                    let mut m = Message::new();
                    m.set_test_delay(TestDelay { time: sent_probes, ..Default::default() });
                    sent_probes += 1;
                    a.send(&m).await.unwrap();
                }
                res = a.next() => {
                    res.unwrap().unwrap();
                    echoes += 1;
                }
            }
        }
        rx.await.unwrap();
        assert!(echoes > 0, "no echo came back during the transfer");
        // Turns, not milliseconds, since a busy box stretches both alike. The bench prints the times.
        assert!(served * 20 >= pumped, "input ran {} times to the pump's {}", served, pumped);
        assert!(worst < Duration::from_secs(10), "the input arm waited {:?}", worst);
    }

    /// A run sealed together and frames opened together are the same bytes on the wire, so a peer
    /// doing either one at a time can't tell.
    #[cfg(boring_stream_run)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_run_is_the_same_on_the_wire_as_one_at_a_time() {
        let (mut a, mut b) = pair().await;
        let big = |n: u64| noise(128 * 1024, n);
        let want: Vec<Vec<u8>> = vec![big(1), big(2), b"small".to_vec(), big(3), vec![], big(4), big(5)];
        let reader = tokio::spawn({
            let want = want.clone();
            async move {
                for (i, w) in want.iter().enumerate() {
                    let got = b.next().await.unwrap().unwrap();
                    assert_eq!(&got[..], &w[..], "frame {} out of order or garbled", i);
                }
                // Now the other way round, against plain one-at-a-time sends.
                b.send_raw(big(6)).await.unwrap();
                b.send_run(vec![big(7), big(8), big(9)]).await.unwrap();
                b.send_raw(big(10)).await.unwrap();
                b
            }
        });
        a.send_raw(want[0].clone()).await.unwrap();
        a.send_run(want[1..3].to_vec()).await.unwrap();
        a.send_raw(want[3].clone()).await.unwrap();
        a.send_run(want[4..].to_vec()).await.unwrap();
        // Let them all reach the buffer, so next() opens a run.
        time::sleep(Duration::from_millis(100)).await;
        for n in 6..=10 {
            assert_eq!(&a.next().await.unwrap().unwrap()[..], &big(n)[..], "frame {}", n);
        }
        drop(reader.await.unwrap());
        assert!(a.next().await.is_none(), "the end of the stream still comes after the run");
    }

    fn engine_is_patched() -> bool {
        let patched = include_str!("fs.rs").contains("boring_compress");
        if !patched {
            eprintln!("raw checkout: fs.rs is upstream's until boring/rebrand.py runs, nothing to check");
        }
        patched
    }

    async fn first_block(path: &Path) -> FileTransferBlock {
        let mut job = read_job(path, false);
        job.init_data_stream_for_cm().await.unwrap();
        job.read().await.unwrap().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_engine_leaves_camera_files_alone_and_still_shrinks_text() {
        if !engine_is_patched() {
            return;
        }
        let dir = Dir::new("src");
        let text = b"the same line again\n".repeat(30_000);
        let mov = dir.file("a.MOV", &text);
        let log = dir.file("a.log", &text);
        assert!(!first_block(&mov).await.compressed, "a camera file went through zstd");
        assert!(first_block(&log).await.compressed, "text should still compress");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_engine_stops_trying_on_a_file_that_stopped_shrinking() {
        if !engine_is_patched() {
            return;
        }
        // Noise, then text: blocks past the fourth stay uncompressed though they could shrink.
        let mut data = noise(BLOCK as usize * 4, 13);
        data.extend_from_slice(&vec![b'x'; BLOCK as usize * 2]);
        let dir = Dir::new("src");
        let path = dir.file("mixed.bin", &data);
        let mut job = read_job(&path, false);
        job.init_data_stream_for_cm().await.unwrap();
        for _ in 0..6 {
            let block = job.read().await.unwrap().unwrap();
            assert!(!block.compressed);
        }
    }
}
