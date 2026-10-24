//! A provider item's fetch against the real Cloud Files driver and a stand-in daemon: the
//! placeholder is read in the middle, the driver asks for a window (the whole file under the
//! `FULL` hydration policy, which is what is recorded and bounded here; `fetch_window` has its
//! own unit test for narrower ones), the host serves it from the daemon's handoff file, the
//! placeholder is evicted, and a second open fetches again. Real Cloud Files state (`#[ignore]`d): run on a Windows machine with
//! `cargo test -- --ignored fetch_tests`.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    MaterializeProgress, MaterializeToTempResponse, ShellIpcMessage,
};

use crate::provider_namespace::{evict, placeholder_info};

/// These tests share process-wide state (the environment variables that point the host at their
/// stand-in daemon, the shown versions, the fetch and transfer logs, the active fetches), so one
/// runs at a time whatever `--test-threads` says. A test that failed does not stop the others.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

const SIZE: usize = 3 * (1 << 20) + 12_345;
const ROOT_ID: &[u8] = b"fetch-test-root!";
const ITEM_ID: &[u8] = b"fetch-test-item!";
const VERSION: [u8; 32] = [0x42; 32];

/// The content of the item: a function of the offset, so any window can be checked.
fn byte_at(offset: usize) -> u8 {
    (offset.wrapping_mul(31).wrapping_add(offset >> 8)) as u8
}

fn content() -> Vec<u8> {
    (0..SIZE).map(byte_at).collect()
}

/// A daemon that answers every materialization with a fresh handoff file of [`content`].
fn spawn_daemon(pipe: String, handoff: PathBuf, requests: Arc<AtomicUsize>, size: usize) {
    spawn_refusing_daemon(pipe, handoff, requests, size, Arc::new(AtomicI32::new(0)));
}

/// Like [`spawn_daemon`], but while `refuse` holds a `MaterializeFailure` number other than 0
/// every request is answered with that failure instead of bytes.
fn spawn_refusing_daemon(
    pipe: String,
    handoff: PathBuf,
    requests: Arc<AtomicUsize>,
    size: usize,
    refuse: Arc<AtomicI32>,
) {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(accept_forever(pipe, handoff, requests, size, refuse));
    });
}

async fn accept_forever(
    pipe: String,
    handoff: PathBuf,
    requests: Arc<AtomicUsize>,
    size: usize,
    refuse: Arc<AtomicI32>,
) {
    let mut server = ServerOptions::new().first_pipe_instance(true).create(&pipe).unwrap();
    loop {
        server.connect().await.unwrap();
        let stream = server;
        server = ServerOptions::new().create(&pipe).unwrap();
        tokio::spawn(serve_connection(
            stream,
            handoff.clone(),
            requests.clone(),
            size,
            refuse.clone(),
        ));
    }
}

async fn serve_connection(
    mut stream: NamedPipeServer,
    handoff: PathBuf,
    requests: Arc<AtomicUsize>,
    size: usize,
    refuse: Arc<AtomicI32>,
) {
    while let Ok(Some(message)) = read_message::<ShellIpcMessage>(&mut stream).await {
        let Some(Payload::MaterializeToTempRequest(request)) = message.payload else {
            continue;
        };
        let n = requests.fetch_add(1, Ordering::SeqCst) + 1;
        let refusal = refuse.load(Ordering::SeqCst);
        if refusal != 0 {
            let response = MaterializeToTempResponse {
                request_id: request.request_id,
                ok: false,
                failure: refusal,
                error: "refused by the stand-in daemon".into(),
                ..Default::default()
            };
            let reply = Payload::MaterializeToTempResponse(response);
            let _ = write_message(&mut stream, &ShellIpcMessage { payload: Some(reply) }).await;
            continue;
        }
        // A request that asked for progress gets it before the answer, as the daemon does:
        // monotonic, below the total until the content is verified, then one `done`.
        if request.report_progress {
            for step in 1..=4u64 {
                let progress = Payload::MaterializeProgress(MaterializeProgress {
                    request_id: request.request_id.clone(),
                    completed: step * 25,
                    total: 100,
                    done: step == 4,
                });
                let _ =
                    write_message(&mut stream, &ShellIpcMessage { payload: Some(progress) }).await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        let name = format!("handoff-{n}.bin");
        // A ranged request is answered with that window of the version it names; a request
        // that does not ask for one gets the whole file.
        let (bytes, range) = if request.ranged {
            assert_eq!(request.requested_version_hash, VERSION.to_vec());
            let start = request.range_offset as usize;
            let end = (start + request.range_length as usize).min(size);
            (
                (start..end).map(byte_at).collect::<Vec<u8>>(),
                Some((start as u64, (end - start) as u64)),
            )
        } else {
            (content(), None)
        };
        std::fs::write(handoff.join(&name), bytes).unwrap();
        let response = MaterializeToTempResponse {
            request_id: request.request_id,
            ok: true,
            handoff_name: name,
            size: size as u64,
            version_hash: VERSION.to_vec(),
            ranged: range.is_some(),
            range_offset: range.map_or(0, |r| r.0),
            range_length: range.map_or(0, |r| r.1),
            ..Default::default()
        };
        let reply = Payload::MaterializeToTempResponse(response);
        let _ = write_message(&mut stream, &ShellIpcMessage { payload: Some(reply) }).await;
    }
}

fn read_window(path: &Path, offset: u64, length: usize) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut window = vec![0u8; length];
    file.read_exact(&mut window).unwrap();
    window
}

#[test]
#[ignore = "real Cloud Files state; run on a Windows machine"]
fn a_provider_item_is_fetched_evicted_and_fetched_again() {
    let _serial = one_at_a_time();
    let tmp = std::env::temp_dir().join(format!("yl-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root, handoff) = (tmp.join("root"), tmp.join("provider").join("handoff"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&handoff).unwrap();
    let pipe = format!(r"\\.\pipe\yl-fetch-test-{}", std::process::id());
    // SAFETY: this test runs alone (`--test-threads=1`); nothing else reads the environment.
    unsafe {
        std::env::set_var("YADORILINK_PROVIDER_TEMP_ROOT", tmp.join("provider"));
        std::env::set_var("YADORILINK_SHELL_IPC_PIPE", &pipe);
    }
    super::FETCHES.lock().unwrap().clear();
    let requests = Arc::new(AtomicUsize::new(0));
    spawn_daemon(pipe, handoff.clone(), requests.clone(), SIZE);

    let mut content_version = VERSION.to_vec();
    content_version.extend_from_slice(&1u64.to_le_bytes());
    crate::provider_client::set_shown_versions(ROOT_ID, [(ITEM_ID, content_version.as_slice())]);
    super::register_and_connect_provider(ROOT_ID, &root).expect("register and connect");
    super::create_item_placeholder(
        &yadorilink_fs_platform::durable_dir::NoLedger,
        &root,
        "big.bin",
        ITEM_ID,
        SIZE as u64,
        0,
        false,
    )
    .expect("the placeholder");
    let path = root.join("big.bin");
    let created = placeholder_info(&path).unwrap();
    assert!(
        created.dehydrated,
        "{created:?}, daemon asked {} time(s)",
        requests.load(Ordering::SeqCst)
    );

    // A read in the middle: the driver asks for a window, the host serves what was asked.
    let offset = 2 * (1 << 20) + 777;
    let window = read_window(&path, offset as u64, 1000);
    assert_eq!(window, (offset..offset + 1000).map(byte_at).collect::<Vec<_>>());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let fetches = super::FETCHES.lock().unwrap().clone();
    println!("driver fetch windows (offset, length): {fetches:?}");
    assert_eq!(fetches.len(), 1);
    let (required_offset, required_length) = fetches[0];
    assert!(required_offset >= 0 && required_offset + required_length <= SIZE as i64);
    assert!(
        required_offset <= offset as i64 && required_offset + required_length > offset as i64,
        "the window {required_offset}+{required_length} does not cover the read at {offset}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), content(), "the whole file reads back exactly");
    assert!(std::fs::read_dir(&handoff).unwrap().next().is_none(), "a handoff file was left");

    // Evicted: no bytes on the disk, the placeholder and its identity stay.
    evict(&path, ITEM_ID).expect("evict");
    let info = placeholder_info(&path).unwrap();
    assert!(info.dehydrated && info.in_sync, "{info:?}");

    // A second open fetches again, and the last bytes are exact.
    let tail = read_window(&path, (SIZE - 10) as u64, 10);
    assert_eq!(tail, (SIZE - 10..SIZE).map(byte_at).collect::<Vec<_>>());
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    let _ = std::fs::remove_file(&path);
    let _ = super::unregister(&root);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The peer is unreachable or the disk is full (the daemon answers with a failure, not bytes):
/// the read of a not-downloaded file fails instead of hanging or returning short data, the
/// placeholder stays not downloaded, and once the daemon can serve again the same file reads
/// back exactly.
#[test]
#[ignore = "real Cloud Files state; run on a Windows machine"]
fn a_refused_fetch_fails_the_read_and_the_file_reads_once_the_daemon_can_serve() {
    use yadorilink_ipc_proto::shellipc::MaterializeFailure;
    let _serial = one_at_a_time();
    let tmp = std::env::temp_dir().join(format!("yl-refuse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root, handoff) = (tmp.join("root"), tmp.join("provider").join("handoff"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&handoff).unwrap();
    let pipe = format!(r"\\.\pipe\yl-refuse-test-{}", std::process::id());
    // SAFETY: this test runs alone (`--test-threads=1`); nothing else reads the environment.
    unsafe {
        std::env::set_var("YADORILINK_PROVIDER_TEMP_ROOT", tmp.join("provider"));
        std::env::set_var("YADORILINK_SHELL_IPC_PIPE", &pipe);
    }
    super::FETCHES.lock().unwrap().clear();
    let requests = Arc::new(AtomicUsize::new(0));
    let refuse = Arc::new(AtomicI32::new(MaterializeFailure::Unobtainable as i32));
    spawn_refusing_daemon(pipe, handoff.clone(), requests.clone(), SIZE, refuse.clone());

    let mut content_version = VERSION.to_vec();
    content_version.extend_from_slice(&1u64.to_le_bytes());
    crate::provider_client::set_shown_versions(ROOT_ID, [(ITEM_ID, content_version.as_slice())]);
    super::register_and_connect_provider(ROOT_ID, &root).expect("register and connect");
    super::create_item_placeholder(
        &yadorilink_fs_platform::durable_dir::NoLedger,
        &root,
        "away.bin",
        ITEM_ID,
        SIZE as u64,
        0,
        false,
    )
    .expect("the placeholder");
    let path = root.join("away.bin");

    for failure in [MaterializeFailure::Unobtainable, MaterializeFailure::LowDisk] {
        refuse.store(failure as i32, Ordering::SeqCst);
        let started = std::time::Instant::now();
        // The read runs on its own thread so a hang fails this test instead of blocking it.
        let (sender, receiver) = std::sync::mpsc::channel();
        let read_path = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(std::fs::read(&read_path).map(|bytes| bytes.len()));
        });
        let read = receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("{failure:?}: the read hung for over 60 s"));
        println!("{failure:?}: read {read:?} after {:?}", started.elapsed());
        assert!(read.is_err(), "{failure:?}: a refused fetch must fail the read");
        let info = placeholder_info(&path).unwrap();
        assert!(info.dehydrated, "{failure:?}: nothing is downloaded after a refusal: {info:?}");
        assert!(std::fs::read_dir(&handoff).unwrap().next().is_none(), "a handoff file was left");
    }

    refuse.store(0, Ordering::SeqCst);
    assert_eq!(std::fs::read(&path).unwrap(), content(), "the file reads once the daemon serves");

    let _ = std::fs::remove_file(&path);
    let _ = super::unregister(&root);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// What the throttled stand-in daemon of the large-file tests saw.
#[derive(Clone, Debug)]
struct Seen {
    /// Seconds since the daemon started.
    at: f64,
    ranged: bool,
    offset: u64,
    length: u64,
}

/// How a throttled stand-in daemon behaves.
#[derive(Clone)]
struct Slow {
    size: u64,
    /// Bytes per second it takes to produce a window (a slow peer).
    rate: u64,
    /// Fail every ranged window from the n-th on (0-based) with VERSION_OUT_OF_DATE: the item
    /// has a newer version for good.
    version_moves_at: Option<usize>,
    log: Arc<std::sync::Mutex<Vec<Seen>>>,
    started: std::time::Instant,
}

fn spawn_slow_daemon(pipe: String, handoff: PathBuf, slow: Slow) {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let mut server = ServerOptions::new().first_pipe_instance(true).create(&pipe).unwrap();
            loop {
                server.connect().await.unwrap();
                let stream = server;
                server = ServerOptions::new().create(&pipe).unwrap();
                tokio::spawn(serve_slow(stream, handoff.clone(), slow.clone()));
            }
        });
    });
}

async fn serve_slow(mut stream: NamedPipeServer, handoff: PathBuf, slow: Slow) {
    while let Ok(Some(message)) = read_message::<ShellIpcMessage>(&mut stream).await {
        let Some(Payload::MaterializeToTempRequest(request)) = message.payload else {
            continue;
        };
        let (offset, length) = if request.ranged {
            (request.range_offset, request.range_length.min(slow.size - request.range_offset))
        } else {
            (0, slow.size)
        };
        let ranged_before = {
            let mut log = slow.log.lock().unwrap();
            let before = log.iter().filter(|s| s.ranged).count();
            log.push(Seen {
                at: slow.started.elapsed().as_secs_f64(),
                ranged: request.ranged,
                offset,
                length,
            });
            before
        };
        let response =
            if request.ranged && slow.version_moves_at.is_some_and(|n| ranged_before >= n) {
                MaterializeToTempResponse {
                    request_id: request.request_id,
                    ok: false,
                    failure: yadorilink_ipc_proto::shellipc::MaterializeFailure::VersionOutOfDate
                        as i32,
                    error: "the version is not current".into(),
                    ..Default::default()
                }
            } else {
                static NAMES: AtomicUsize = AtomicUsize::new(0);
                let name = format!("handoff-slow-{}.bin", NAMES.fetch_add(1, Ordering::SeqCst));
                let path = handoff.join(&name);
                if request.ranged {
                    // A slow peer: the bytes of the window take as long as its share of the rate.
                    tokio::time::sleep(std::time::Duration::from_micros(
                        length * 1_000_000 / slow.rate,
                    ))
                    .await;
                    let bytes: Vec<u8> =
                        (offset..offset + length).map(|o| byte_at(o as usize)).collect();
                    std::fs::write(&path, bytes).unwrap();
                } else {
                    // The whole version (what records the handoff): the host only deletes it.
                    std::fs::File::create(&path).unwrap().set_len(slow.size).unwrap();
                }
                MaterializeToTempResponse {
                    request_id: request.request_id,
                    ok: true,
                    handoff_name: name,
                    size: slow.size,
                    version_hash: VERSION.to_vec(),
                    ranged: request.ranged,
                    range_offset: if request.ranged { offset } else { 0 },
                    range_length: if request.ranged { length } else { 0 },
                    ..Default::default()
                }
            };
        let reply = Payload::MaterializeToTempResponse(response);
        let _ = write_message(&mut stream, &ShellIpcMessage { payload: Some(reply) }).await;
    }
}

/// A placeholder of `size` bytes in a fresh sync root served by a throttled stand-in daemon.
struct Slowroom {
    tmp: PathBuf,
    root: PathBuf,
    path: PathBuf,
    log: Arc<std::sync::Mutex<Vec<Seen>>>,
}

fn slowroom(name: &str, size: u64, rate: u64, version_moves_at: Option<usize>) -> Slowroom {
    let tmp = std::env::temp_dir().join(format!("yl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root, handoff) = (tmp.join("root"), tmp.join("provider").join("handoff"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&handoff).unwrap();
    let pipe = format!(r"\\.\pipe\yl-{name}-{}", std::process::id());
    // SAFETY: these tests run alone (`--test-threads=1`); nothing else reads the environment.
    unsafe {
        std::env::set_var("YADORILINK_PROVIDER_TEMP_ROOT", tmp.join("provider"));
        std::env::set_var("YADORILINK_SHELL_IPC_PIPE", &pipe);
    }
    super::FETCHES.lock().unwrap().clear();
    super::TRANSFERS.lock().unwrap().clear();
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let slow =
        Slow { size, rate, version_moves_at, log: log.clone(), started: std::time::Instant::now() };
    spawn_slow_daemon(pipe, handoff, slow);
    let mut content_version = VERSION.to_vec();
    content_version.extend_from_slice(&1u64.to_le_bytes());
    crate::provider_client::set_shown_versions(ROOT_ID, [(ITEM_ID, content_version.as_slice())]);
    super::register_and_connect_provider(ROOT_ID, &root).expect("register and connect");
    super::create_item_placeholder(
        &yadorilink_fs_platform::durable_dir::NoLedger,
        &root,
        "big.bin",
        ITEM_ID,
        size,
        0,
        false,
    )
    .expect("the placeholder");
    let path = root.join("big.bin");
    assert!(placeholder_info(&path).unwrap().dehydrated);
    Slowroom { tmp, root, path, log }
}

impl Slowroom {
    fn finish(self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = super::unregister(&self.root);
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// A fresh 1 GiB placeholder and a slow peer (24 MB/s, which makes the whole file take longer
/// than the 40 s a single request used to get). The first open is a whole-file fetch under the
/// `FULL` policy. It is served in bounded windows: each is asked for and delivered in turn, the
/// reader gets exact bytes without a timeout or retry, and the whole version is recorded once,
/// after the last window.
#[test]
#[ignore = "real Cloud Files state and about a minute; run on a Windows machine"]
fn a_gib_whole_file_fetch_is_served_window_by_window() {
    let _serial = one_at_a_time();
    const GIB: u64 = 1 << 30;
    let room = slowroom("gib", GIB, 24_000_000, None);
    let started = std::time::Instant::now();

    let mut file = std::fs::File::open(&room.path).expect("open");
    let opened = started.elapsed().as_secs_f64();
    let mut head = vec![0u8; 4096];
    file.read_exact(&mut head).expect("the first read");
    let first_bytes = started.elapsed().as_secs_f64();
    assert_eq!(head, (0..4096).map(byte_at).collect::<Vec<_>>());

    // The rest: the first and last MiB exactly, 64 bytes at every MiB in between.
    let mib = 1usize << 20;
    let mut chunk = vec![0u8; mib];
    file.seek(SeekFrom::Start(0)).unwrap();
    for n in 0..(GIB as usize / mib) {
        file.read_exact(&mut chunk).expect("read");
        let base = n * mib;
        if n == 0 || n == GIB as usize / mib - 1 {
            assert!(chunk.iter().enumerate().all(|(i, b)| *b == byte_at(base + i)), "MiB {n}");
        } else {
            assert!((0..64).all(|i| chunk[i] == byte_at(base + i)), "MiB {n}");
        }
    }
    let total = started.elapsed().as_secs_f64();
    drop(file);
    let transfers = super::TRANSFERS.lock().unwrap().clone();
    let transfer_times: Vec<f64> =
        transfers.iter().map(|t| t.0.duration_since(started).as_secs_f64()).collect();
    let first_transfer = transfer_times.first().copied().unwrap_or(f64::MAX);
    let before_open_returned = transfer_times.iter().filter(|t| **t < opened).count();

    // The whole version is recorded after the last window, without the reader waiting for it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while room.log.lock().unwrap().iter().all(|s| s.ranged) && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let seen = room.log.lock().unwrap().clone();
    let windows: Vec<&Seen> = seen.iter().filter(|s| s.ranged).collect();
    let whole: Vec<&Seen> = seen.iter().filter(|s| !s.ranged).collect();
    println!(
        "first CfExecute {first_transfer:.2}s ({before_open_returned} of {} transfers made before \
         open returned), open returned {opened:.2}s, first 4 KiB {first_bytes:.2}s, whole file \
         read {total:.2}s, {} ranged windows (first answered {:.2}s, last requested {:.2}s), {} whole-version request(s)",
        transfers.len(),
        windows.len(),
        windows.first().map_or(0.0, |s| s.at),
        windows.last().map_or(0.0, |s| s.at),
        whole.len()
    );
    assert!(windows.len() as u64 >= GIB / crate::windowed_fetch::WINDOW);
    let mut at = 0;
    for window in &windows {
        assert_eq!(window.offset, at, "windows are asked for in order, without gaps");
        assert!(window.length <= crate::windowed_fetch::WINDOW);
        at += window.length;
    }
    assert_eq!(at, GIB);
    assert_eq!(whole.len(), 1, "the whole version is recorded exactly once");
    assert!(whole[0].at >= windows.last().unwrap().at, "and only after the last window");
    // Bounded forward progress, not one long wait: the host hands bytes to the system long
    // before the old timeout, window after window while the open is still outstanding (under
    // `FULL` the open itself completes with the file), and the whole file takes longer than the
    // old timeout, which a single request could not do.
    assert!(first_transfer < 5.0, "the first CfExecute came after {first_transfer:.1}s");
    assert!(transfers.iter().all(|t| t.3), "the operating system took every transfer");
    assert!(before_open_returned >= 100, "only {before_open_returned} transfers before the open");
    assert!(total > 40.0, "the whole file took only {total:.1}s; the rate no longer exceeds 40 s");
    let info = placeholder_info(&room.path).unwrap();
    assert!(!info.dehydrated, "all bytes were delivered: {info:?}");
    room.finish();
}

/// The version moves while a large file is being served: the window that finds out fails, no
/// later window is asked for, the reader gets an error, the whole version is not recorded and the
/// placeholder never reads as hydrated.
#[test]
#[ignore = "real Cloud Files state; run on a Windows machine"]
fn a_version_change_mid_transfer_fails_the_read_and_records_nothing() {
    let _serial = one_at_a_time();
    const SIZE: u64 = 64 << 20;
    let room = slowroom("moves", SIZE, 200_000_000, Some(3));
    let mut file = std::fs::File::open(&room.path).ok();
    let read = file.as_mut().map(|f| {
        let mut all = Vec::new();
        f.read_to_end(&mut all).map(|_| all.len())
    });
    println!("read after a version change: {read:?}");
    assert!(!matches!(read, Some(Ok(n)) if n as u64 == SIZE), "the read must not succeed");
    drop(file);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let seen = room.log.lock().unwrap().clone();
    assert!(seen.iter().all(|s| s.ranged), "no whole version was recorded: {seen:?}");
    // Only the three windows before the move were ever delivered, however often the system retried.
    let delivered: u64 = super::TRANSFERS.lock().unwrap().iter().map(|t| t.2 as u64).sum();
    assert_eq!(delivered, 3 * crate::windowed_fetch::WINDOW, "{seen:?}");
    assert!(placeholder_info(&room.path).unwrap().dehydrated, "partial progress is not hydrated");
    room.finish();
}

/// The reader goes away while a large file is being served: the driver cancels the fetch and no
/// further window is asked for.
#[test]
#[ignore = "real Cloud Files state and about half a minute; run on a Windows machine"]
fn a_cancelled_fetch_stops_asking_for_windows() {
    let _serial = one_at_a_time();
    const SIZE: u64 = 512 << 20;
    let room = slowroom("cancel", SIZE, 32_000_000, None);
    let path = room.path.clone();
    // The open blocks until the whole file is there under `FULL`; the reader gives up early.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(std::fs::File::open(&path).map(|_| ()));
    });
    std::thread::sleep(std::time::Duration::from_secs(3));
    let asked_before = room.log.lock().unwrap().len();
    println!("windows asked for after 3s: {asked_before}");
    assert!(asked_before >= 1 && (asked_before as u64) < SIZE / crate::windowed_fetch::WINDOW);
    // Cancel by what the driver does when the reader's request goes away: the host's own
    // cancellation entry point, with the range covering everything left.
    let key = super::ACTIVE_FETCHES.lock().unwrap().first().map(|f| (f.connection, f.transfer));
    let (connection, transfer) = key.expect("a fetch is being served");
    super::cancel_fetches(connection, transfer, 0, SIZE as i64);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let after_cancel = room.log.lock().unwrap().len();
    std::thread::sleep(std::time::Duration::from_secs(5));
    let later = room.log.lock().unwrap().len();
    println!("requests at cancel {after_cancel}, 5 s later {later}");
    assert!(later <= after_cancel + 1 && later == room.log.lock().unwrap().len());
    assert!(
        room.log.lock().unwrap().iter().all(|s| s.ranged),
        "a cancelled fetch records no whole version"
    );
    let _ = receiver.recv_timeout(std::time::Duration::from_secs(30));
    room.finish();
}

/// Reads a not-downloaded provider item whose fetch the daemon refuses with `failure`, and
/// returns the error the reader gets.
fn refused_read_error(failure: i32) -> std::io::Error {
    let _serial = one_at_a_time();
    let tmp = std::env::temp_dir().join(format!("yl-refused-{}-{failure}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root, handoff) = (tmp.join("root"), tmp.join("provider").join("handoff"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&handoff).unwrap();
    let pipe = format!(r"\\.\pipe\yl-refused-test-{}-{failure}", std::process::id());
    // SAFETY: the tests of this module run one at a time.
    unsafe {
        std::env::set_var("YADORILINK_PROVIDER_TEMP_ROOT", tmp.join("provider"));
        std::env::set_var("YADORILINK_SHELL_IPC_PIPE", &pipe);
    }
    spawn_refusing_daemon(
        pipe,
        handoff,
        Arc::new(AtomicUsize::new(0)),
        SIZE,
        Arc::new(AtomicI32::new(failure)),
    );
    let mut content_version = VERSION.to_vec();
    content_version.extend_from_slice(&1u64.to_le_bytes());
    crate::provider_client::set_shown_versions(ROOT_ID, [(ITEM_ID, content_version.as_slice())]);
    super::register_and_connect_provider(ROOT_ID, &root).expect("register and connect");
    super::create_item_placeholder(
        &yadorilink_fs_platform::durable_dir::NoLedger,
        &root,
        "big.bin",
        ITEM_ID,
        SIZE as u64,
        0,
        false,
    )
    .expect("the placeholder");
    let path = root.join("big.bin");
    let error = std::fs::read(&path).expect_err("a refused fetch must fail the read");
    assert!(placeholder_info(&path).unwrap().dehydrated, "nothing was downloaded");
    let _ = std::fs::remove_file(&path);
    let _ = super::unregister(&root);
    let _ = std::fs::remove_dir_all(&tmp);
    error
}

/// Explorer and applications can tell a full disk from an unreachable device: each refusal ends
/// the read with its own error, not one generic cloud-file failure.
#[test]
#[ignore = "real Cloud Files state; run on a Windows machine"]
fn a_refused_fetch_fails_the_read_with_the_reason() {
    use yadorilink_ipc_proto::shellipc::MaterializeFailure;
    let disk = refused_read_error(MaterializeFailure::LowDisk as i32);
    let offline = refused_read_error(MaterializeFailure::Unobtainable as i32);
    let other = refused_read_error(MaterializeFailure::NotReady as i32);
    let moved = refused_read_error(MaterializeFailure::VersionOutOfDate as i32);
    println!(
        "low disk: {disk:?}\nunobtainable: {offline:?}\nnot ready: {other:?}\nversion: {moved:?}"
    );
    let codes = [
        disk.raw_os_error(),
        offline.raw_os_error(),
        other.raw_os_error(),
        moved.raw_os_error(),
    ];
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert_ne!(a, b, "{codes:?}");
        }
    }
    // ERROR_CLOUD_FILE_INSUFFICIENT_RESOURCES, ..._NETWORK_UNAVAILABLE, ..._UNSUCCESSFUL, and
    // ..._NOT_IN_SYNC for a version that is no longer available.
    let not_in_sync = windows::Win32::Foundation::ERROR_CLOUD_FILE_NOT_IN_SYNC.0 as i32;
    assert_eq!(codes, [Some(387), Some(388), Some(389), Some(not_in_sync)]);
}

/// Reading a not-downloaded file reports how far the fetch is to the operating system: every
/// report below the total (the read is what completes it), never backwards, and the content
/// is complete and right afterwards.
#[test]
#[ignore = "real Cloud Files state; run on a Windows machine"]
fn a_fetch_reports_truthful_progress_to_the_system() {
    let _serial = one_at_a_time();
    let tmp = std::env::temp_dir().join(format!("yl-progress-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root, handoff) = (tmp.join("root"), tmp.join("provider").join("handoff"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&handoff).unwrap();
    let pipe = format!(r"\\.\pipe\yl-progress-test-{}", std::process::id());
    // SAFETY: the tests of this module run one at a time.
    unsafe {
        std::env::set_var("YADORILINK_PROVIDER_TEMP_ROOT", tmp.join("provider"));
        std::env::set_var("YADORILINK_SHELL_IPC_PIPE", &pipe);
    }
    spawn_daemon(pipe, handoff, Arc::new(AtomicUsize::new(0)), SIZE);
    let mut content_version = VERSION.to_vec();
    content_version.extend_from_slice(&1u64.to_le_bytes());
    crate::provider_client::set_shown_versions(ROOT_ID, [(ITEM_ID, content_version.as_slice())]);
    super::register_and_connect_provider(ROOT_ID, &root).expect("register and connect");
    super::create_item_placeholder(
        &yadorilink_fs_platform::durable_dir::NoLedger,
        &root,
        "progress.bin",
        ITEM_ID,
        SIZE as u64,
        0,
        false,
    )
    .expect("the placeholder");
    let path = root.join("progress.bin");
    super::PROGRESS_REPORTS.lock().unwrap().clear();
    assert_eq!(std::fs::read(&path).unwrap(), content());
    let reports = super::PROGRESS_REPORTS.lock().unwrap().clone();
    println!("progress reports: {reports:?}");
    assert!(reports.len() >= 2, "the fetch reported progress: {reports:?}");
    let mut last = 0;
    for (total, completed) in &reports {
        assert_eq!(*total, SIZE as u64, "the total is the range the reader needed");
        assert!(*completed < *total, "complete before the read is: {reports:?}");
        assert!(*completed > last, "not increasing: {reports:?}");
        last = *completed;
    }
    let _ = std::fs::remove_file(&path);
    let _ = super::unregister(&root);
    let _ = std::fs::remove_dir_all(&tmp);
}
