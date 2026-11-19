use crate::common::*;
use crate::jwt;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures_util::{
        future::{AbortHandle, Abortable},
        sink::SinkExt,
        stream::{self, FuturesUnordered, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        sync::{mpsc, watch, Mutex, Notify},
        time::{interval, Duration, MissedTickBehavior},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex as StdMutex, RwLock},
    time::Instant,
};

#[derive(Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
}

enum PeerTarget {
    Udp(SocketAddr),
    Tcp(TcpSender),
}

const REG_TIMEOUT: i64 = 30_000;
type TcpSender = mpsc::Sender<Bytes>;
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
const CHECK_RELAY_CONCURRENCY: usize = 8;
const RELAY_CANDIDATE_CONCURRENCY: usize = 4;
const RELAY_CANDIDATE_DELAY: Duration = Duration::from_millis(200);
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
static MUST_LOGIN: AtomicBool = AtomicBool::new(false);
const MAX_RELAY_UUID_LEN: usize = 128;

fn validate_relay_address(address: &str) -> Result<(), &'static str> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return if socket.port() == 0 {
            Err("Invalid relay server port")
        } else {
            Ok(())
        };
    }
    if address.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    let hostname = match address.split_once(':') {
        Some((hostname, port)) => {
            if !port.bytes().all(|byte| byte.is_ascii_digit())
                || !port.parse::<u16>().is_ok_and(|port| port != 0)
            {
                return Err("Invalid relay server port");
            }
            hostname
        }
        None => address,
    };
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.split('.').count() == 4
        && hostname.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err("Invalid relay server IP address");
    }
    if hostname.len() > 253
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("Invalid relay server list");
    }
    Ok(())
}

fn tcp_register_enabled() -> bool {
    matches!(
        get_arg("ENABLE_TCP_REGISTER").to_ascii_uppercase().as_str(),
        "Y" | "YES" | "1" | "TRUE"
    )
}

// The peer sends this uuid to whatever relay_server names, so keep control bytes out of it.
fn validate_relay_uuid(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_RELAY_UUID_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid relay UUID");
    }
    Ok(())
}

// A peer acknowledging a RequestRelay leaves both fields empty.
fn validate_relay_response(uuid: &str, relay_server: &str) -> Result<(), &'static str> {
    if uuid.is_empty() && relay_server.is_empty() {
        return Ok(());
    }
    validate_relay_uuid(uuid)
}

// An online query for about 5000 ids is the largest message a client sends here.
const DEFAULT_MAX_MESSAGE_KB: usize = 64;
// A knob that can be turned to unbounded is not a bound.
const MAX_MESSAGE_KB_CAP: usize = 64 << 10;
// tungstenite's default, so raising MAX_MESSAGE_KB does not widen a frame past it.
const WS_DEFAULT_MAX_FRAME_SIZE: usize = 16 << 20;
// Every connection pays its read buffer up front, and tungstenite's default is 128 KiB.
const WS_BUFFER_SIZE: usize = 8 << 10;
static MAX_MESSAGE: Lazy<usize> =
    Lazy::new(|| max_message_kb(&get_arg("MAX_MESSAGE_KB")) << 10);

fn max_message_kb(arg: &str) -> usize {
    match arg.parse::<usize>() {
        Ok(kb) if kb > 0 => kb.min(MAX_MESSAGE_KB_CAP),
        _ => DEFAULT_MAX_MESSAGE_KB,
    }
}

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 { return; }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        if lock.len() >= max { lock.pop_front(); }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

#[derive(Default)]
struct RelayState {
    configured: Arc<RelayServers>,
    available: Vec<usize>,
    health: Vec<RelayHealth>,
}

#[derive(Clone, Copy, Default)]
struct RelayHealth {
    last_reply: Option<RelayReply>,
    next_candidate: usize,
}

#[derive(Clone, Copy)]
struct RelayReply {
    socket: SocketAddr,
    failures: u8,
}

impl RelayState {
    fn set(&mut self, servers: RelayServers) -> Arc<RelayServers> {
        let previous: HashMap<_, _> = self
            .health
            .iter()
            .enumerate()
            .map(|(index, &health)| {
                let available = self.available.binary_search(&index).is_ok();
                (
                    relay_probe_endpoint(&self.configured[index]),
                    (available, health),
                )
            })
            .collect();
        self.available.clear();
        self.health.clear();
        for (index, server) in servers.iter().enumerate() {
            let (available, health) = previous
                .get(&relay_probe_endpoint(server))
                .copied()
                .unwrap_or_default();
            self.health.push(health);
            if available {
                self.available.push(index);
            }
        }
        let servers = Arc::new(servers);
        self.configured = servers.clone();
        servers
    }

    fn record_probe(&mut self, index: usize, probe: RelayProbe) {
        let available = self.available.binary_search(&index);
        let health = &mut self.health[index];
        if matches!(probe, RelayProbe::Reachable(_) | RelayProbe::Failed) {
            health.next_candidate = health.next_candidate.wrapping_add(1);
        }
        match probe {
            RelayProbe::Reachable(socket) => {
                health.last_reply = Some(RelayReply {
                    socket,
                    failures: 0,
                });
                if let Err(position) = available {
                    self.available.insert(position, index);
                }
            }
            RelayProbe::Failed | RelayProbe::Unresolved => {
                // Retain the last responding IP as a hint for recovery.
                if let Some(reply) = health.last_reply.as_mut() {
                    reply.failures = reply.failures.saturating_add(1);
                }
                if let Ok(position) = available {
                    self.available.remove(position);
                }
            }
            RelayProbe::Deferred => {}
        }
    }
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, TcpSender>>>,
    tcp_peers: Arc<Mutex<HashMap<String, TcpSender>>>,
    tcp_peer_ids: Arc<Mutex<HashSet<String>>>,
    pm: PeerMap,
    tx: Sender,
    relays: Arc<RwLock<RelayState>>,
    relay_changed: Arc<Notify>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    pub fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(Self::run(bind_addr, port, serial, key, rmem));
        // Blocking system DNS cannot be canceled. Do not wait indefinitely during shutdown.
        runtime.shutdown_timeout(Duration::from_secs(1));
        result
    }

    async fn run(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            tcp_peers: Arc::new(Mutex::new(HashMap::new())),
            tcp_peer_ids: Arc::new(Mutex::new(HashSet::new())),
            pm,
            tx: tx.clone(),
            relays: Default::default(),
            relay_changed: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        let relays: RelayServers = get_arg("relay-servers")
            .split(',')
            .filter(|address| !address.is_empty())
            .filter_map(|address| match validate_relay_address(address) {
                Ok(_) => Some(address.to_owned()),
                Err(err) => {
                    log::warn!("{err}: {address}");
                    None
                }
            })
            .collect();
        log::info!("relay-servers={:?}", relays);
        rs.relays.write().unwrap().set(relays);
        let mut listener = create_tcp_listener(bind_addr, port).await?;
        let mut listener2 = create_tcp_listener(bind_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(bind_addr, ws_port).await?;
        let mut listener_console = listen_console(bind_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        log::info!("MAX_MESSAGE_KB={}", *MAX_MESSAGE >> 10);
        let test_addr = get_arg("TEST_HBBS");
        if get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        let must_login = get_arg("must-login");
        let must_login_enabled = must_login.eq_ignore_ascii_case("Y")
            || (must_login.is_empty()
                && std::env::var("MUST_LOGIN")
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("Y"));
        MUST_LOGIN.store(must_login_enabled, Ordering::SeqCst);
        log::info!(
            "MUST_LOGIN={}",
            if MUST_LOGIN.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        tokio::spawn(check_relay_servers_periodically(
            rs.relays.clone(),
            rs.relay_changed.clone(),
        ));
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(bind_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        loop {
            tokio::select! {
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        _key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        let serial = rp.serial;
                        let id = rp.id;
                        self.tcp_peers.lock().await.remove(&id);
                        self.tcp_peer_ids.lock().await.remove(&id);
                        let request_pk = self.update_addr_state(id, addr).await?;
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_peer_response(RegisterPeerResponse {
                            request_pk,
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                        if self.inner.serial > serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    let id = rk.id.clone();
                    if let Some((_, result)) = self.register_pk_state(rk, addr).await? {
                        if result == register_pk_response::Result::OK {
                            self.tcp_peers.lock().await.remove(&id);
                            self.tcp_peer_ids.lock().await.remove(&id);
                        }
                        send_rk_res(socket, addr, result).await?
                    }
                }
                Some(rendezvous_message::Union::PunchHoleRequest(_ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(_phs)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(_la)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        channel: &TcpSender,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        if bytes.is_empty() {
            return channel.send(Bytes::new()).await.is_ok();
        }
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    self.tcp_punch
                        .lock()
                        .await
                        .insert(try_into_v4(addr), channel.clone());
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    if let Err(err) = validate_relay_uuid(&rf.uuid) {
                        log::warn!(
                            "Drop RequestRelay from {addr}: {err} (length {})",
                            rf.uuid.len()
                        );
                        return false;
                    }
                    self.tcp_punch
                        .lock()
                        .await
                        .insert(try_into_v4(addr), channel.clone());
                    let target_id = rf.id.clone();
                    if self.pm.get_in_memory(&target_id).await.is_some() {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        rf.token.clear();
                        msg_out.set_request_relay(rf);
                        self.send_to_peer(&target_id, msg_out).await;
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    if let Err(err) = validate_relay_response(&rr.uuid, &rr.relay_server) {
                        log::warn!(
                            "Drop RelayResponse from {addr}: {err} (length {})",
                            rr.uuid.len()
                        );
                        return false;
                    }
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_channel(Some(channel), msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    if !tcp_register_enabled() || rp.id.is_empty() || rp.id.len() > MAX_PEER_ID_LEN {
                        return false;
                    }
                    let id = rp.id.clone();
                    if let Ok(request_pk) = self.update_addr_state(id, addr).await {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_peer_response(RegisterPeerResponse {
                            request_pk,
                            ..Default::default()
                        });
                        Self::send_to_channel(Some(channel), msg_out).await;
                        if self.inner.serial > rp.serial {
                            let mut update = RendezvousMessage::new();
                            update.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            Self::send_to_channel(Some(channel), update).await;
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if !tcp_register_enabled() {
                        let res = register_pk_response::Result::NOT_SUPPORT;
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: res.into(),
                            ..Default::default()
                        });
                        Self::send_to_channel(Some(channel), msg_out).await;
                        return false;
                    }
                    let result = match self.register_pk_state(rk, addr).await {
                        Ok(result) => result,
                        Err(err) => {
                            log::warn!("TCP peer registration failed: {}", err);
                            None
                        }
                    };
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: result
                            .as_ref()
                            .map(|(_, result)| result.clone())
                            .unwrap_or(register_pk_response::Result::UUID_MISMATCH)
                            .into(),
                        ..Default::default()
                    });
                    Self::send_to_channel(Some(channel), msg_out).await;
                    if let Some((id, register_pk_response::Result::OK)) = result {
                        self.tcp_peers.lock().await.insert(id.clone(), channel.clone());
                        self.tcp_peer_ids.lock().await.insert(id);
                    }
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    async fn register_pk_state(
        &mut self,
        rk: RegisterPk,
        addr: SocketAddr,
    ) -> ResultType<Option<(String, register_pk_response::Result)>> {
        if rk.uuid.is_empty() || rk.pk.is_empty() {
            return Ok(None);
        }
        let id = rk.id;
        let ip = addr.ip().to_string();
        if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
            return Ok(Some((id, UUID_MISMATCH)));
        }
        if !self.check_ip_blocker(&ip, &id).await {
            return Ok(Some((id, TOO_FREQUENT)));
        }
        let peer = self.pm.get_or(&id).await;
        let (changed, ip_changed) = {
            let peer = peer.read().await;
            if peer.uuid.is_empty() {
                (true, false)
            } else {
                if peer.uuid == rk.uuid {
                    if peer.info.ip != ip && peer.pk != rk.pk {
                        log::warn!(
                            "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                            id,
                            ip,
                            rk.pk,
                            peer.info.ip,
                            peer.pk,
                        );
                        return Ok(Some((id, UUID_MISMATCH)));
                    }
                } else {
                    log::warn!("Peer {} uuid mismatch: {:?} vs {:?}", id, rk.uuid, peer.uuid);
                    return Ok(Some((id, UUID_MISMATCH)));
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                    ip_changed,
                )
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if req_pk.0 > 2 {
            return Ok(Some((id, TOO_FREQUENT)));
        }
        req_pk.0 += 1;
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.clone(), 1);
                } else if let Some(v) = ips.get_mut(&ip) {
                    *v += 1;
                } else {
                    ips.insert(ip.clone(), 1);
                }
            } else {
                lock.insert(id.clone(), (Instant::now(), HashMap::from([(ip.clone(), 1)])));
            }
        }
        let result = if changed {
            self.pm.update_pk(id.clone(), peer, addr, rk.uuid, rk.pk, ip).await
        } else {
            register_pk_response::Result::OK
        };
        Ok(Some((id, result)))
    }

    #[inline]
    async fn update_addr_state(&mut self, id: String, socket_addr: SocketAddr) -> ResultType<bool> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        Ok(request_pk)
    }

    async fn send_to_peer(&self, id: &str, msg: RendezvousMessage) {
        if let Some(channel) = self.tcp_peers.lock().await.get(id).cloned() {
            let bytes = match msg.write_to_bytes() {
                Ok(bytes) => Bytes::from(bytes),
                Err(err) => {
                    log::warn!("failed to serialize message for TCP peer {}: {}", id, err);
                    return;
                }
            };
            if channel.send(bytes).await.is_ok() {
                return;
            }
            self.tcp_peers.lock().await.remove(id);
        }
        if self.tcp_peer_ids.lock().await.contains(id) {
            return;
        }
        if let Some(peer) = self.pm.get_in_memory(id).await {
            let addr = peer.read().await.socket_addr;
            self.tx.send(Data::Msg(msg.into(), addr)).ok();
        }
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<PeerTarget>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        if MUST_LOGIN.load(Ordering::SeqCst) {
            if ph.token.is_empty() {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    other_failure: "Connection failed, please login!".to_owned(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            if !jwt::SECRET.is_empty() && jwt::verify_token(&ph.token).is_err() {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    other_failure: "Token error, please log out and log back in!".to_owned(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            record_punch_req(
                try_into_v4(addr).ip().to_string(),
                try_into_v4(peer_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let tcp_channel = self.tcp_peers.lock().await.get(&id).cloned();
            let tcp_registered = tcp_channel.is_some();
            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if tcp_registered
                || ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                || (peer_is_lan ^ is_lan)
            {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !tcp_registered
                && !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    force_relay: tcp_registered,
                    ..Default::default()
                });
            }
            let target = tcp_channel
                .map(PeerTarget::Tcp)
                .or_else(|| Some(PeerTarget::Udp(peer_addr)));
            Ok((msg_out, target))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_channel(tcp.as_ref(), msg).await;
        });
    }

    #[inline]
    async fn send_to_channel(channel: Option<&TcpSender>, msg: RendezvousMessage) {
        if let Some(channel) = channel {
            if let Ok(bytes) = msg.write_to_bytes() {
                allow_err!(channel.send(Bytes::from(bytes)).await);
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_channel(sink.as_ref(), msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, target) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        match target {
            Some(PeerTarget::Tcp(channel)) => {
                Self::send_to_channel(Some(&channel), msg).await;
            }
            Some(PeerTarget::Udp(addr)) => {
                self.tx.send(Data::Msg(msg.into(), addr))?;
            }
            None => {
                self.send_to_tcp_sync(msg, addr).await?;
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, target) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        match target {
            Some(PeerTarget::Tcp(channel)) => {
                Self::send_to_channel(Some(&channel), msg).await;
            }
            Some(PeerTarget::Udp(addr)) => {
                self.tx.send(Data::Msg(msg.into(), addr))?;
            }
            None => {
                self.tx.send(Data::Msg(msg.into(), addr))?;
            }
        }
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        let relays = self.relays.read().unwrap();
        // A public relay can be reachable by clients without being reachable from this host.
        let count = if relays.available.is_empty() {
            relays.configured.len()
        } else {
            relays.available.len()
        };
        let position = match count {
            0 => return String::new(),
            1 => 0,
            _ => ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % count,
        };
        let index = relays.available.get(position).copied().unwrap_or(position);
        relays.configured[index].clone()
    }

    fn update_relay_servers(&self, input: &str) -> Result<Arc<RelayServers>, &'static str> {
        let mut servers = Vec::new();
        if input != "-" {
            for address in input.split(',') {
                validate_relay_address(address)?;
                servers.push(address.to_owned());
            }
        }
        let mut relays = self.relays.write().unwrap();
        if relays.configured.as_ref() == &servers {
            return Ok(relays.configured.clone());
        }
        let configured = relays.set(servers);
        self.relay_changed.notify_one();
        Ok(configured)
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) [<separated by ,>|-]",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "must-login(ml) [Y|N]",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                let servers = if let Some(input) = fds.next() {
                    if fds.next().is_some() {
                        return "Error: Invalid relay server list\n".to_owned();
                    }
                    match self.update_relay_servers(input) {
                        Ok(servers) => servers,
                        Err(err) => return format!("Error: {err}\n"),
                    }
                } else {
                    self.relays.read().unwrap().configured.clone()
                };
                if servers.is_empty() {
                    return "RELAY_SERVERS: default\n".to_owned();
                }
                for ip in servers.iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(value) = fds.next() {
                    if value.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("must-login" | "ml") => {
                if let Some(value) = fds.next() {
                    MUST_LOGIN.store(value.eq_ignore_ascii_case("Y"), Ordering::SeqCst);
                } else {
                    let _ = writeln!(
                        res,
                        "MUST_LOGIN: {:?}",
                        MUST_LOGIN.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// Handles loopback console requests and external NAT or online-status queries.
    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let Some(command) = read_console_command(&mut stream).await else {
                    return;
                };
                let reply = match command {
                    Ok(command) => rs.check_cmd(&command).await,
                    Err(error) => format!("Error: {error}\n"),
                };
                if let Err(err) = timeout(1000, stream.write_all(reply.as_bytes()))
                    .await
                    .unwrap_or_else(|elapsed| Err(elapsed.into()))
                {
                    log::warn!("Failed to send the console reply: {err}");
                }
            });
            return;
        }
        let mut stream = FramedStream::from(stream, addr);
        stream.codec_mut().set_max_packet_length(*MAX_MESSAGE);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    /// Processes rendezvous messages on an accepted TCP or WebSocket connection.
    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let callback = |req: &Request, response: Response| {
                let headers = req.headers();
                // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
                // client IP is preserved when the WebSocket port runs behind a
                // reverse proxy (WSS). They are NOT validated: anyone who can reach
                // this port directly can spoof an arbitrary IP, bypassing IP-based
                // rate limiting / blocking and corrupting logged IPs. Do not expose
                // the WebSocket port directly to untrusted networks; only the
                // reverse proxy, which overwrites these headers, should be able to
                // connect to it.
                // https://github.com/rustdesk/rustdesk-server/issues/634
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok());
                if let Some(ip) = real_ip {
                    if let Ok(ip) = ip.parse() {
                        addr = SocketAddr::new(ip, addr.port());
                    }
                }
                Ok(response)
            };
            let ws_config = tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(*MAX_MESSAGE))
                .max_frame_size(Some((*MAX_MESSAGE).min(WS_DEFAULT_MAX_FRAME_SIZE)))
                .read_buffer_size(WS_BUFFER_SIZE)
                .write_buffer_size(WS_BUFFER_SIZE);
            let ws_stream = timeout(
                30_000,
                tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config)),
            )
            .await??;
            let (a, mut b) = ws_stream.split();
            let (channel, mut outbound) = mpsc::channel::<Bytes>(64);
            let writer = tokio::spawn(async move {
                let mut sink = a;
                while let Some(bytes) = outbound.recv().await {
                    if sink
                        .send(tungstenite::Message::Binary(bytes))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            while let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await {
                if let tungstenite::Message::Binary(bytes) = msg {
                    if !self.handle_tcp(&bytes, &channel, addr, key, ws).await {
                        break;
                    }
                }
            }
            self.remove_tcp_channel(addr, &channel).await;
            drop(channel);
            let _ = writer.await;
        } else {
            let mut framed = Framed::new(stream, BytesCodec::new());
            framed.codec_mut().set_max_packet_length(*MAX_MESSAGE);
            let (a, mut b) = framed.split();
            let (channel, mut outbound) = mpsc::channel::<Bytes>(64);
            let writer = tokio::spawn(async move {
                let mut sink = a;
                while let Some(bytes) = outbound.recv().await {
                    if sink.send(bytes).await.is_err() {
                        break;
                    }
                }
            });
            while let Ok(Some(Ok(bytes))) = timeout(30_000, b.next()).await {
                if !self.handle_tcp(&bytes, &channel, addr, key, ws).await {
                    break;
                }
            }
            self.remove_tcp_channel(addr, &channel).await;
            drop(channel);
            let _ = writer.await;
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    async fn remove_tcp_channel(&self, addr: SocketAddr, channel: &TcpSender) {
        let addr = try_into_v4(addr);
        let mut tcp_punch = self.tcp_punch.lock().await;
        if tcp_punch
            .get(&addr)
            .is_some_and(|current| current.same_channel(channel))
        {
            tcp_punch.remove(&addr);
        }
        drop(tcp_punch);
        self.tcp_peers
            .lock()
            .await
            .retain(|_, current| !current.same_channel(channel));
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

#[derive(Clone, Copy)]
enum RelayProbe {
    Reachable(SocketAddr),
    Failed,
    Unresolved,
    Deferred,
}

type RelayDns = HashMap<String, (tokio::time::Instant, watch::Receiver<Vec<SocketAddr>>)>;

enum RelayEndpoint {
    Socket(SocketAddr),
    Host(String, u16),
}

async fn check_relay_servers_periodically(relays: Arc<RwLock<RelayState>>, changed: Arc<Notify>) {
    let mut timer = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let pending_dns = Arc::new(StdMutex::new(RelayDns::new()));
    let mut first = 0;
    let mut last_configured = None;
    loop {
        tokio::select! {
            _ = timer.tick() => {},
            _ = changed.notified() => {},
        }
        'snapshot: loop {
            let (configured, health) = {
                let relays = relays.read().unwrap();
                (relays.configured.clone(), relays.health.clone())
            };
            if !last_configured
                .as_ref()
                .is_some_and(|last| Arc::ptr_eq(last, &configured))
            {
                first = 0;
                last_configured = Some(configured.clone());
            }
            if configured.is_empty() {
                break;
            }
            let probes = check_relay_servers(
                &configured,
                &relays,
                &health,
                pending_dns.clone(),
                first,
            );
            tokio::pin!(probes);
            let count = configured.len();
            let mut deferred_offset = count;
            loop {
                let checked = tokio::select! {
                    biased;
                    _ = changed.notified() => {
                        if !Arc::ptr_eq(&relays.read().unwrap().configured, &configured) {
                            continue 'snapshot;
                        }
                        continue;
                    },
                    checked = probes.next() => checked,
                };
                let Some((indices, probe)) = checked else {
                    break;
                };
                if matches!(probe, RelayProbe::Deferred) {
                    if let Some(index) = indices.first() {
                        deferred_offset = deferred_offset.min((index + count - first) % count);
                    }
                    continue;
                }
                let mut relays = relays.write().unwrap();
                if Arc::ptr_eq(&relays.configured, &configured) {
                    for index in indices {
                        relays.record_probe(index, probe);
                    }
                }
            }
            first = if deferred_offset == count {
                0
            } else {
                (first + deferred_offset) % count
            };
            break;
        }
    }
}

fn relay_probe_endpoint(address: &str) -> String {
    let address = if address.contains(':') {
        address.to_ascii_lowercase()
    } else {
        format!("{}:{}", address.to_ascii_lowercase(), config::RELAY_PORT)
    };
    address
        .parse::<SocketAddr>()
        .map_or(address, |socket| socket.to_string())
}

fn check_relay_servers<'a>(
    configured: &'a Arc<RelayServers>,
    relays: &'a RwLock<RelayState>,
    health: &'a [RelayHealth],
    pending_dns: Arc<StdMutex<RelayDns>>,
    first: usize,
) -> impl hbb_common::futures_util::Stream<Item = (Vec<usize>, RelayProbe)> + 'a {
    use std::net::ToSocketAddrs;

    let mut grouped: Vec<(String, Vec<usize>)> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    for offset in 0..configured.len() {
        let index = (first + offset) % configured.len();
        let endpoint = relay_probe_endpoint(&configured[index]);
        let position = *positions.entry(endpoint.clone()).or_insert(grouped.len());
        if let Some((_, indices)) = grouped.get_mut(position) {
            indices.push(index);
        } else {
            grouped.push((endpoint, vec![index]));
        }
    }
    // Give each name a probe slot before assigning more slots to its other ports.
    let mut ports_per_name = HashMap::<String, usize>::new();
    let mut groups: Vec<_> = grouped
        .into_iter()
        .filter_map(|(host, indices)| {
            if let Ok(socket) = host.parse() {
                Some((0, RelayEndpoint::Socket(socket), indices))
            } else {
                let (name, port) = host.rsplit_once(':')?;
                let port = port.parse().ok()?;
                let count = ports_per_name.entry(name.to_owned()).or_default();
                *count += 1;
                Some((
                    *count - 1,
                    RelayEndpoint::Host(name.to_owned(), port),
                    indices,
                ))
            }
        })
        .collect();
    groups.sort_by_key(|(rank, _, _)| *rank);
    let batch_dns = Arc::new(StdMutex::new(RelayDns::new()));
    stream::iter(groups)
        .map(move |(_, endpoint, indices)| {
            let health = health[indices[0]];
            let preferred = health
                .last_reply
                .filter(|reply| reply.failures <= 1)
                .map(|reply| reply.socket);
            let batch_dns = batch_dns.clone();
            let pending_dns = pending_dns.clone();
            async move {
                let deadline =
                    tokio::time::Instant::now() + Duration::from_millis(CHECK_RELAY_TIMEOUT);
                let mut candidates = match endpoint {
                    RelayEndpoint::Socket(socket) => vec![socket],
                    RelayEndpoint::Host(name, port) => {
                        let (dns_deadline, mut result) = {
                            // Only the active configuration can reserve a DNS slot.
                            let current = relays.read().unwrap();
                            if !Arc::ptr_eq(&current.configured, configured) {
                                return (indices, RelayProbe::Deferred);
                            }
                            let mut batch = batch_dns.lock().unwrap();
                            if let Some(lookup) = batch.get(&name) {
                                lookup.clone()
                            } else {
                                let mut pending = pending_dns.lock().unwrap();
                                let lookup = if let Some(lookup) = pending.get(&name) {
                                    // Configuration changes reuse the original DNS deadline.
                                    lookup.clone()
                                } else {
                                    if pending.len() >= CHECK_RELAY_CONCURRENCY {
                                        return (indices, RelayProbe::Deferred);
                                    }
                                    let (send, result) = watch::channel(Vec::new());
                                    let lookup = (deadline, result);
                                    pending.insert(name.clone(), lookup.clone());
                                    let worker_name = name.clone();
                                    let pending_dns = pending_dns.clone();
                                    tokio::task::spawn_blocking(move || {
                                        let mut addresses = (worker_name.as_str(), 0)
                                            .to_socket_addrs()
                                            .map(|addresses| addresses.collect::<Vec<_>>())
                                            .unwrap_or_default();
                                        addresses.sort_unstable();
                                        addresses.dedup();
                                        let _ = send.send(addresses);
                                        pending_dns.lock().unwrap().remove(&worker_name);
                                    });
                                    lookup
                                };
                                batch.insert(name, lookup.clone());
                                lookup
                            }
                        };
                        if !matches!(
                            tokio::time::timeout_at(dns_deadline, result.changed()).await,
                            Ok(Ok(()))
                        ) {
                            return (indices, RelayProbe::Unresolved);
                        }
                        let mut addresses = result.borrow().clone();
                        for address in &mut addresses {
                            address.set_port(port);
                        }
                        addresses
                    }
                };
                if !candidates.is_empty() {
                    let offset = health.next_candidate % candidates.len();
                    candidates.rotate_left(offset);
                }
                // Prefer the last responder until repeated failures require rotating again.
                if let Some(position) = candidates
                    .iter()
                    .position(|&socket| Some(socket) == preferred)
                {
                    candidates[..=position].rotate_right(1);
                }
                let probe = connect_relay_candidates(candidates, deadline).await;
                (indices, probe)
            }
        })
        .buffer_unordered(CHECK_RELAY_CONCURRENCY)
}

async fn connect_relay_candidates(
    candidates: Vec<SocketAddr>,
    deadline: tokio::time::Instant,
) -> RelayProbe {
    let count = candidates.len();
    let waves = candidates
        .len()
        .saturating_sub(1)
        .div_ceil(RELAY_CANDIDATE_CONCURRENCY - 1);
    let mut candidates = candidates.into_iter().enumerate();
    let mut pending = FuturesUnordered::new();
    let mut active: VecDeque<(usize, tokio::time::Instant, AbortHandle)> = VecDeque::new();
    let attempt_delay = |now, waiting: usize| {
        RELAY_CANDIDATE_DELAY.min(deadline.saturating_duration_since(now) / (waiting as u32 + 1))
    };
    let now = tokio::time::Instant::now();
    let slot_budget = deadline.saturating_duration_since(now) / (waves as u32 + 1);
    let mut next_attempt = now;
    while candidates.len() > 0 || !pending.is_empty() {
        let oldest = active
            .iter()
            .find(|(index, _, _)| *index != 0)
            .filter(|_| active.len() == RELAY_CANDIDATE_CONCURRENCY);
        let next = oldest.map_or(next_attempt, |(_, started, _)| next_attempt.max(*started + slot_budget));
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => break,
            Some((index, socket, result)) = pending.next(), if !pending.is_empty() => {
                if matches!(result, Ok(Ok(_))) {
                    return RelayProbe::Reachable(socket);
                }
                active.retain(|(active_index, _, _)| *active_index != index);
                if pending.is_empty() {
                    next_attempt = tokio::time::Instant::now();
                }
            },
            _ = tokio::time::sleep_until(next), if candidates.len() > 0 => {
                if let Some((_, _, abort)) = oldest {
                    // Give the first candidate the full budget and rotate the remaining slots when busy.
                    abort.abort();
                } else if let Some((index, candidate)) = candidates.next() {
                    let now = tokio::time::Instant::now();
                    let (abort, registration) = AbortHandle::new_pair();
                    active.push_back((index, now, abort));
                    pending.push(async move {
                        let result = Abortable::new(TcpStream::connect(candidate), registration).await;
                        (index, candidate, result)
                    });
                    next_attempt = now + attempt_delay(now, candidates.len());
                }
            },
        }
    }
    if candidates.len() < count {
        RelayProbe::Failed
    } else {
        RelayProbe::Unresolved
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_message_kb_falls_back_to_default_and_is_capped() {
        assert_eq!(max_message_kb(""), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("0"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("abc"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("256"), 256);
        assert_eq!(max_message_kb(&usize::MAX.to_string()), MAX_MESSAGE_KB_CAP);
    }

    #[test]
    fn default_message_bound_holds_an_online_query_for_5000_ids() {
        let mut msg = RendezvousMessage::new();
        msg.set_online_request(OnlineRequest {
            id: "1234567890".to_owned(),
            peers: (0..5000).map(|i| format!("{i:010}")).collect(),
            ..Default::default()
        });
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len <= DEFAULT_MAX_MESSAGE_KB << 10, "{len}");
    }

    #[test]
    fn relay_uuid_validation() {
        let uuid = "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12";
        assert_eq!(validate_relay_response(uuid, "relay.example"), Ok(()));
        assert_eq!(validate_relay_response("", ""), Ok(()));
        let max_len = "a".repeat(128);
        for value in [
            uuid,
            "E4C181D0-41C7-4AE6-8EF0-36581B6B2B12",
            "e4c181d041c74ae68ef036581b6b2b12",
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "a_b-c",
            max_len.as_str(),
        ] {
            assert_eq!(validate_relay_uuid(value), Ok(()), "rejected {value:?}");
        }
        let too_long = "a".repeat(129);
        for value in [
            "",
            "\r\nPING\r\n",
            "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12\n",
            "e4c181d0 41c7",
            "{e4c181d0-41c7-4ae6-8ef0-36581b6b2b12}",
            "e4c181d0\0",
            "é",
            too_long.as_str(),
        ] {
            assert!(validate_relay_uuid(value).is_err(), "accepted {value:?}");
            assert!(validate_relay_response(value, "relay.example").is_err());
        }
    }

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // one request at least, so MAX_PUNCH_REQUESTS=0 is exercised too
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // the oldest half is evicted and the newest kept
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }
}
