//! Direct Link (v1.7 ticket 03, ADRs 0001, 0004, 0005).
//!
//! Connecting to a name or IP dials the Target's own address first. No answer in about a second
//! means the Target's Tailscale address, if one is known; neither answering is the plain
//! [`NOT_ON_THIS_NETWORK`]. There is no ID / rendezvous / relay path at all.

use crate::message_proto::{message, Message, PublicKey};
use hbb_common::{
    anyhow::anyhow,
    bail,
    config::LocalConfig,
    protobuf::Message as _,
    rendezvous_proto::IdPk,
    serde_json,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{kx_version_for, KxTranscript},
    ResultType, Stream,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, future::Future, net::IpAddr, net::SocketAddr};

// What the connect box says, in plain words with one next step (boring/rebrand.py keeps the same
// text as translation keys). The Mac build says "Mac"; the Windows build says "computer".

/// Neither the Direct Link nor the Tailscale address answered.
#[cfg(not(target_os = "windows"))]
pub const NOT_ON_THIS_NETWORK: &str =
    "Couldn't reach that Mac. Check that it's turned on and on the same Wi-Fi or network as this one, then try again.";
#[cfg(target_os = "windows")]
pub const NOT_ON_THIS_NETWORK: &str =
    "Couldn't reach that computer. Check that it's turned on and on the same Wi-Fi or network as this one, then try again.";

/// A name that resolves to nothing a Target would accept.
#[cfg(not(target_os = "windows"))]
pub const NOT_FOUND: &str = "Couldn't find a Mac with that name. Pick it from the list, or check the spelling and try again.";
#[cfg(target_os = "windows")]
pub const NOT_FOUND: &str =
    "Couldn't find a computer with that name. Pick it from the list, or check the spelling and try again.";

/// A non-Tailscale Target that answers without the encrypted Direct Link handshake (ADR 0005).
#[cfg(not(target_os = "windows"))]
pub const PLAINTEXT_REFUSED: &str = "That Mac needs the latest Boring Remote. Update it on that Mac, then try again.";
#[cfg(target_os = "windows")]
pub const PLAINTEXT_REFUSED: &str =
    "That computer needs the latest Boring Remote. Update it on that computer, then try again.";

/// The Target's identity key differs from the one pinned for that address or ID.
#[cfg(not(target_os = "windows"))]
pub const IDENTITY_CHANGED: &str = "This isn't the Mac you connected to before, so Boring Remote stopped. If it was reinstalled, open Settings, click Trusted Controllers, click Forget next to it, then try again.";
#[cfg(target_os = "windows")]
pub const IDENTITY_CHANGED: &str = "This isn't the computer you connected to before, so Boring Remote stopped. If it was reinstalled, open Settings, click Trusted Controllers, click Forget next to it, then try again.";

/// Controller-side memory of Targets met over an encrypted Direct Link (LocalConfig option).
pub const KNOWN_OPTION: &str = "boring-direct-link-known";

/// How long the Target's own (non-Tailscale) address gets to answer (TCP connect) before the
/// Tailscale path is tried.
pub const DIRECT_TIMEOUT_MS: u64 = 1_000;

/// Each read of the encrypted handshake and trust exchange, once a Target has answered.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

/// Tailscale's ranges: IPv4 CGNAT 100.64.0.0/10 and the IPv6 ULA fd7a:115c:a1e0::/48.
pub fn is_tailscale(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64,
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// ADR 0005: everything but Tailscale (already WireGuard) must carry an encrypted session.
/// Both ends apply this to the other's address, so they agree on whether to key the stream.
pub fn must_encrypt(ip: IpAddr) -> bool {
    !is_tailscale(ip)
}

/// Which way a session reached the Target; Flutter's Link Badge reads [`Path::stream_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Straight to the Target on the same network.
    Local,
    /// Over Tailscale.
    ViaInternet,
}

impl Path {
    pub fn of(addr: SocketAddr) -> Self {
        if is_tailscale(addr.ip()) {
            Path::ViaInternet
        } else {
            Path::Local
        }
    }

    /// The session's `stream_type`, as the `connection_ready` event hands it to Flutter.
    pub fn stream_type(self) -> &'static str {
        match self {
            Path::Local => "Local",
            Path::ViaInternet => "Tailscale",
        }
    }
}

/// Where to dial: the Target's own address, then its Tailscale address if one is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub direct: SocketAddr,
    pub tailscale: Option<SocketAddr>,
}

/// Why one dial didn't give a session.
#[derive(Debug)]
pub enum Failure {
    /// Nothing answered, or nothing we could talk to: try the next address.
    Unreachable,
    /// Something answered and was refused (plaintext, a changed identity). Final: falling back
    /// would only route around the refusal.
    Refused(hbb_common::anyhow::Error),
}

/// Dial `plan.direct`, then `plan.tailscale` if the first gave nothing. "Nothing" means TCP didn't
/// answer within `direct_ms` (a non-Tailscale address) or `slow_ms` (Tailscale: its first packets
/// may go through a DERP relay), or the handshake found nothing it could talk to. A Target that
/// answered gets the handshake's own timeouts, not the no-answer budget. A [`Failure::Refused`]
/// ends the attempt; the fallback is never contacted.
pub async fn race<S, T, C, CFut, H, HFut>(
    plan: Plan,
    direct_ms: u64,
    slow_ms: u64,
    mut connect: C,
    mut handshake: H,
) -> ResultType<(T, SocketAddr)>
where
    C: FnMut(SocketAddr) -> CFut,
    CFut: Future<Output = Option<S>>,
    H: FnMut(S, SocketAddr) -> HFut,
    HFut: Future<Output = Result<T, Failure>>,
{
    let tailscale = plan.tailscale.filter(|t| *t != plan.direct);
    for addr in std::iter::once(plan.direct).chain(tailscale) {
        let ms = if is_tailscale(addr.ip()) { slow_ms } else { direct_ms };
        let Ok(Some(s)) = hbb_common::timeout(ms, connect(addr)).await else {
            continue;
        };
        match handshake(s, addr).await {
            Ok(t) => return Ok((t, addr)),
            Err(Failure::Refused(e)) => return Err(e),
            Err(Failure::Unreachable) => {}
        }
    }
    bail!(NOT_ON_THIS_NETWORK)
}

/// The Target's first Direct Link message (ADR 0005), sent only where [`must_encrypt`]: its
/// identity key, so the Controller can pin it and check the signed handshake that follows
/// (`identity_handshake` in src/server.rs), plus its Tailscale address if it has one, so the
/// Controller can fall back to it later. Rides `PublicKey` (no proto change): the identity key in
/// `asymmetric_value`, the Tailscale address as text in `symmetric_value`.
pub async fn announce(stream: &mut Stream, sign_pk: &[u8], tailscale: Option<IpAddr>) -> ResultType<()> {
    if sign_pk.len() != sign::PUBLICKEYBYTES {
        bail!("no identity key to announce");
    }
    let mut msg = Message::new();
    msg.set_public_key(PublicKey {
        asymmetric_value: sign_pk.to_vec().into(),
        symmetric_value: tailscale.map(|t| t.to_string()).unwrap_or_default().into_bytes().into(),
        ..Default::default()
    });
    stream.send(&msg).await
}

/// Target side, after the handshake: a Direct Link on a non-Tailscale address that did not end
/// keyed is dropped before anything else is read from it.
pub fn require_encrypted(peer: IpAddr, stream: &Stream) -> ResultType<()> {
    if must_encrypt(peer) && !stream.is_secured() {
        bail!("plaintext Direct Link from {} refused (ADR 0005)", peer);
    }
    Ok(())
}

/// Who answered a Direct Link handshake, verified against its own identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub id: String,
    pub sign_pk: Vec<u8>,
    pub tailscale: Option<IpAddr>,
}

async fn read(stream: &mut Stream, ms: u64) -> Result<Message, Failure> {
    match hbb_common::timeout(ms, stream.next()).await {
        Ok(Some(Ok(bytes))) => {
            Message::parse_from_bytes(&bytes).map_err(|_| Failure::Refused(anyhow!(PLAINTEXT_REFUSED)))
        }
        _ => Err(Failure::Unreachable),
    }
}

/// Controller side of the encrypted Direct Link: read the Target's [`announce`], refuse a
/// changed identity, verify its signed ephemeral key, seal a fresh session key to it and key
/// `stream`. Anything but that exact exchange is refused; there is no plaintext fallback.
///
/// Ticket 04 seam: the returned [`Verified`] (pinned id + key) is who a trust token belongs to,
/// and the stream is already encrypted when the login carrying it goes out.
pub async fn secure(stream: &mut Stream, known: &Known, dialled: SocketAddr, ms: u64) -> Result<Verified, Failure> {
    let refused = |why: &str| Failure::Refused(anyhow!("{}", why));
    let (sign_pk, tailscale) = match read(stream, ms).await?.union {
        Some(message::Union::PublicKey(pk)) if pk.asymmetric_value.len() == sign::PUBLICKEYBYTES => {
            let ts = String::from_utf8_lossy(&pk.symmetric_value).parse::<IpAddr>().ok();
            (pk.asymmetric_value.to_vec(), ts.filter(|ip| is_tailscale(*ip)))
        }
        _ => return Err(refused(PLAINTEXT_REFUSED)),
    };
    let si = match read(stream, ms).await?.union {
        Some(message::Union::SignedId(si)) => si,
        _ => return Err(refused(PLAINTEXT_REFUSED)),
    };
    let mut key = [0u8; sign::PUBLICKEYBYTES];
    key.copy_from_slice(&sign_pk);
    let id_pk = sign::verify(&si.id, &sign::PublicKey(key))
        .ok()
        .and_then(|b| IdPk::parse_from_bytes(&b).ok())
        .filter(|p| p.pk.len() == box_::PUBLICKEYBYTES && !p.id.is_empty())
        .ok_or_else(|| refused(PLAINTEXT_REFUSED))?;
    if !known.pin_ok(dialled, &id_pk.id, &sign_pk) {
        return Err(refused(IDENTITY_CHANGED));
    }
    let mut their = [0u8; box_::PUBLICKEYBYTES];
    their.copy_from_slice(&id_pk.pk);
    let (our_pk, our_sk) = box_::gen_keypair();
    let session = secretbox::gen_key();
    let sealed = box_::seal(&session.0, &box_::Nonce([0u8; box_::NONCEBYTES]), &box_::PublicKey(their), &our_sk);
    let picked = kx_version_for(id_pk.kx_version);
    let mut msg = Message::new();
    msg.set_public_key(PublicKey {
        asymmetric_value: our_pk.0.to_vec().into(),
        symmetric_value: sealed.into(),
        kx_version: picked,
        ..Default::default()
    });
    stream.send(&msg).await.map_err(|_| Failure::Unreachable)?;
    let t = KxTranscript {
        initiator_pk: &our_pk.0,
        responder_pk: &their,
        advertised: id_pk.kx_version,
        picked,
    };
    stream.set_negotiated_key(session, true, &t).map_err(Failure::Refused)?;
    Ok(Verified { id: id_pk.id, sign_pk, tailscale })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct KnownTarget {
    /// Identity key, hex.
    pk: String,
    #[serde(default)]
    lan: String,
    #[serde(default)]
    tailscale: String,
}

/// Targets this Controller has met over an encrypted Direct Link, by Target ID: the pinned
/// identity key (trust on first use), the address it answered on and its Tailscale address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Known(HashMap<String, KnownTarget>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

impl Known {
    pub fn parse(json: &str) -> Self {
        Known(crate::trust::parse_or_default(json, "known Targets"))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_default()
    }

    pub fn load() -> Self {
        Self::parse(&LocalConfig::get_option(KNOWN_OPTION))
    }

    pub fn save(&self) {
        LocalConfig::set_option(KNOWN_OPTION.to_owned(), self.to_json());
    }

    /// Trust on first use, pinned twice: the address we dialled keeps the Target first met there
    /// (its ID and key), and a known ID keeps its key wherever it answers. The ID alone proves
    /// nothing (it is signed by the key that just announced itself), so a new ID with its own key
    /// at a known address is a changed identity too.
    pub fn pin_ok(&self, dialled: SocketAddr, id: &str, sign_pk: &[u8]) -> bool {
        let lan = dialled.to_string();
        let pk = hex(sign_pk);
        let at_address = self.0.iter().all(|(known_id, t)| t.lan != lan || (known_id == id && t.pk == pk));
        at_address && self.0.get(id).map_or(true, |t| t.pk == pk)
    }

    /// Remember who answered at `addr`, after [`Known::pin_ok`] let it in.
    pub fn record(&mut self, who: &Verified, addr: SocketAddr) {
        let lan = addr.to_string();
        let t = self.0.entry(who.id.clone()).or_default();
        t.pk = hex(&who.sign_pk);
        t.lan = lan;
        if let Some(ts) = who.tailscale {
            t.tailscale = SocketAddr::new(ts, addr.port()).to_string();
        }
    }

    /// The Tailscale address of whoever last answered at `direct`, if it told us one.
    pub fn tailscale_for(&self, direct: SocketAddr) -> Option<SocketAddr> {
        let lan = direct.to_string();
        self.0
            .values()
            .find(|t| t.lan == lan)
            .and_then(|t| t.tailscale.parse().ok())
    }
}

/// The address a name or IP resolves to, and its Tailscale fallback. Only addresses a Target
/// accepts (Tailscale and private LAN, `lan::is_allowed`) are dialled; a name that resolves to
/// anything else, or nothing, is [`NOT_FOUND`]. Never an ID: there is no rendezvous server.
pub async fn plan_for(peer: &str, known: &Known, ms: u64) -> ResultType<Plan> {
    let host = hbb_common::socket_client::check_port(peer, hbb_common::config::RELAY_PORT + 1);
    let addrs: Vec<SocketAddr> = match hbb_common::timeout(ms, hbb_common::tokio::net::lookup_host(host)).await {
        Ok(Ok(addrs)) => addrs.map(hbb_common::try_into_v4).collect(),
        _ => bail!(NOT_FOUND),
    };
    if addrs.is_empty() || !addrs.iter().all(|a| crate::lan::is_allowed(a.ip())) {
        bail!(NOT_FOUND);
    }
    // Same network first: a non-Tailscale address, IPv4 before IPv6.
    let mut sorted = addrs;
    sorted.sort_by_key(|a| (is_tailscale(a.ip()), !a.is_ipv4()));
    let direct = sorted[0];
    let tailscale = known
        .tailscale_for(direct)
        .or_else(|| sorted.iter().copied().find(|a| is_tailscale(a.ip())))
        .filter(|t| *t != direct);
    Ok(Plan { direct, tailscale })
}

/// The connect box (src/client.rs `_start`): Direct Link first, then Tailscale, else
/// [`NOT_ON_THIS_NETWORK`]. Non-Tailscale sessions come back encrypted or not at all. Returns the
/// stream, the path it took and the Target's identity key (the session fingerprint) when known.
pub async fn connect(peer: &str, slow_ms: u64) -> ResultType<(Stream, Path, Option<Vec<u8>>)> {
    let mut known = Known::load();
    let plan = plan_for(peer, &known, slow_ms).await?;
    let ((stream, who), addr) = race(
        plan,
        DIRECT_TIMEOUT_MS,
        slow_ms,
        |addr| async move { hbb_common::socket_client::connect_tcp_local(addr, None, slow_ms).await.ok() },
        |stream, addr| handshake(stream, addr, &known, HANDSHAKE_TIMEOUT_MS),
    )
    .await?;
    let pk = who.map(|w| {
        known.record(&w, addr);
        known.save();
        w.sign_pk
    });
    Ok((stream, Path::of(addr), pk))
}

/// A Target that picked up at `addr`: the encrypted handshake wherever [`must_encrypt`], then
/// the trust token. Each read gets `ms`.
pub async fn handshake(
    mut stream: Stream,
    addr: SocketAddr,
    known: &Known,
    ms: u64,
) -> Result<(Stream, Option<Verified>), Failure> {
    if !must_encrypt(addr.ip()) {
        return Ok((stream, None));
    }
    let who = secure(&mut stream, known, addr, ms).await?;
    if !stream.is_secured() {
        return Err(Failure::Refused(anyhow!(PLAINTEXT_REFUSED)));
    }
    // v1.7 t04: present this Target's trust token (if any) inside the encrypted stream.
    crate::trust::present_for(&mut stream, &who.id, ms).await.map_err(|e| {
        log::warn!("trust exchange with {} failed: {}", addr, e);
        Failure::Refused(anyhow!(PLAINTEXT_REFUSED))
    })?;
    Ok((stream, Some(who)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    const LAN: &str = "192.168.1.20:21118";
    const TS: &str = "100.101.102.103:21118";

    /// TCP that answers per address: Some(delay) = connects after delay, None = refused
    /// connection (unreachable). Records every address it was asked for.
    fn dialer(
        answers: Vec<(&'static str, Option<u64>)>,
        seen: Arc<Mutex<Vec<SocketAddr>>>,
    ) -> impl FnMut(SocketAddr) -> std::pin::Pin<Box<dyn Future<Output = Option<SocketAddr>>>> {
        move |addr| {
            seen.lock().unwrap().push(addr);
            let answer = answers.iter().find(|(a, _)| sa(a) == addr).and_then(|(_, d)| *d);
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(answer?)).await;
                Some(addr)
            })
        }
    }

    /// A handshake that takes `ms` once TCP is up.
    fn handshake(ms: u64) -> impl FnMut(SocketAddr, SocketAddr) -> std::pin::Pin<Box<dyn Future<Output = Result<SocketAddr, Failure>>>> {
        move |s, _| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Ok(s)
            })
        }
    }

    #[tokio::test]
    async fn direct_timeout_falls_back_to_tailscale() {
        let seen = Arc::new(Mutex::new(vec![]));
        let plan = Plan { direct: sa(LAN), tailscale: Some(sa(TS)) };
        let (got, addr) =
            race(plan, 50, 500, dialer(vec![(LAN, Some(5_000)), (TS, Some(1))], seen.clone()), handshake(0))
                .await
                .unwrap();
        assert_eq!((got, addr), (sa(TS), sa(TS)));
        assert_eq!(Path::of(addr), Path::ViaInternet);
        assert_eq!(*seen.lock().unwrap(), vec![sa(LAN), sa(TS)]);
    }

    #[tokio::test]
    async fn direct_success_never_contacts_the_fallback() {
        let seen = Arc::new(Mutex::new(vec![]));
        let plan = Plan { direct: sa(LAN), tailscale: Some(sa(TS)) };
        let (_, addr) =
            race(plan, 50, 500, dialer(vec![(LAN, Some(1)), (TS, Some(1))], seen.clone()), handshake(0))
                .await
                .unwrap();
        assert_eq!(Path::of(addr), Path::Local);
        assert_eq!(*seen.lock().unwrap(), vec![sa(LAN)]);
    }

    #[tokio::test]
    async fn a_target_that_answers_in_time_but_handshakes_slowly_stays_local() {
        // The ~1 s is for "no answer". A Target that picked up gets the handshake's own budget.
        let seen = Arc::new(Mutex::new(vec![]));
        let plan = Plan { direct: sa(LAN), tailscale: Some(sa(TS)) };
        let (_, addr) =
            race(plan, 50, 500, dialer(vec![(LAN, Some(1)), (TS, Some(1))], seen.clone()), handshake(200))
                .await
                .unwrap();
        assert_eq!(Path::of(addr), Path::Local);
        assert_eq!(*seen.lock().unwrap(), vec![sa(LAN)]);
    }

    #[tokio::test]
    async fn nothing_answers_is_not_on_this_network() {
        let seen = Arc::new(Mutex::new(vec![]));
        let plan = Plan { direct: sa(LAN), tailscale: Some(sa(TS)) };
        let err = race(plan, 50, 50, dialer(vec![(LAN, None), (TS, Some(5_000))], seen), handshake(0))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), NOT_ON_THIS_NETWORK);
        let plan = Plan { direct: sa(LAN), tailscale: None };
        let err = race(plan, 50, 50, dialer(vec![], Default::default()), handshake(0)).await.unwrap_err();
        assert_eq!(err.to_string(), NOT_ON_THIS_NETWORK);
    }

    #[tokio::test]
    async fn a_refused_direct_link_never_falls_back() {
        let seen = Arc::new(Mutex::new(vec![]));
        let plan = Plan { direct: sa(LAN), tailscale: Some(sa(TS)) };
        let err = race(plan, 50, 500, dialer(vec![(LAN, Some(1)), (TS, Some(1))], seen.clone()), |_, _| async {
            Err::<(), _>(Failure::Refused(hbb_common::anyhow::anyhow!("plaintext")))
        })
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "plaintext");
        assert_eq!(*seen.lock().unwrap(), vec![sa(LAN)]);
    }

    #[tokio::test]
    async fn a_typed_tailscale_address_gets_the_slow_timeout() {
        let plan = Plan { direct: sa(TS), tailscale: None };
        let (_, addr) = race(plan, 10, 500, dialer(vec![(TS, Some(100))], Default::default()), handshake(0))
            .await
            .unwrap();
        assert_eq!(Path::of(addr), Path::ViaInternet);
    }

    #[test]
    fn plaintext_is_allowed_only_on_tailscale() {
        for s in ["192.168.1.20", "10.0.0.5", "172.16.0.1", "fe80::1", "fd12::1", "127.0.0.1"] {
            assert!(must_encrypt(s.parse().unwrap()), "{}", s);
        }
        for s in ["100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1", "::ffff:100.100.1.1"] {
            assert!(!must_encrypt(s.parse().unwrap()), "{}", s);
        }
        assert!(must_encrypt("100.128.0.1".parse().unwrap()));
    }

    // --- the encrypted handshake, over loopback (127.0.0.1 is not Tailscale: must encrypt) ---

    use hbb_common::tcp::KX_VERSION_LATEST;

    /// A Target that speaks the Direct Link the way src/server.rs does: announce, then
    /// identity_handshake's SignedId, then key the stream from the Controller's reply.
    async fn target(mut s: Stream, sk: sign::SecretKey, pk: sign::PublicKey, id: &str) -> Stream {
        announce(&mut s, &pk.0, Some("100.101.102.103".parse().unwrap())).await.unwrap();
        let (our_pk, our_sk) = box_::gen_keypair();
        let mut m = Message::new();
        m.set_signed_id(crate::message_proto::SignedId {
            id: sign::sign(
                &IdPk { id: id.into(), pk: our_pk.0.to_vec().into(), kx_version: KX_VERSION_LATEST, ..Default::default() }
                    .write_to_bytes()
                    .unwrap(),
                &sk,
            )
            .into(),
            ..Default::default()
        });
        s.send(&m).await.unwrap();
        let reply = Message::parse_from_bytes(&s.next().await.unwrap().unwrap()).unwrap();
        let Some(message::Union::PublicKey(r)) = reply.union else { panic!("no key") };
        let key = hbb_common::tcp::Encrypt::decode(&r.symmetric_value, &r.asymmetric_value, &our_sk).unwrap();
        s.set_negotiated_key(
            key,
            false,
            &KxTranscript { initiator_pk: &r.asymmetric_value, responder_pk: &our_pk.0, advertised: KX_VERSION_LATEST, picked: r.kx_version },
        )
        .unwrap();
        s
    }

    async fn pair() -> (Stream, Stream) {
        let l = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let c = hbb_common::tokio::net::TcpStream::connect(addr).await.unwrap();
        let (srv, _) = l.accept().await.unwrap();
        (Stream::from(c, addr), Stream::from(srv, addr))
    }

    #[tokio::test]
    async fn direct_link_on_a_private_lan_is_encrypted_end_to_end() {
        let (mut ctl, srv) = pair().await;
        let (pk, sk) = sign::gen_keypair();
        let t = tokio::spawn(target(srv, sk, pk, "123456789"));
        let who = secure(&mut ctl, &Known::default(), sa(LAN), 2_000).await.unwrap();
        let mut srv = t.await.unwrap();
        assert!(ctl.is_secured() && srv.is_secured());
        assert_eq!((who.id.as_str(), who.sign_pk.as_slice()), ("123456789", &pk.0[..]));
        assert_eq!(who.tailscale, Some("100.101.102.103".parse().unwrap()));
        let mut hello = Message::new();
        hello.set_signed_id(crate::message_proto::SignedId { id: b"hello".to_vec().into(), ..Default::default() });
        ctl.send(&hello).await.unwrap();
        let got = Message::parse_from_bytes(&srv.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(got, hello);
    }

    #[tokio::test]
    async fn a_plaintext_target_on_a_private_lan_is_refused() {
        let (mut ctl, mut srv) = pair().await;
        // What a Target that skips the handshake sends first: the login challenge, in the clear.
        let mut hash = Message::new();
        hash.set_hash(crate::message_proto::Hash { salt: "s".into(), challenge: "c".into(), ..Default::default() });
        srv.send(&hash).await.unwrap();
        match secure(&mut ctl, &Known::default(), sa(LAN), 2_000).await {
            Err(Failure::Refused(e)) => assert_eq!(e.to_string(), PLAINTEXT_REFUSED),
            other => panic!("not refused: {:?}", other.map(|w| w.id)),
        }
        assert!(!ctl.is_secured());
        assert!(require_encrypted("192.168.1.20".parse().unwrap(), &srv).is_err());
        assert!(require_encrypted("100.101.102.103".parse().unwrap(), &srv).is_ok());
    }

    #[tokio::test]
    async fn a_changed_identity_key_is_refused() {
        let (mut ctl, srv) = pair().await;
        let (pk, sk) = sign::gen_keypair();
        let (old_pk, _) = sign::gen_keypair();
        let mut known = Known::default();
        known.record(&Verified { id: "123456789".into(), sign_pk: old_pk.0.to_vec(), tailscale: None }, sa(LAN));
        tokio::spawn(target(srv, sk, pk, "123456789"));
        match secure(&mut ctl, &known, sa(LAN), 2_000).await {
            Err(Failure::Refused(e)) => assert_eq!(e.to_string(), IDENTITY_CHANGED),
            other => panic!("not refused: {:?}", other.map(|w| w.id)),
        }
    }

    #[tokio::test]
    async fn a_new_id_with_a_new_key_at_a_known_address_is_refused() {
        // Someone else on the Wi-Fi answers at a Target's address with an ID and key of its own.
        let (mut ctl, srv) = pair().await;
        let (pk, sk) = sign::gen_keypair();
        let (old_pk, _) = sign::gen_keypair();
        let mut known = Known::default();
        known.record(&Verified { id: "123456789".into(), sign_pk: old_pk.0.to_vec(), tailscale: None }, sa(LAN));
        tokio::spawn(target(srv, sk, pk, "555000111"));
        match secure(&mut ctl, &known, sa(LAN), 2_000).await {
            Err(Failure::Refused(e)) => assert_eq!(e.to_string(), IDENTITY_CHANGED),
            other => panic!("not refused: {:?}", other.map(|w| w.id)),
        }
    }

    #[tokio::test]
    async fn a_known_target_at_a_new_address_still_connects() {
        let (mut ctl, srv) = pair().await;
        let (pk, sk) = sign::gen_keypair();
        let mut known = Known::default();
        known.record(&Verified { id: "123456789".into(), sign_pk: pk.0.to_vec(), tailscale: None }, sa(LAN));
        tokio::spawn(target(srv, sk, pk, "123456789"));
        let who = secure(&mut ctl, &known, sa("192.168.1.77:21118"), 2_000).await.map_err(|_| "refused").unwrap();
        known.record(&who, sa("192.168.1.77:21118"));
        assert!(known.pin_ok(sa("192.168.1.77:21118"), "123456789", &pk.0));
    }

    // --- what the Controller remembers -----------------------------------------------------

    #[test]
    fn a_target_met_on_the_lan_is_reached_over_tailscale_next_time() {
        let mut known = Known::default();
        let who = Verified { id: "1".into(), sign_pk: vec![7; 32], tailscale: Some("100.101.102.103".parse().unwrap()) };
        known.record(&who, sa(LAN));
        let known = Known::parse(&known.to_json());
        assert_eq!(known.tailscale_for(sa(LAN)), Some(sa(TS)));
        let other = sa("192.168.1.30:21118");
        assert!(known.pin_ok(sa(LAN), "1", &[7; 32]) && !known.pin_ok(other, "1", &[8; 32]));
        assert!(known.pin_ok(other, "2", &[8; 32]), "a new Target at a new address is met for the first time");
    }

    #[tokio::test]
    async fn the_connect_box_takes_tailscale_or_private_addresses_never_public_ones() {
        let mut known = Known::default();
        known.record(&Verified { id: "1".into(), sign_pk: vec![1; 32], tailscale: Some("100.101.102.103".parse().unwrap()) }, sa(LAN));
        let plan = plan_for("192.168.1.20", &known, 1_000).await.unwrap();
        assert_eq!(plan, Plan { direct: sa(LAN), tailscale: Some(sa(TS)) });
        let plan = plan_for("100.101.102.103", &known, 1_000).await.unwrap();
        assert_eq!(plan, Plan { direct: sa(TS), tailscale: None });
        for public in ["8.8.8.8", "1.1.1.1:21118", "123456789"] {
            assert_eq!(plan_for(public, &known, 1_000).await.unwrap_err().to_string(), NOT_FOUND, "{}", public);
        }
    }
}
