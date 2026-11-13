//! Trusted Controllers, 1.8.0: the Controller's own key on 1.7's Trusted list (ticket 06, trust
//! binding option B). The list, the decisions and the signed login itself live in `base::trust`
//! (one list, one ask: 1.7's tokens, "Always ask for password", the service as the one writer).
//! This file is the wiring that needs the rebranded protocol: two `LoginRequest` fields,
//! `boring_controller_pk` (1000) and `boring_login_sig` (1001), added by `rebrand.py` PROTO_PATCH.
//!
//! - Controller (`sign_login`): every login carries the Controller's Ed25519 public key (the
//!   service's key pair, the one it signs its ID with as a Target) and its signature over
//!   `base::trust::login_message`: this connection's challenge, the Target's Machine ID and the
//!   Controller's own ID. It signs a Machine ID only over a stream keyed to a Target it verified as
//!   that Machine ID (`signed_target`): a Direct Link pinned to it (`connect_plan::direct_first`
//!   takes only a Target that answers as the Machine ID dialled), or the Hosted servers' word on
//!   the Target's key under the server key baked into the app (`Client::start` refuses a Machine ID
//!   with any other key, and upstream's plaintext fallback leaves the stream unkeyed, which
//!   io_loop refuses). The signature travels inside that stream, so nobody between can read it.
//! - Target (`login_key`): the key such a login proves, only over a keyed stream and only for this
//!   computer's own Machine ID. `base::trust::Admission::prove` finds its entry with it.
//!
//! Known limits:
//! - A Controller's identity is its key file (the key pair in its config). Whoever copies that
//!   file and has the Unattended Password gets in with no Allow, as that Controller; Remove ends it.
//!   A Direct Link token (1.7) is the same: a bearer secret in the Controller's config.
//! - A login over a Direct Link to a typed name or address signs the Target ID that link's
//!   handshake verified and pinned (trust on first use, as every 1.7 Direct Link), so one Controller
//!   has one entry whichever way it connects (review-v18 S2).
//! - The Hosted servers' word on which key belongs to a Machine ID can be wrong: whoever holds the
//!   server's private key (on the Hosted box and in Keychain) can vouch any key, and stock `hbbs`
//!   lets a Machine ID's key change when the registration carries the same UUID from the same IP
//!   (RegisterPk is plaintext UDP; the UUID is the machine UID). A Controller that has met that
//!   Target before (over a Direct Link or Hosted) holds its key pinned (`base::direct_link::Known`)
//!   and refuses a changed one; one meeting it first through a lying server signs for the
//!   impostor, which can relay that one login to the real Target in real time (its Unattended
//!   Password is still needed). Closing that needs an `hbbs` that never lets a key change.
//! - The server's public key is not access control: a stock RustDesk client can register with the
//!   Hosted servers and dial a Target. It can't get in without the Unattended Password and Allow.
//! - The challenge is ~30 bits, fresh per connection.
use base::message_proto::LoginRequest;
use hbb_common::config::Config;

/// The key a connection checks the Hosted servers' word with is the baked server key ("" means
/// the built-in one). `Client::start` refuses a Machine ID with any other key (ticket 07).
pub fn baked_key(key: &str) -> bool {
    key.is_empty() || key == hbb_common::config::RS_PUB_KEY
}

/// What this Controller signs as the Target: `peer`'s Machine ID, or for a Direct Link to a typed
/// name or address the Target ID that link's handshake verified and pinned (`link`, review-v18 S2),
/// only when the stream carrying this login is keyed (`secured`). For a Machine ID a keyed stream
/// means a Direct Link pinned to it or `secure_connection` under the baked key verified the Target.
/// None for anything else, so that login goes unsigned.
pub fn signed_target(peer: &str, secured: bool, link: Option<&str>) -> Option<String> {
    if !secured {
        return None;
    }
    if crate::client::boring_is_machine_id(peer) {
        return Some(peer.to_owned());
    }
    link.filter(|id| crate::client::boring_is_machine_id(id)).map(str::to_owned)
}

/// Direct Links this session opened to a typed name or address: each stream's local address and
/// the Target ID its handshake verified (`_start` writes it for every stream it returns, before
/// any login on it). A stream reads only its own entry.
pub fn note_link(links: &mut Vec<(std::net::SocketAddr, String)>, local: std::net::SocketAddr, id: Option<String>) {
    links.retain(|(l, _)| *l != local);
    if let Some(id) = id {
        if links.len() >= 16 {
            links.remove(0);
        }
        links.push((local, id));
    }
}

/// The Target ID the Direct Link carrying this login (by its local address) verified, if any.
pub fn link_target(links: &[(std::net::SocketAddr, String)], local: std::net::SocketAddr) -> Option<String> {
    links.iter().find(|(l, _)| *l == local).map(|(_, id)| id.clone())
}

/// Sign this login with the Controller's own key pair, for the Target's Trusted list. Left
/// unsigned (the Target then relies on a token, or asks) for a Target it can't bind
/// (`signed_target`), a challenge no Target makes, or no key pair. On desktop it takes the key
/// pair the service made and never makes one: a key made by this UI process could differ from
/// the service's or race it. Mobile runs both sides in one process.
pub fn sign_login(lr: &mut LoginRequest, challenge: &str, secured: bool, link: Option<String>) {
    let Some(target) = signed_target(&lr.username, secured, link.as_deref()) else {
        return;
    };
    if base::trust::login_message(challenge, &target, &lr.my_id).is_none() {
        return;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let pair = Some(Config::get_key_pair());
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let pair = Config::get_existing_key_pair();
    let Some((sk, pk)) = pair else {
        return;
    };
    if let Some(sig) = base::trust::login_signature(challenge, &target, &lr.my_id, &sk) {
        lr.boring_controller_pk = pk.into();
        lr.boring_login_sig = sig.into();
    }
}

/// Target side: the Controller key this login proves on this connection. Only this computer's
/// own Machine ID (`own_id`) is a name it signs, and only once this connection's key exchange
/// completed (`secured`): defense in depth, since anyone can complete a key exchange; what makes
/// the name safe is the Controller's own check (`signed_target`). None: no signature (1.7 and
/// older, stock RustDesk), a bad one, or one made for another challenge, Target or Controller ID.
pub fn login_key(my_id: &str, pk: &[u8], sig: &[u8], challenge: &str, own_id: &str, secured: bool) -> Option<[u8; 32]> {
    if !secured || !crate::client::boring_is_machine_id(own_id) {
        return None;
    }
    base::trust::proven_key(my_id, pk, sig, challenge, own_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::{protobuf::Message as _, rendezvous_proto::IdPk, sodiumoxide::crypto::sign};

    const CONTROLLER: &str = "987654321";
    const TARGET: &str = "555666777";
    const CHALLENGE: &str = "k3m9xz";

    /// What `sign_login` does, with a key pair of our own (the real one reads the service's).
    fn login(dialed: &str, secured: bool, sk: &sign::SecretKey, pk: &sign::PublicKey) -> LoginRequest {
        let mut lr = LoginRequest { my_id: CONTROLLER.into(), username: dialed.into(), ..Default::default() };
        if let Some(target) = signed_target(dialed, secured, None) {
            lr.boring_controller_pk = pk.0.to_vec().into();
            lr.boring_login_sig = base::trust::login_signature(CHALLENGE, &target, CONTROLLER, &sk.0).unwrap().into();
        }
        lr
    }

    fn proven(lr: &LoginRequest, own_id: &str, secured: bool) -> Option<[u8; 32]> {
        login_key(&lr.my_id, &lr.boring_controller_pk, &lr.boring_login_sig, CHALLENGE, own_id, secured)
    }

    #[test]
    fn a_machine_id_is_signed_only_over_a_keyed_stream() {
        assert_eq!(signed_target(TARGET, true, None), Some(TARGET.into()));
        assert_eq!(signed_target(TARGET, false, None), None, "unverified: unsigned");
        for not_an_id in ["edit-bay-2.local", "100.101.102.103", "192.168.1.20:21118", "123@rs.example.com", ""] {
            assert_eq!(signed_target(not_an_id, true, None), None, "{}", not_an_id);
        }
    }

    #[test]
    fn a_typed_name_signs_the_target_id_its_direct_link_verified() {
        // review-v18 S2: a typed name's Direct Link is pinned like a Machine ID's, so it signs that ID.
        assert_eq!(signed_target("edit-bay-2.local", true, Some(TARGET)), Some(TARGET.into()));
        assert_eq!(signed_target("edit-bay-2.local", false, Some(TARGET)), None, "unkeyed: unsigned");
        assert_eq!(signed_target("edit-bay-2.local", true, Some("not-an-id")), None);
        let a: std::net::SocketAddr = "192.168.1.5:50001".parse().unwrap();
        let b: std::net::SocketAddr = "192.168.1.5:50002".parse().unwrap();
        let mut links = Vec::new();
        note_link(&mut links, a, Some(TARGET.into()));
        note_link(&mut links, b, Some("111222333".into()));
        assert_eq!(link_target(&links, a).as_deref(), Some(TARGET), "each stream reads its own");
        assert_eq!(link_target(&links, b).as_deref(), Some("111222333"));
        note_link(&mut links, a, None);
        assert_eq!(link_target(&links, a), None, "a new stream at that address clears the old entry");
    }

    #[test]
    fn the_target_takes_its_own_machine_id_on_a_keyed_connection_only() {
        let (pk, sk) = sign::gen_keypair();
        let lr = login(TARGET, true, &sk, &pk);
        assert_eq!(proven(&lr, TARGET, true), Some(pk.0));
        assert_eq!(proven(&lr, TARGET, false), None, "not keyed here");
        assert_eq!(proven(&lr, "111222333", true), None, "signed for another Target");
        assert_eq!(proven(&lr, "edit-bay-2", true), None, "no Machine ID here");
        let unsigned = login(TARGET, false, &sk, &pk);
        assert_eq!(proven(&unsigned, TARGET, true), None);
        let mut claimed = lr.clone();
        claimed.my_id = "111".into();
        assert_eq!(proven(&claimed, TARGET, true), None, "another Controller ID");
    }

    #[test]
    fn only_the_baked_server_key_counts() {
        assert!(baked_key(""));
        assert!(baked_key(hbb_common::config::RS_PUB_KEY));
        assert!(!baked_key("OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="));
    }

    #[test]
    fn a_signed_login_is_never_a_signed_id() {
        let m = base::trust::login_message(CHALLENGE, TARGET, CONTROLLER).unwrap();
        assert!(IdPk::parse_from_bytes(&m).is_err());
    }
}
