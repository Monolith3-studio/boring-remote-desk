//! High Efficiency (v1.7 ticket 05, ADR 0006).

use crate::direct_link::Path;
use crate::lan::LinkKind;
use std::convert::TryFrom;
use crate::message_proto::supported_decoding::PreferCodec;
use crate::message_proto::{ImageQuality, Message, Misc, OptionMessage, PeerInfo, SupportedDecoding};

/// What a High Efficiency session asks the Target for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub fps: i32,
    pub quality: ImageQuality,
    pub codec: PreferCodec,
}

/// The `platform_additions` key a Boring Remote Target adds to its `PeerInfo` (connection.rs),
/// valued with its version. Upstream RustDesk never sends it, so its presence is the Boring signal.
pub const MARKER: &str = "boring_remote";

/// Whether the Target's `platform_additions` JSON carries [`MARKER`] with a version string.
pub fn is_boring_remote(platform_additions: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(platform_additions)
        .ok()
        .and_then(|v| v.get(MARKER).and_then(|m| m.as_str()).map(|m| !m.is_empty()))
        .unwrap_or(false)
}

/// The size the Target encodes its current display at under High Efficiency: a Retina Mac
/// (`scale` > 1) captures its points size while a software codec runs ([`captures_points`]).
/// `None` when the PeerInfo names no current display.
pub fn encode_size(peer: &PeerInfo) -> Option<(i32, i32)> {
    let d = peer.displays.get(usize::try_from(peer.current_display).ok()?)?;
    let scale = if d.scale > 1.0 { d.scale } else { 1.0 };
    Some(((d.width as f64 / scale).round() as i32, (d.height as f64 / scale).round() as i32))
}

/// The biggest frame AV1 gets (ADR 0006 amendment). No Mac and no GPU this app drives encodes AV1
/// in hardware: AV1 is always software libaom, already at its fastest realtime speed (10). Upstream
/// passes AV1 only when it encodes a 1080p frame in under 30 ms (scrap `test_av1`); past that size
/// it can't hold 30 fps (device check A3: 3024x1964 gave 23 fps, 503 ms), and VP9 is cheaper.
pub const AV1_MAX_PIXELS: i64 = 1920 * 1080;

/// Best software codec both ends have (ADR 0006: hardware H.265/H.264 stay out): AV1 up to
/// [`AV1_MAX_PIXELS`], then VP9, then VP8. The Target always encodes VP9 (SupportedEncoding has
/// no flag for it). Neither left means Auto: the Target picks as it would anyway.
fn best_codec(peer: &PeerInfo, ours: &SupportedDecoding) -> PreferCodec {
    let theirs = peer.encoding.get_or_default();
    let av1_keeps_up = encode_size(peer).is_some_and(|(w, h)| w as i64 * h as i64 <= AV1_MAX_PIXELS);
    if theirs.av1 && ours.ability_av1 > 0 && av1_keeps_up {
        PreferCodec::AV1
    } else if ours.ability_vp9 > 0 {
        PreferCodec::VP9
    } else if theirs.vp8 && ours.ability_vp8 > 0 {
        PreferCodec::VP8
    } else {
        PreferCodec::Auto
    }
}

/// High Efficiency (ticket 05): a Direct Link on this network between two Boring Remotes asks for
/// 60 fps, best image quality and the best shared software codec. Anything else (via internet,
/// a Target that isn't Boring Remote) gets `None`: the session keeps its adaptive defaults.
/// `ours` is what this Controller decodes; the Target's encoders come from `peer.encoding`.
pub fn choose(link: Path, peer: &PeerInfo, ours: &SupportedDecoding) -> Option<Settings> {
    if link != Path::Local || !is_boring_remote(&peer.platform_additions) {
        return None;
    }
    Some(Settings { fps: FPS, quality: ImageQuality::Best, codec: best_codec(peer, ours) })
}

pub const FPS: i32 = 60;

/// The `stream_type` the Controller re-reports once the Target answered the ask, so the Link Badge
/// reads "Local · High Efficiency" only when it was actually applied (Flutter `linkStateFor`).
pub const STREAM_TYPE: &str = "LocalHighEfficiency";
/// boring-remote (v1.7 t25): the same, on a link whose type both ends know.
pub const STREAM_TYPE_WIRED: &str = "LocalWiredHighEfficiency";
pub const STREAM_TYPE_WIFI: &str = "LocalWiFiHighEfficiency";

impl Settings {
    /// The one mid-session option message carrying these settings. Session only: nothing is
    /// written to the peer's config, so a later Tailscale session starts from the defaults.
    /// `ours` keeps this Mac's decode abilities; only the codec preference changes.
    pub fn message(&self, mut ours: SupportedDecoding) -> Message {
        ours.prefer = self.codec.into();
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            image_quality: self.quality.into(),
            custom_fps: self.fps,
            supported_decoding: protobuf::MessageField::some(ours),
            ..Default::default()
        });
        let mut msg = Message::new();
        msg.set_misc(misc);
        msg
    }
}

/// What the Controller holds for one connection round, from connect until the Target answers
/// the High Efficiency ask (src/client/io_loop.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub path: Path,
    pub kind: LinkKind,
    pub secured: bool,
    pub direct: bool,
    asked: bool,
}

impl Link {
    pub fn new(stream_type: &str, secured: bool, direct: bool) -> Self {
        // boring-remote (v1.7 t25): "Local", "LocalWired", "LocalWiFi" are all this network.
        let path = if stream_type.starts_with(Path::Local.stream_type()) { Path::Local } else { Path::ViaInternet };
        let kind = match stream_type {
            "LocalWired" => LinkKind::Wired,
            "LocalWiFi" => LinkKind::WiFi,
            _ => LinkKind::Other,
        };
        Link { path, kind, secured, direct, asked: false }
    }

    /// What to re-report once the Target answered: High Efficiency, keeping the link type on the badge.
    pub fn answered_stream_type(&self) -> &'static str {
        match self.kind {
            LinkKind::Wired => STREAM_TYPE_WIRED,
            LinkKind::WiFi => STREAM_TYPE_WIFI,
            LinkKind::Other => STREAM_TYPE,
        }
    }

    /// The first PeerInfo of the round: the High Efficiency ask to send, once, if [`choose`] says
    /// so. `ours` is what this Controller decodes.
    pub fn ask(&mut self, peer: &PeerInfo, ours: SupportedDecoding) -> Option<Message> {
        if self.asked {
            return None;
        }
        let settings = choose(self.path, peer, &ours)?;
        self.asked = true;
        log::info!("High Efficiency asked: {:?}", settings);
        Some(settings.message(ours))
    }

    /// A misc option from the Target. True once, when it is the Target's answer to our ask: only
    /// then does the badge say High Efficiency (re-report [`STREAM_TYPE`]).
    pub fn answered(&mut self, o: &OptionMessage) -> bool {
        if !self.asked || !is_answer(o) {
            return false;
        }
        self.asked = false;
        true
    }
}

fn is_best_at_full_rate(o: &OptionMessage) -> bool {
    o.image_quality.enum_value() == Ok(ImageQuality::Best) && o.custom_fps == FPS
}

fn is_answer(o: &OptionMessage) -> bool {
    is_best_at_full_rate(o) && o.supported_decoding.is_none()
}

/// Target side, after `update_options` applied `o`: the answer to a High Efficiency ask (best
/// quality, 60 fps and a codec choice in one message, which only a Boring Remote Controller sends).
/// Anything else, such as a quality picked by hand, gets `None`.
pub fn ack_for(o: &OptionMessage) -> Option<Message> {
    if !is_best_at_full_rate(o) || o.supported_decoding.is_none() {
        return None;
    }
    let mut misc = Misc::new();
    misc.set_option(OptionMessage {
        image_quality: ImageQuality::Best.into(),
        custom_fps: FPS,
        ..Default::default()
    });
    let mut msg = Message::new();
    msg.set_misc(misc);
    Some(msg)
}

/// Target (macOS): whether High Efficiency captures a Retina display at its points size, a quarter
/// of the pixels. Only on a software encoder (VP9/AV1/VP8); a hardware one keeps the full size.
pub fn captures_points(hardware_encoder: bool) -> bool {
    !hardware_encoder
}

/// Target (macOS): the connections on High Efficiency with a software encoder. Upstream drops to
/// points when it streams two displays (server.rs `update_enable_retina`); this adds the second
/// reason, held until the connection closes.
#[derive(Default)]
pub struct PointsCapture(std::sync::Mutex<Vec<i32>>);

impl PointsCapture {
    pub fn hold(&self, conn_id: i32) {
        if let Ok(mut held) = self.0.lock() {
            if !held.contains(&conn_id) {
                held.push(conn_id);
            }
        }
    }

    /// Upstream's Retina rule plus ours. `open` are the server's connection ids: a held id that
    /// is not open any more is let go.
    pub fn retina(&self, video_services: usize, open: impl Iterator<Item = i32>) -> bool {
        let open: Vec<i32> = open.collect();
        let mut held = match self.0.lock() {
            Ok(held) => held,
            Err(e) => e.into_inner(),
        };
        held.retain(|id| open.contains(id));
        video_services < 2 && held.is_empty()
    }
}

/// The Target's one [`PointsCapture`].
pub static POINTS_CAPTURE: PointsCapture = PointsCapture(std::sync::Mutex::new(Vec::new()));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_proto::{DisplayInfo, SupportedEncoding};

    fn display(width: i32, height: i32, scale: f64) -> DisplayInfo {
        DisplayInfo { width, height, scale, ..Default::default() }
    }

    fn boring_peer_on(av1: bool, d: DisplayInfo) -> PeerInfo {
        PeerInfo {
            platform_additions: r#"{"boring_remote":"1.7.0","is_installed":true}"#.into(),
            encoding: protobuf::MessageField::some(SupportedEncoding { av1, vp8: true, ..Default::default() }),
            displays: vec![display(1920, 1080, 1.0), d],
            current_display: 1,
            ..Default::default()
        }
    }

    /// Tori Laptop (device check A3): a Retina M1 Pro, 3024x1964 pixels, 1512x982 points.
    fn boring_peer(av1: bool) -> PeerInfo {
        boring_peer_on(av1, display(3024, 1964, 2.0))
    }

    fn decodes(av1: bool) -> SupportedDecoding {
        SupportedDecoding { ability_vp9: 1, ability_vp8: 1, ability_av1: av1 as i32, ..Default::default() }
    }

    #[test]
    fn local_between_two_boring_remotes_gets_60_fps_best_quality_on_av1() {
        let s = choose(Path::Local, &boring_peer(true), &decodes(true)).unwrap();
        assert_eq!(s, Settings { fps: 60, quality: ImageQuality::Best, codec: PreferCodec::AV1 });
    }

    #[test]
    fn via_internet_keeps_the_adaptive_defaults() {
        assert_eq!(choose(Path::ViaInternet, &boring_peer(true), &decodes(true)), None);
    }

    #[test]
    fn a_target_that_is_not_boring_remote_keeps_the_defaults() {
        let mut upstream = boring_peer(true);
        upstream.platform_additions = r#"{"is_installed":true}"#.into();
        assert_eq!(choose(Path::Local, &upstream, &decodes(true)), None);
        for junk in ["", "not json", r#"{"boring_remote":""}"#, r#"{"boring_remote":true}"#] {
            upstream.platform_additions = junk.into();
            assert_eq!(choose(Path::Local, &upstream, &decodes(true)), None, "{}", junk);
        }
    }

    #[test]
    fn codec_falls_back_to_vp9_when_either_side_lacks_av1() {
        for (peer_av1, our_av1) in [(false, true), (true, false), (false, false)] {
            let s = choose(Path::Local, &boring_peer(peer_av1), &decodes(our_av1)).unwrap();
            assert_eq!(s.codec, PreferCodec::VP9, "peer av1 {} ours {}", peer_av1, our_av1);
            assert_eq!((s.fps, s.quality), (60, ImageQuality::Best));
        }
    }

    #[test]
    fn codec_falls_back_to_vp8_then_auto() {
        let mut ours = decodes(false);
        ours.ability_vp9 = 0;
        assert_eq!(choose(Path::Local, &boring_peer(false), &ours).unwrap().codec, PreferCodec::VP8);
        ours.ability_vp8 = 0;
        assert_eq!(choose(Path::Local, &boring_peer(false), &ours).unwrap().codec, PreferCodec::Auto);
    }

    #[test]
    fn the_target_is_asked_for_exactly_these_settings_for_this_session() {
        let s = choose(Path::Local, &boring_peer(true), &decodes(true)).unwrap();
        let msg = s.message(decodes(true));
        let o = msg.misc().option();
        assert_eq!(o.image_quality.enum_value(), Ok(ImageQuality::Best));
        assert_eq!(o.custom_fps, 60);
        let d = o.supported_decoding.get_or_default();
        assert_eq!(d.prefer.enum_value(), Ok(PreferCodec::AV1));
        assert_eq!((d.ability_vp9, d.ability_av1), (1, 1), "abilities stay what this Mac decodes");
        assert_eq!(STREAM_TYPE, "LocalHighEfficiency", "what Flutter's linkStateFor maps to the badge");
    }

    #[test]
    fn a_retina_mac_is_encoded_at_its_points_size() {
        assert_eq!(encode_size(&boring_peer(true)), Some((1512, 982)));
        assert_eq!(encode_size(&boring_peer_on(true, display(3440, 1440, 1.0))), Some((3440, 1440)));
        let mut lost = boring_peer(true);
        lost.current_display = 7;
        assert_eq!(encode_size(&lost), None, "no current display, no size");
    }

    #[test]
    fn av1_only_where_its_software_encoder_keeps_up() {
        // Device check A3: libaom at 3024x1964 gave 23 fps / 503 ms; at points size it is a
        // quarter of the pixels, under the 1080p frame upstream's own AV1 speed test passes.
        let mac = choose(Path::Local, &boring_peer(true), &decodes(true)).unwrap();
        assert_eq!(mac.codec, PreferCodec::AV1);
        let fhd = choose(Path::Local, &boring_peer_on(true, display(1920, 1080, 1.0)), &decodes(true));
        assert_eq!(fhd.unwrap().codec, PreferCodec::AV1);
        // The Windows PC and Mac Studio (3440x1440) and a 5K iMac (2560x1440 points): VP9.
        for d in [display(3440, 1440, 1.0), display(5120, 2880, 2.0), display(3840, 2160, 1.0)] {
            let s = choose(Path::Local, &boring_peer_on(true, d.clone()), &decodes(true)).unwrap();
            assert_eq!(s.codec, PreferCodec::VP9, "{}x{} @{}", d.width, d.height, d.scale);
            assert_eq!((s.fps, s.quality), (60, ImageQuality::Best));
        }
        let mut unknown = boring_peer(true);
        unknown.displays.clear();
        assert_eq!(choose(Path::Local, &unknown, &decodes(true)).unwrap().codec, PreferCodec::VP9);
    }

    #[test]
    fn a_target_on_a_software_codec_captures_points_while_high_efficiency_is_on() {
        assert!(captures_points(false), "software VP9/AV1/VP8 encode the points size");
        assert!(!captures_points(true), "a hardware H.264/H.265 encoder keeps the Retina pixels");
        let held = PointsCapture::default();
        assert!(held.retina(1, vec![1, 2].into_iter()), "no High Efficiency session: Retina as upstream");
        held.hold(2);
        assert!(!held.retina(1, vec![1, 2].into_iter()), "connection 2 is on High Efficiency");
        assert!(!held.retina(2, vec![1].into_iter()), "two displays: upstream's points rule stands");
        assert!(held.retina(1, vec![1, 3].into_iter()), "connection 2 closed: back to Retina");
        assert!(held.retina(1, vec![1, 2].into_iter()), "and it was let go, not just skipped");
    }

    fn option(m: &Message) -> OptionMessage {
        m.misc().option().clone()
    }

    #[test]
    fn the_badge_waits_until_the_target_says_high_efficiency_took() {
        let mut link = Link::new(Path::Local.stream_type(), true, false);
        let ask = link.ask(&boring_peer(true), decodes(true)).expect("asks on a Local link");
        assert!(link.ask(&boring_peer(true), decodes(true)).is_none(), "asks once");
        let pick = OptionMessage { image_quality: ImageQuality::Best.into(), ..Default::default() };
        assert!(ack_for(&pick).is_none(), "a quality picked by hand gets no answer");
        assert!(!link.answered(&pick));
        let answer = ack_for(&option(&ask)).expect("the Target answers the ask");
        assert!(link.answered(&option(&answer)));
        assert!(!link.answered(&option(&answer)), "the badge flips once");
    }

    #[test]
    fn no_answer_counts_without_an_ask() {
        let mut link = Link::new(Path::ViaInternet.stream_type(), true, false);
        assert!(link.ask(&boring_peer(true), decodes(true)).is_none(), "via internet keeps the defaults");
        let ask = choose(Path::Local, &boring_peer(true), &decodes(true)).unwrap().message(decodes(true));
        let answer = ack_for(&option(&ask)).unwrap();
        assert!(!link.answered(&option(&answer)));
    }

    // --- v1.7 t25: the link type stays on the badge ---
    #[test]
    fn a_wired_or_wifi_local_link_still_asks_and_keeps_its_link_type() {
        for (stream_type, after) in [
            ("Local", "LocalHighEfficiency"),
            ("LocalWired", "LocalWiredHighEfficiency"),
            ("LocalWiFi", "LocalWiFiHighEfficiency"),
        ] {
            let mut link = Link::new(stream_type, true, false);
            assert!(link.ask(&boring_peer(true), decodes(true)).is_some(), "{}", stream_type);
            assert_eq!(link.answered_stream_type(), after);
        }
        assert!(Link::new("Tailscale", true, false).ask(&boring_peer(true), decodes(true)).is_none());
    }
}
