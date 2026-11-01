//! High Efficiency (v1.7 ticket 05, ADR 0006).

use crate::direct_link::Path;
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

/// Best software codec both ends have (ADR 0006: hardware H.265/H.264 stay out): AV1, then VP9,
/// then VP8. The Target always encodes VP9 (SupportedEncoding has no flag for it). Neither left
/// means Auto: the Target picks as it would anyway.
fn best_codec(peer: &PeerInfo, ours: &SupportedDecoding) -> PreferCodec {
    let theirs = peer.encoding.get_or_default();
    if theirs.av1 && ours.ability_av1 > 0 {
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

/// The `stream_type` the Controller re-reports once High Efficiency went out, so the Link Badge
/// reads "Local · High Efficiency" only when it was actually applied (Flutter `linkStateFor`).
pub const STREAM_TYPE: &str = "LocalHighEfficiency";

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_proto::SupportedEncoding;

    fn boring_peer(av1: bool) -> PeerInfo {
        PeerInfo {
            platform_additions: r#"{"boring_remote":"1.7.0","is_installed":true}"#.into(),
            encoding: protobuf::MessageField::some(SupportedEncoding { av1, vp8: true, ..Default::default() }),
            ..Default::default()
        }
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
}
