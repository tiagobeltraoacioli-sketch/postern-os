//! Call-audio routing via **callaudiod** (`org.mobian_project.CallAudio`).
//!
//! **Honest gap most designs skip:** ModemManager sets up the *call* but NOT
//! the *audio path*. On Linux phones the voice audio route (earpiece vs
//! speaker, mic mute, "voice call" ALSA/UCM profile) is switched by the
//! **callaudiod** daemon (GPL — used over D-Bus only, never embedded), on top
//! of PipeWire/ALSA with device-specific UCM profiles. Without this, a call
//! "connects" silently. On modems with USB audio the PCM may instead be a
//! plain ALSA device — device bring-up decides; both need real hardware.

use zbus::proxy;

pub const CALLAUDIO_SERVICE: &str = "org.mobian_project.CallAudio";
pub const CALLAUDIO_PATH: &str = "/org/mobian_project/CallAudio";

/// Audio mode as callaudiod defines it.
pub const MODE_DEFAULT: u32 = 0;
pub const MODE_CALL: u32 = 1;

#[proxy(
    interface = "org.mobian_project.CallAudio",
    default_service = "org.mobian_project.CallAudio",
    default_path = "/org/mobian_project/CallAudio"
)]
pub trait CallAudio {
    /// Switch between normal audio and voice-call routing (UCM profile).
    fn select_mode(&self, mode: u32) -> zbus::Result<bool>;
    /// Route to loudspeaker instead of earpiece.
    fn enable_speaker(&self, enable: bool) -> zbus::Result<bool>;
    /// Hardware-path mic mute for the call.
    fn mute_mic(&self, mute: bool) -> zbus::Result<bool>;
}
