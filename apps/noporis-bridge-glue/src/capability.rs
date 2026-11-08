// SPDX-License-Identifier: MIT OR Apache-2.0
//! The five per-capability bridges — the only things that may cross the span.
//!
//! These mirror `apps/sloboda-gate`'s `bridges.{clipboard, files, mic,
//! camera, location}` one-for-one (Mechanism-Design §3.4). Each is a **covert
//! channel if silently on**, so each is **deny-by-default** and crosses only by
//! an explicit, disclosed, individually-revocable grant. There is no sixth
//! "everything" lane and no lane is ever silent — the honest point of the guarded
//! crossing is that *nothing crosses that the user did not hand across*.

use serde::{Deserialize, Serialize};

// Reused from the tested signer-protocol: how "loud" an action is. We do NOT
// invent a tiering vocabulary; we reuse the one the phone-as-signer flow already
// speaks so a crossing prompt and a signing prompt read the same.
use postern_signer_protocol::ConsequenceTier;

/// The exhaustive set of capability bridges NoporIS can extend across the span.
/// Ordered + hashable so a gate can key its per-capability state on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// A one-shot clipboard payload (text/blob) handed to the far persona.
    Clipboard,
    /// A file/document blob handed across.
    Files,
    /// A microphone sample/stream lent across.
    Mic,
    /// A camera frame/stream lent across.
    Camera,
    /// A location fix lent across.
    Location,
}

impl Capability {
    /// Every capability, in a stable order — the deny-by-default panel enumerates
    /// exactly these and no more.
    pub const ALL: [Capability; 5] = [
        Capability::Clipboard,
        Capability::Files,
        Capability::Mic,
        Capability::Camera,
        Capability::Location,
    ];

    /// The stable machine key (matches the gate-store bridge names).
    pub fn key(self) -> &'static str {
        match self {
            Capability::Clipboard => "clipboard",
            Capability::Files => "files",
            Capability::Mic => "mic",
            Capability::Camera => "camera",
            Capability::Location => "location",
        }
    }

    /// A plain-language label for the crossing prompt.
    pub fn label(self) -> &'static str {
        match self {
            Capability::Clipboard => "clipboard",
            Capability::Files => "a file",
            Capability::Mic => "the microphone",
            Capability::Camera => "the camera",
            Capability::Location => "your location",
        }
    }

    /// How loud this crossing is. **Nothing is `SilentReadOnly`** — every crossing
    /// is at least an explicit single-tap lane. Continuous, ambient *sensor*
    /// streams (mic/camera/location) are the highest tier: they demand a
    /// deliberate confirm, never a muscle-memory tap. This is derived structurally
    /// from what the capability *is*, never from a field the requester controls.
    pub fn tier(self) -> ConsequenceTier {
        match self {
            Capability::Clipboard | Capability::Files => ConsequenceTier::SingleTap,
            Capability::Mic | Capability::Camera | Capability::Location => {
                ConsequenceTier::ExplicitReview
            }
        }
    }
}
