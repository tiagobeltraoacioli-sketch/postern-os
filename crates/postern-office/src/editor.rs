//! The **injected, mockable editor seam** — the boundary at which unmodified
//! LibreOffice is aggregated out-of-process, never linked or forked.
//!
//! [`OfficeSession::edit`](crate::session::OfficeSession::edit) takes any
//! `FnOnce(&[u8]) -> Result<Vec<u8>, String>` — the **exact** shape of
//! `postern_quarantine`'s converter seam. That single signature lets the tests
//! drive a pure-Rust [`MockEditor`] fully offline, while the real
//! LibreOffice-backed editor ([`soffice_editor`], feature `soffice-live`) is a
//! drop-in replacement exercised only under an `#[ignore]`d live test.
//!
//! ## Honest status of the live path
//!
//! LibreOffice is **not present in this build**, and a real *interactive* edit
//! needs a human at a GUI, so [`soffice_editor`] is a **SCAFFOLD**, not a
//! shipped feature: it mirrors the out-of-process spawn pattern
//! (`postern_quarantine::adapters::soffice_convert`) — throwaway profile,
//! stdio nulled — but round-tripping an *edited* document reliably (format
//! fidelity, the "did the user actually save" question) is unimplemented. Treat
//! anything behind `soffice-live` as **partial / blocked** until run against a
//! real `soffice` on a real desktop.

/// A pure-Rust, in-process editor for **offline tests**: applies a caller-
/// supplied transform to the plaintext document bytes. No LibreOffice, no
/// subprocess — this is how the panic-lock and reseal paths are tested without
/// the engine present.
///
/// ```
/// use postern_office::editor::MockEditor;
/// let ed = MockEditor::new(|doc| {
///     let mut v = doc.to_vec();
///     v.extend_from_slice(b" [reviewed]");
///     Ok(v)
/// });
/// assert_eq!(ed.run(b"memo"), Ok(b"memo [reviewed]".to_vec()));
/// ```
pub struct MockEditor<F> {
    transform: F,
}

impl<F> MockEditor<F>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    /// Wrap a transform closure as an editor.
    pub fn new(transform: F) -> Self {
        MockEditor { transform }
    }

    /// Run the edit over `plaintext`, returning the edited document (or a
    /// `String` error, matching the seam contract).
    pub fn run(self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        (self.transform)(plaintext)
    }
}

/// Adapt a [`MockEditor`] into the bare `FnOnce(&[u8]) -> Result<Vec<u8>, String>`
/// that [`OfficeSession::edit`](crate::session::OfficeSession::edit) expects.
pub fn mock_editor<F>(transform: F) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, String>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    move |pt| MockEditor::new(transform).run(pt)
}

/// The real out-of-process LibreOffice editor seam. **SCAFFOLD, feature-gated,
/// never built by default** — see the module docs. LibreOffice is aggregated
/// (spawned), never forked or linked.
#[cfg(feature = "soffice-live")]
pub mod live {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    /// Configuration for spawning an unmodified `soffice` for an interactive
    /// edit. Mirrors `postern_quarantine::adapters::SofficeConfig`.
    pub struct SofficeEditConfig {
        /// Explicit `soffice` path, or `None` to search `PATH`.
        pub executable: Option<PathBuf>,
    }

    /// Build the editor closure backed by a real `soffice` process.
    ///
    /// HONEST SCAFFOLD: this spawns `soffice` on a scratch file so a human can
    /// edit it, waits for the process to exit, and reads the file back. It does
    /// NOT solve format round-trip fidelity or verify the user saved — those are
    /// unimplemented. Do not present this as a shipped editing pipeline.
    pub fn soffice_editor(
        config: SofficeEditConfig,
    ) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, String> {
        move |plaintext| {
            let soffice = config
                .executable
                .clone()
                .or_else(|| find_soffice())
                .ok_or_else(|| {
                    "no `soffice` on PATH — install LibreOffice (aggregated, not forked)"
                        .to_string()
                })?;

            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let work =
                std::env::temp_dir().join(format!("postern-office-edit-{nanos}"));
            std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
            let doc = work.join("document");
            std::fs::write(&doc, plaintext).map_err(|e| e.to_string())?;

            // Spawn the GUI editor on the scratch; wait for the user to finish.
            let status = Command::new(&soffice)
                .arg("--norestore")
                .arg(&doc)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("could not spawn {}: {e}", soffice.display()))?;
            if !status.success() {
                return Err(format!("soffice exited with {status}"));
            }
            let edited = std::fs::read(&doc).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_dir_all(&work);
            Ok(edited)
        }
    }

    fn find_soffice() -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join("soffice");
            if cand.is_file() {
                return Some(cand);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_editor_transforms() {
        let out = mock_editor(|d| Ok([d, b" done"].concat()))(b"task");
        assert_eq!(out, Ok(b"task done".to_vec()));
    }

    #[test]
    fn mock_editor_can_fail() {
        let out = mock_editor(|_| Err("nope".to_string()))(b"x");
        assert_eq!(out, Err("nope".to_string()));
    }

    /// Live LibreOffice edit: `#[ignore]`d and feature-gated. LibreOffice is not
    /// present here; this documents the seam and is run only on a real desktop
    /// with `--features soffice-live -- --ignored`.
    #[cfg(feature = "soffice-live")]
    #[test]
    #[ignore = "needs a real interactive LibreOffice on a desktop; not run offline/CI"]
    fn soffice_live_edit_roundtrip() {
        use super::live::{soffice_editor, SofficeEditConfig};
        let ed = soffice_editor(SofficeEditConfig { executable: None });
        let _ = ed(b"live edit scaffold");
    }
}
