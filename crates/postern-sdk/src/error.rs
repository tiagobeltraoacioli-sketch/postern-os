//! The single typed error crossing the Postern SDK FFI boundary. Every product
//! core's error (each has its own concrete type, or plain `String`) is funneled
//! into this one variant via its `Display`/`to_string`, so the app layer sees a
//! uniform `PosternError` regardless of which product raised it.

/// Error returned across the unified FFI boundary. Carries the originating
/// core's message so nothing is lost, while keeping ONE error type for the
/// whole suite.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PosternError {
    #[error("{msg}")]
    Postern { msg: String },
}

impl From<String> for PosternError {
    fn from(msg: String) -> Self {
        PosternError::Postern { msg }
    }
}

impl From<&str> for PosternError {
    fn from(msg: &str) -> Self {
        PosternError::Postern { msg: msg.to_string() }
    }
}
