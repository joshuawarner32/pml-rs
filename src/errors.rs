use thiserror::Error;

#[derive(Error, Debug)]
pub enum FormatError {
    #[error("invalid event class {0}")]
    InvalidEventClass(u32),
    #[error("utf16 error")]
    Utf16Error,
    #[error("ascii error")]
    AsciiError,
}
