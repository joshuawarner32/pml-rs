
#[derive(Debug)]
pub enum FormatError {
    InvalidEventClass(u32),
    Utf16Error,
    AsciiError,
}
