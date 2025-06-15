 
// Errors for header struct
#[derive(Debug)]
pub enum HeaderParseError {
    InvalidMode,
    InvalidVersion,
    InvalidMagic,
    InvalidUtf8,
    FieldTooLong(&'static str),
    InvalidOctal(&'static str),
    NonAsciiField(&'static str),
    InvalidTypeflag(u8),
    InvalidChecksum,
    InvalidBlockSize,
    PathTooLong,
    UnexpectedEOF,
}

