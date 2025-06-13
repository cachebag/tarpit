

#[derive(Debug)]
pub enum HeaderParseError {
    InvalidMagic,
    InvalidVersion,
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

