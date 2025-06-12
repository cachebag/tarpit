use crate::error::HeaderParseError;

#[derive(Debug)]
pub struct HeaderUstar {
    name:       [u8; 100],              // offset: 0 
    mode:       [u8; 8],                // offset: 100
    uid:        [u8; 8],                // offset: 108
    gid:        [u8; 8],                // offset: 116
    size:       [u8; 12],               // offset: 124
    mtime:      [u8; 12],               // offset: 136
    chksum:     [u8; 8],                // offset: 148
    typeflag:   u8,                     // offset: 156
    linkname:   [u8; 100],              // offset: 157
    magic:      [u8; 6],                // offset: 257
    version:    [u8; 2],                // offset: 263
    uname:      [u8; 32],               // offset: 265
    gname:      [u8; 32],               // offset: 297
    devmajor:   [u8; 8],                // offset: 329
    devminor:   [u8; 8],                // offset: 337
    prefix:     [u8; 155],              // offset: 345
}

impl HeaderUstar {
    pub fn from_bytes(_block: &[u8; 512]) -> Result<Self, HeaderParseError> {
        Err(HeaderParseError::InvalidMagic) // placeholder
    }
}

fn test() {
    let dummy_block = [0u8; 512];
    let _ = HeaderUstar::from_bytes(&dummy_block);
}
