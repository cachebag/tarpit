use std::io::Write;
use tarpit::{HeaderUstar, HeaderParseError, TypeFlags};

mod field {
    pub const NAME:      (usize, usize) = (  0, 100);
    pub const MODE:      (usize, usize) = (100,   8);
    pub const UID:       (usize, usize) = (108,   8);
    pub const GID:       (usize, usize) = (116,   8);
    pub const SIZE:      (usize, usize) = (124,  12);
    pub const MTIME:     (usize, usize) = (136,  12);
    pub const CHKSUM:    (usize, usize) = (148,   8);
    pub const TYPEFLAG:  (usize, usize) = (156,   1);
    pub const LINKNAME:  (usize, usize) = (157, 100);
    pub const MAGIC:     (usize, usize) = (257,   6);
    pub const VERSION:   (usize, usize) = (263,   2);
    pub const UNAME:     (usize, usize) = (265,  32);
    pub const GNAME:     (usize, usize) = (297,  32);
    pub const DEVMAJOR:  (usize, usize) = (329,   8);
    pub const DEVMINOR:  (usize, usize) = (337,   8);
    pub const PREFIX:    (usize, usize) = (345, 155);
}

macro_rules! blank_block { () => { [0u8; 512] } }

macro_rules! set_field {
    ($blk:expr, $field:path, $bytes:expr) => {{
        let (offset, len) = $field;
        let slice = &mut $blk[offset .. offset + len];
        assert_eq!($bytes.len(), len, "byte count mismatch in set_field!");
        slice.copy_from_slice(&$bytes[..len]);
    }};
}

macro_rules! set_string {
    ($blk:expr, $field:path, $val:expr) => {{
        let (offset, len) = $field;
        let slice = &mut $blk[offset .. offset + len];
        let bytes: &[u8] = $val.as_ref();
        assert!(bytes.len() <= len, "String too long for field");
        slice[..bytes.len()].copy_from_slice(bytes);
        for b in &mut slice[bytes.len()..] { *b = 0 }
    }};
}

macro_rules! set_octal {
    ($blk:expr, $field:path, $value:expr) => {{
        let len = $field.1;
        let mut tmp = vec![0u8; len];
        write!(&mut tmp[..], "{:01$o}\0", $value, len - 1).unwrap();
        set_field!($blk, $field, &tmp[..]);
    }};
}

fn finalise(mut blk: [u8; 512]) -> [u8; 512] {
    set_field!(blk, field::MAGIC,   *b"ustar\0");
    set_field!(blk, field::VERSION, *b"00");
    for b in &mut blk[field::CHKSUM.0 .. field::CHKSUM.0 + field::CHKSUM.1] { *b = b' '; }
    let sum: u32 = blk.iter().map(|&b| b as u32).sum();
    let mut buf = [0u8; 8];
    write!(&mut buf[..], "{:06o}\0 ", sum).unwrap();
    set_field!(blk, field::CHKSUM, buf);
    blk
}

/*---------------------- Happy path --------------------------*/

#[test]
fn parses_file_name() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_string!(blk, field::NAME, b"test_file.txt");
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_name()?, "test_file.txt");
    Ok(())
}

#[test]
fn parses_file_mode() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_octal!(blk, field::MODE, 0o777);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_mode()?, 0o777);
    Ok(())
}

#[test]
fn parses_file_uid() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_octal!(blk, field::UID, 0o1741);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_uid()?, 0o1741);
    Ok(())
}

#[test]
fn parses_file_gid() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_octal!(blk, field::GID, 0o5710);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_gid()?, 0o5710);
    Ok(())
}

#[test]
fn parses_file_size() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_octal!(blk, field::SIZE, 0o10000000000);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_size()?, 0o10000000000);
    Ok(())
} 

#[test]
fn parses_file_mtime() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    const MTIME: u64 = 1_000_214_760;
    set_octal!(blk, field::MTIME, MTIME);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_mtime()?, MTIME);
    Ok(())
}

#[test]
fn parses_file_chksum() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_string!(blk, field::NAME, b"file.txt");
    let blk = finalise(blk);
    let hdr = HeaderUstar::from_bytes(&blk)?;
    let mut chk_bytes = blk;              
    chk_bytes[148..156].fill(b' ');         
    let expected: u64 = chk_bytes.iter().map(|&b| b as u64).sum();
    assert_eq!(hdr.file_chksum()?, expected);
    Ok(())
}

#[test]
fn parses_file_type() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_field!(blk, field::TYPEFLAG, *b"2");
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_type()?, TypeFlags::Symtype);
    Ok(())
}

#[test]
fn parses_file_linkname() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_field!(blk, field::LINKNAME, [b'A'; 100]);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_linkname()?, "A".repeat(100));
    Ok(())
}

#[test]
fn parses_file_magic() -> Result<(), HeaderParseError> {
    let blk = blank_block!();
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_magic()?, "ustar");
    Ok(())
}

#[test]
fn parses_file_version() -> Result<(), HeaderParseError> {
    let blk = blank_block!();
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_version()?, "00");
    Ok(())
}

#[test]
fn parses_file_uname() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_field!(blk, field::UNAME, [b'A'; 32]);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_uname()?, "A".repeat(32));
    Ok(())
}

#[test]
fn parses_file_gname() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_field!(blk, field::GNAME, [b'A'; 32]);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_gname()?, "A".repeat(32));
    Ok(())
}

#[test]
fn parses_file_devmajor() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_octal!(blk, field::DEVMAJOR, 0o7752);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_devmajor()?, 0o7752);
    Ok(())
}

#[test]
fn parses_file_devminor() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_octal!(blk, field::DEVMINOR, 0o1457);
    let hdr = HeaderUstar::from_bytes(&finalise(blk))?;
    assert_eq!(hdr.file_devminor()?, 0o1457);
    Ok(())
}

#[test]
fn parses_file_prefix() -> Result<(), HeaderParseError> {
    let mut blk = blank_block!();
    set_string!(blk, field::PREFIX, b"some/path");
    set_string!(blk, field::NAME, b"file.txt");
    let blk = finalise(blk);
    let hdr = HeaderUstar::from_bytes(&blk)?;
    assert_eq!(hdr.full_path()?, "some/path/file.txt");
    Ok(())
}

/*---------------------- Negative/Invalid Tests --------------------------*/
/*-------------------------------TODO -----------------------------------*/