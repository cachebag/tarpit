// Minimal header testing on a zero-filled block
use std::io::Write;
use tarpit::{HeaderUstar, HeaderParseError};

fn blank_block() -> [u8; 512] { [0u8; 512] }

/// Helper that writes magic, version and checksum.
fn finalise_block(mut blk: [u8; 512]) -> [u8; 512] {
    blk[257..263].copy_from_slice(b"ustar\0"); // magic
    blk[263..265].copy_from_slice(b"00"); // file version
    for b in &mut blk[148..156] { *b = b' '; } // checksum
    let sum: u32 = blk.iter().map(|&b| b as u32).sum();
    write!(&mut blk[148..156], "{:06o}\0 ", sum).unwrap();
    blk
}

#[test]
fn parses_file_name() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[..13].copy_from_slice(b"test_file.txt");
    let hdr = HeaderUstar::from_bytes(&finalise_block(blk))?;
    assert_eq!(hdr.file_name()?, "test_file.txt");
    Ok(())
}

#[test]
fn parses_file_mode() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[100..108].copy_from_slice(b"0000777\0");
    let hdr = HeaderUstar::from_bytes(&finalise_block(blk))?;
    assert_eq!(hdr.file_mode()?, 0o777);
    Ok(())
}

#[test]
fn parses_file_uid() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[108..116].copy_from_slice(b"0001741\0");
    let hdr = HeaderUstar::from_bytes(&finalise_block(blk))?;
    assert_eq!(hdr.file_uid()?, 0o1741);
    Ok(())
}

#[test]
fn parses_file_gid() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[116..124].copy_from_slice(b"0005710\0");
    let hdr = HeaderUstar::from_bytes(&finalise_block(blk))?;
    assert_eq!(hdr.file_gid()?, 0o5710);
    Ok(())
}

#[test]
fn parses_file_size() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[124..136].copy_from_slice(b"10000000000\0"
);
    let hdr = HeaderUstar::from_bytes(&finalise_block(blk))?;
    assert_eq!(hdr.file_size()?, 0o10000000000);
    Ok(())
}

#[test]
fn parses_file_mtime() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[136..148].copy_from_slice(b"07347410350\0"); 
    let hdr = HeaderUstar::from_bytes(&finalise_block(blk))?;
    assert_eq!(hdr.file_mtime()?, 1000214760);        
    Ok(())
}


#[test]
fn parses_file_chksum() -> Result<(), HeaderParseError> {
    let mut blk = blank_block();
    blk[0..9].copy_from_slice(b"file.txt\0");
    blk[257..263].copy_from_slice(b"ustar\0");
    blk[263..265].copy_from_slice(b"00");

    for b in &mut blk[148..156] {
        *b = b' ';
    }

    let sum: u64 = blk.iter().map(|&b| b as u64).sum();

    let chksum_field = format!("{:06o}\0 ", sum);
    blk[148..156].copy_from_slice(chksum_field.as_bytes());

    let hdr = HeaderUstar::from_bytes(&blk)?;

    assert_eq!(hdr.file_chksum()?, sum);

    Ok(())
}


