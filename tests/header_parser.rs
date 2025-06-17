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

