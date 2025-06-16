mod header;
mod error;

use header::HeaderUstar;
use header::HeaderParseError;

fn main() -> Result<(), HeaderParseError>{
    println!("Hello Tarpit!\n");

    let mut block = [0u8; 512];

    let dummy_text = b"test_file.txt";
    block[..dummy_text.len()].copy_from_slice(dummy_text);

    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");

    block[156] = b'0';

    block[124..133].copy_from_slice(b"00000123\0");

    let header = HeaderUstar::from_bytes(&block)?;

    println!("name      : {}", header.file_name()?);
    println!("size (dec): {}", header.file_size()?);
    println!("typeflag  : {:?}", header.file_type()?);

    Ok(())
}

