mod header;
mod error;

use header::HeaderUstar;

fn main() {
    let mut block = [0u8; 512];

    let name_bytes = b"test_file.txt";
    block[..name_bytes.len()].copy_from_slice(name_bytes);


    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");

    match HeaderUstar::from_bytes(&block) {
        Ok(header) => {
            match header.file_name() {
                Ok(name) => println!("Parsed file name: {}", name),
                Err(e) => eprintln!("File name parse error: {:?}", e),
            }
        }
        Err(e) => {
            eprintln!("Header parse error: {:?}", e);
        } 
    }
}

