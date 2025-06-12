mod header;
mod error;

fn main() {
    println!("Hello World!");

    let block = [0u8; 512]; // define a dummy block for test
    let result = header::HeaderUstar::from_bytes(&block);
    let test = header::test();
    println!("{:?}", result);
    println!("{:#?}", test);
}

