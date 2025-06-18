# tarpit

[![Build & Tests](https://github.com/cachebag/tarpit/actions/workflows/CI.yaml/badge.svg)](https://github.com/cachebag/tarpit/actions/workflows/CI.yaml)
<br>
<br>
`tarpit` is a minimal parser for POSIX `ustar` TAR headers, implemented in Rust. It focuses on interpreting raw 512-byte blocks according to the `ustar` specification.

*Note: This parser intentionally rejects non-`ustar` formats. This is just meant as an exercise, please proceed with caution when using this code on any real TAR files (you really shouldn't be doing so anyways).*

Reference:
- POSIX.1-1988 `ustar` format: [https://pubs.opengroup.org/onlinepubs/009695399/utilities/pax.html](https://pubs.opengroup.org/onlinepubs/009695399/utilities/pax.html)
- GNU tar format overview: [https://www.gnu.org/software/tar/manual/html_node/Standard.html](https://www.gnu.org/software/tar/manual/html_node/Standard.html)

## Usage

To parse a 512-byte TAR header:

```rust
use tarpit::HeaderUstar;

let blk: [u8; 512] = /* your TAR header block */;
let header = HeaderUstar::from_bytes(&blk)?;
println!("File name: {}", header.file_name()?);
println!("Size: {}", header.file_size()?);
/*-----Rest of accessors...-----*/
