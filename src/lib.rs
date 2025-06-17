//! Public library entry-point for tar header parsing logic.

pub mod header;          
pub mod error;           

// Re-export the main types so test code can write `tarpit::HeaderUstar`
pub use header::{HeaderUstar, TypeFlags};
pub use error::HeaderParseError;

