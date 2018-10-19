//! # Urkel-rs
//!
//! An implementation of an [Urkel (Merkle) Tree](https://handshake.org/files/handshake.txt),
//!
//!
extern crate byteorder;
extern crate rand;
extern crate tiny_keccak;

mod hashutils;
mod metadata;
mod nodes;
pub mod proof;
mod store;
pub mod tree;

use std::io::Error;
use std::result;

/// Result type used across project
pub type Result<T> = result::Result<T, Error>;
