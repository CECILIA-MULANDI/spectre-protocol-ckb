#![no_std]
extern crate alloc;

pub use molecule::prelude;

include!(concat!(env!("OUT_DIR"), "/agent-record.rs"));
