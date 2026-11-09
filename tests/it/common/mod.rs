//! Shared fixtures of the integration tests.
#![allow(dead_code)]
#[allow(unused_imports)]
pub use czkp::reference::catalogue;
use czkp::standing::Params;

/// The reference community's parameters.
pub fn reference() -> Params {
    czkp::reference::params()
}
