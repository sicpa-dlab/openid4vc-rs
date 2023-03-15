//! [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) implementation as a library.
//!
//! This library contains the following modules:
//!
//! ### Access Token
//!
//! The access token module contains the code to do the following:
//!
//! - evaluate requests
//! - generate success responses
//! - generate error responses
//!

/// Macros for the openid4vci-rs crate
#[macro_use]
mod macros;

#[macro_use]
extern crate strum;

/// Error module that contains an serialize, complex error object that can be send of over FFI,
/// HTTP, `gRPC`, etc.
pub mod error;

/// Module that contains the functionality related to the access token endpoint
pub mod access_token;

/// Module that contains the functionality related to the credential issuance
pub mod credential_issuer;

/// Module that contains some meta types that will be extracted later on
pub mod types;
