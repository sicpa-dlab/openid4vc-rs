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
pub mod macros;

#[macro_use]
extern crate strum;

pub use ssi_dids::Document;

/// Error module that contains a serializable, complex error object that can be send of over FFI,
/// HTTP, `gRPC`, etc.
pub mod error;

/// Module that contains the functionality related to the access token endpoint
pub mod access_token;

/// Module that contains the functionality related to the credential issuance
pub mod credential_issuer;

/// Module that contains some meta types that will be extracted later on
pub mod types;

/// Module containing a struct for json web tokens, specific for openid4vci
pub mod jwt;

/// Module that contains traits for validation on strutuctures
pub mod validate;

/// Module for base64, base64url and base58 encoding
mod base;

/// Module for a generic error response
mod error_response;
