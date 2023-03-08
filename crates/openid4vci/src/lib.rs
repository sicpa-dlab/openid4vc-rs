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

/// Module that contains the functionality related to the token endpoint
pub mod access_token;

/// Module containing a single struct for the issuer metadata
pub mod credential_issuer_metadata;
