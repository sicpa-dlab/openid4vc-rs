//! [`gRPC`](https://grpc.io) wrapper around the [`openid4vci`] crate.
//!
//! This exposes the main functionality from the [`openid4vci`] crate. Please refer to
//! [client.rs](./client.rs) for a client example and [server.rs](./server.rs) for a server
//! example.

#[macro_use]
extern crate strum;

/// Credential issuer module which wraps [`openid4vci::credential_issuer`]
mod credential_issuer;
pub use credential_issuer::*;

/// Access token module which wraps [`openid4vci::access_token`]
mod access_token;
pub use access_token::*;

/// Error module that contains the code to convert any [`openid4vci`] error into an error that is
/// meant for `gRPC`
pub mod error;

/// Generated `gRPC` module based on the [protofbuf definition](../proto/openid4vci.proto).
/// Generation is done by [`tonic`], which uses [`prost`].
///
/// Clippy is disabled here as we can not directly control the generated code.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::missing_docs_in_private_items
)]
mod grpc_openid4vci {
    tonic::include_proto!("openid4vci");
}

/// Module for utilities regarding `gRPC`
mod utils;

pub use grpc_openid4vci::credential_issuer_service_client as credential_issuer_client;
pub use grpc_openid4vci::credential_issuer_service_server as credential_issuer_server;
pub use grpc_openid4vci::{CreateOfferRequest, CreateOfferResponse};

pub use grpc_openid4vci::access_token_service_client as access_token_client;
pub use grpc_openid4vci::access_token_service_server as access_token_server;
pub use grpc_openid4vci::{
    CreateAccessTokenErrorResponseRequest, CreateAccessTokenErrorResponseResponse,
};
