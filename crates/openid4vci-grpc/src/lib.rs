#![doc = include_str!("../../../README.md")]

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
pub use grpc_openid4vci::{
    create_access_token_error_response_response, create_access_token_success_response_response,
    create_credential_offer_response, evaluate_access_token_request_response,
    pre_evaluate_credential_request_response, CreateCredentialOfferRequest,
    CreateCredentialOfferResponse, EvaluateCredentialRequestRequest,
    EvaluateCredentialRequestResponse, PreEvaluateCredentialRequestRequest,
    PreEvaluateCredentialRequestResponse,
};

pub use grpc_openid4vci::access_token_service_client as access_token_client;
pub use grpc_openid4vci::access_token_service_server as access_token_server;
pub use grpc_openid4vci::{
    CreateAccessTokenErrorResponseRequest, CreateAccessTokenErrorResponseResponse,
    CreateAccessTokenSuccessResponseRequest, CreateAccessTokenSuccessResponseResponse,
};
