use openid4vci::{
    access_token::error::AccessTokenError, credential_issuer::error::CredentialIssuerError,
    error_impl, validate::ValidationError,
};
use serde::Serialize;
use thiserror::Error;
use tonic::{Code, Status};

use crate::utils::serialize_to_optional_slice;

/// Generic `gRPC` error that wraps errors from the [`openid4vci`] crate
#[derive(Error, Debug, Serialize)]
#[serde(untagged)]
pub enum GrpcError {
    /// [`CredentialIssuerError`] wrapper
    #[error(transparent)]
    CredentialIssuerError(#[from] CredentialIssuerError),

    /// [`AccessTokenError`] wrapper
    #[error(transparent)]
    AccessTokenError(#[from] AccessTokenError),

    /// [`ValidationError`] wrapper
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
}

impl AsRef<str> for GrpcError {
    fn as_ref(&self) -> &str {
        match self {
            GrpcError::CredentialIssuerError(e) => e.as_ref(),
            GrpcError::AccessTokenError(e) => e.as_ref(),
            GrpcError::ValidationError(e) => e.as_ref(),
        }
    }
}

/// Result type which automatically sets the error type to [`GrpcError`]
pub(crate) type GrpcResult<T> = std::result::Result<T, Status>;

error_impl!(GrpcError);

impl TryFrom<GrpcError> for crate::grpc_openid4vci::Error {
    type Error = GrpcError;

    fn try_from(value: GrpcError) -> Result<Self, Self::Error> {
        let information = value.information();
        let additional_information =
            serialize_to_optional_slice(information.additional_information)?;
        Ok(crate::grpc_openid4vci::Error {
            code: information.code,
            name: information.name,
            description: information.description,
            additional_information,
        })
    }
}

impl From<GrpcError> for Status {
    fn from(value: GrpcError) -> Self {
        let info = match value {
            GrpcError::CredentialIssuerError(e) => e.information(),
            GrpcError::AccessTokenError(e) => e.information(),
            GrpcError::ValidationError(e) => e.information(),
        };
        let (code, message) = match serde_json::to_string(&info) {
            Ok(m) => (Code::InvalidArgument, m),
            Err(e) => (Code::Internal, e.to_string()),
        };

        Self::new(code, message)
    }
}
