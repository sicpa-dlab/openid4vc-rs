use openid4vci::{
    access_token::error::AccessTokenError, credential_issuer::error::CredentialIssuerError,
    error_impl, validate::ValidationError,
};
use serde::Serialize;
use thiserror::Error;
use tonic::{Code, Status};

/// Generic `gRPC` error that wraps errors from the [`openid4vci`] crate
#[derive(Error, Debug, AsRefStr, Serialize)]
pub enum GrpcError {
    /// [`CredentialIssuerError`] wrapper
    #[error(transparent)]
    CredentialIssuerError(#[from] CredentialIssuerError),

    /// [`AccessToken`] wrapper
    #[error(transparent)]
    AccessTokenError(#[from] AccessTokenError),

    /// [`ValidationError`] wrapper
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
}

error_impl!(GrpcError);

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

/// Result type which automatically sets the error type to [`GrpcError`]
pub(crate) type Result<T> = std::result::Result<T, Status>;
