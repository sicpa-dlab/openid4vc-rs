use openid4vci::{credential_issuer::error::CredentialIssuerError, error_impl};
use serde::Serialize;
use thiserror::Error;
use tonic::{Code, Status};

/// Generic `gRPC` error that wraps errors from the [`openid4vci`] crate
#[derive(Error, Debug, AsRefStr, Serialize)]
pub enum GrpcError {
    /// [`CredentialIssuerError`] wrapper
    #[error(transparent)]
    CredentialIssuerError(#[from] CredentialIssuerError),
}

error_impl!(GrpcError);

impl From<GrpcError> for Status {
    fn from(value: GrpcError) -> Self {
        let info = match value {
            GrpcError::CredentialIssuerError(e) => e.information(),
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
