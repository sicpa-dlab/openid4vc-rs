use openid4vci::{
    access_token::error::AccessTokenError, credential_issuer::error::CredentialIssuerError,
    error_impl,
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

    #[error("Unable to serialize the response")]
    UnableToSerialize { message: String },

    #[error("Unable to deserialize the input of `{item}`")]
    UnableToDeserialize { item: String, bytes: Vec<u8> },
}

error_impl!(GrpcError);

impl From<GrpcError> for Status {
    fn from(value: GrpcError) -> Self {
        let info = match value {
            GrpcError::CredentialIssuerError(e) => e.information(),
            GrpcError::AccessTokenError(e) => e.information(),
            // FIXME: How to get information? What should be returned here?
            GrpcError::UnableToDeserialize { bytes, item } => {
                return Self::new(
                    Code::Internal,
                    format!("Unable to deserialize the input of `{}`", item),
                )
            }
            GrpcError::UnableToSerialize { message } => return Self::new(Code::Internal, message),
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
