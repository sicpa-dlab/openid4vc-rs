use serde::Serialize;
use thiserror::Error;

/// Result type which automatically sets the error type to `CredentialIssuerError`
pub type Result<T> = std::result::Result<T, CredentialIssuerError>;

/// Error enum for development when an error occurs related to the `Credential` struct.
#[repr(u32)]
#[derive(Error, Debug, PartialEq, Clone, AsRefStr, Serialize)]
#[serde(untagged)]
pub enum CredentialIssuerError {
    /// Authorized code flow is currently not supported. The option is already added to supply the
    /// functionality to keep breaking changes to a minimum
    #[error("The Authorized flow is currently not supported")]
    AuthorizedFlowNotSupported = 100,
}

error_impl!(CredentialIssuerError);

#[cfg(test)]
mod credential_issuer_error_tests {
    use super::*;

    #[test]
    fn should_extract_correct_information() {
        let error_information = CredentialIssuerError::AuthorizedFlowNotSupported.information();

        assert!(error_information.code == 100);
        assert!(error_information.name == "AuthorizedFlowNotSupported");
        assert!(error_information.description == "The Authorized flow is currently not supported");
    }
}
