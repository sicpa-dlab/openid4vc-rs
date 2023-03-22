use serde::Serialize;
use thiserror::Error;

/// Result type which automatically sets the error type to [`CredentialIssuerError`]
pub type Result<T> = std::result::Result<T, CredentialIssuerError>;

/// Error enum for development when an error occurs related to the [`super::CredentialIssuer`] struct.
#[repr(u32)]
#[derive(Error, Debug, PartialEq, Clone, AsRefStr, Serialize)]
#[serde(untagged)]
pub enum CredentialIssuerError {
    /// Authorized code flow is currently not supported. The option is already added to supply the
    /// functionality to keep breaking changes to a minimum
    #[error("The Authorized flow is currently not supported")]
    AuthorizedFlowNotSupported = 100,

    /// The credential identifier inside the [`super::CredentialOrIds`] object could not be resolved
    /// with in the [`super::CredentialIssuerMetadata`]
    #[error("The id `{id}` does not refer to a credential format inside the issuer metadata")]
    CredentialIdNotInIssuerMetadata {
        /// Identifier from the credential that could not be found in the `IssuerMetadata`
        id: String,
    } = 101,

    /// The credential identifier inside the [`super::CredentialOrIds`] object could not be resolved
    /// with in the [`super::CredentialIssuerMetadata`]
    #[error("Could not url-encode the credential")]
    InvalidCredentialOfferEncoding {
        /// Error message provided by [`serde_json::to_string`]
        error_message: String,
    } = 102,

    #[error("An error occurred during serialization")]
    SerializationError {
        /// Serialization error from serde
        error_message: String,
    } = 103,

    #[error("An error occurred during deserialization")]
    DeserializationError {
        /// Deserialization error from serde
        error_message: String,
    } = 104,
}

error_impl!(CredentialIssuerError);

#[cfg(test)]
mod credential_issuer_error_tests {
    use super::*;

    #[test]
    fn should_extract_correct_information_for_authorized_flow_not_supported() {
        let error_information = CredentialIssuerError::AuthorizedFlowNotSupported.information();

        assert!(error_information.code == 100);
        assert!(error_information.name == "AuthorizedFlowNotSupported");
        assert!(error_information.description == "The Authorized flow is currently not supported");
        assert!(error_information.additional_information == serde_json::Value::Null);
    }

    #[test]
    fn should_extract_correct_information_for_credential_id_not_in_issuer_metadata() {
        let error_information = CredentialIssuerError::CredentialIdNotInIssuerMetadata {
            id: "cred_id_one".to_owned(),
        }
        .information();

        assert!(error_information.code == 101);
        assert!(error_information.name == "CredentialIdNotInIssuerMetadata");
        assert!(error_information.description == "The id `cred_id_one` does not refer to a credential format inside the issuer metadata");
    }

    #[test]
    fn should_extract_correct_information_for_invalid_credential_offer_encoding() {
        let error_information = CredentialIssuerError::InvalidCredentialOfferEncoding {
            error_message: "invalid encoding".to_owned(),
        }
        .information();

        assert!(error_information.code == 102);
        assert!(error_information.name == "InvalidCredentialOfferEncoding");
        assert!(error_information.description == "Could not url-encode the credential");
    }
}
