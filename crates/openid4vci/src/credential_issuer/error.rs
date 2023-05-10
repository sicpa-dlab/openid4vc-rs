use crate::jwt::error::JwtError;
use crate::types::credential::CredentialFormatProfile;
use crate::validate::ValidationError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

/// Result type which automatically sets the error type to [`CredentialIssuerError`]
pub type CredentialIssuerResult<T> = std::result::Result<T, CredentialIssuerError>;

/// Error enum for development when an error occurs related to the [`super::CredentialIssuer`] struct.
#[repr(u32)]
#[derive(Error, Debug, PartialEq, Clone, AsRefStr, Serialize)]
#[serde(untagged)]
pub enum CredentialIssuerError {
    /// A wrapper for validation errors
    #[error(transparent)]
    ValidationError(#[from] ValidationError) = 100,

    /// A [`JwtError`] wrapper
    #[error(transparent)]
    JwtError(#[from] JwtError) = 101,

    /// Authorized code flow is currently not supported. The option is already added to supply the
    /// functionality to keep breaking changes to a minimum
    #[error("The Authorized flow is currently not supported")]
    AuthorizedFlowNotSupported = 102,

    /// The credential identifier inside the [`super::CredentialOrIds`] object could not be resolved
    /// with in the [`super::CredentialIssuerMetadata`]
    #[error("The id `{id}` does not refer to a credential format inside the issuer metadata")]
    CredentialIdNotInIssuerMetadata {
        /// Identifier from the credential that could not be found in the `IssuerMetadata`
        id: String,
    } = 103,

    /// The credential identifier inside the [`super::CredentialOrIds`] object could not be resolved
    /// with in the [`super::CredentialIssuerMetadata`]
    #[error("Could not url-encode the credential")]
    InvalidCredentialOfferEncoding {
        /// Error message provided by [`serde_json::to_string`]
        error_message: String,
    } = 104,

    /// Requested credential was not found in the provided issuer metadata
    #[error("Requested credential not found in issuer metadata")]
    InvalidRequestedCredential {
        /// Boxed, for size, requested credential format
        requested_credential: Box<CredentialFormatProfile>,

        /// issuer supported credential formats
        supported_formats: Vec<CredentialFormatProfile>,
    } = 105,

    #[error("`c_nonce_expires_in` is not valid anymore.")]
    ExpiredCNonce {
        /// Timetstamp of now
        now: DateTime<Utc>,

        /// Timestamp of when the `c_nonce` expires
        expires_in: Option<DateTime<Utc>>,
    } = 106,

    /// Either the credential or acceptance token must be supplied
    #[error("Credential and acceptance token cannot both be supplied for the success response")]
    CredentialAndAcceptanceTokenSupplied = 107,

    /// Authorization server metadata is not yet supported
    #[error("Authorization server metadata is not yet supported")]
    AuthorizationServerMetadataNotSupported = 108,

    /// Credential offer must be supplied as that is the only we support right now
    #[error("Credential offer must be supplied, other flows are not supported yet")]
    CredentialOfferMustBeSupplied = 109,

    /// Options were required by the evaluate credential request call
    #[error("evaluate credential request called without options, but were needed")]
    EvaluteCredentialRequestOptionsNotSupplied {
        /// Reason why the options were needed
        reason: String,
    } = 110,

    #[error("c_nonce expires at {expiry_timestamp} which is before {now}")]
    CNonceIsExpired {
        /// Timestamp of now
        now: DateTime<Utc>,

        /// Timestamp of when the nonce expires
        expiry_timestamp: DateTime<Utc>,
    } = 111,
}

error_impl!(CredentialIssuerError, CredentialIssuerResult);

#[cfg(test)]
mod credential_issuer_error_tests {
    use crate::validate::ValidationError;

    use super::*;

    #[test]
    fn should_extract_correct_information_for_validation_error() {
        let validation_error = ValidationError::Any {
            validation_message: "some error".to_owned(),
        };
        let credential_issuer_error: CredentialIssuerError = validation_error.into();
        let error_information = credential_issuer_error.information();

        assert!(error_information.code == 100);
        assert!(error_information.name == "ValidationError");
        assert!(error_information.description == "some error");
        assert!(
            error_information.additional_information
                == Some(serde_json::json!({
                    "validation_message": "some error"
                }))
        );
    }

    #[test]
    fn should_extract_correct_information_for_authorized_flow_not_supported() {
        let error_information = CredentialIssuerError::AuthorizedFlowNotSupported.information();

        assert!(error_information.code == 102);
        assert!(error_information.name == "AuthorizedFlowNotSupported");
        assert!(error_information.description == "The Authorized flow is currently not supported");
        assert!(error_information.additional_information == Some(serde_json::Value::Null));
    }

    #[test]
    fn should_extract_correct_information_for_credential_id_not_in_issuer_metadata() {
        let error_information = CredentialIssuerError::CredentialIdNotInIssuerMetadata {
            id: "cred_id_one".to_owned(),
        }
        .information();

        assert!(error_information.code == 103);
        assert!(error_information.name == "CredentialIdNotInIssuerMetadata");
        assert!(error_information.description == "The id `cred_id_one` does not refer to a credential format inside the issuer metadata");
        assert!(
            error_information.additional_information
                == Some(serde_json::json!({
                    "id": "cred_id_one"
                }))
        );
    }

    #[test]
    fn should_extract_correct_information_for_invalid_credential_offer_encoding() {
        let error_information = CredentialIssuerError::InvalidCredentialOfferEncoding {
            error_message: "invalid encoding".to_owned(),
        }
        .information();

        assert!(error_information.code == 104);
        assert!(error_information.name == "InvalidCredentialOfferEncoding");
        assert!(error_information.description == "Could not url-encode the credential");
        assert!(
            error_information.additional_information
                == Some(serde_json::json!({
                    "error_message": "invalid encoding"
                }))
        );
    }
}
