use serde::Serialize;
use thiserror::Error;

use crate::validate::ValidationError;

/// Result type which automatically sets the error type to [`AccessTokenError`]
pub type AccessTokenResult<T> = std::result::Result<T, AccessTokenError>;

/// Error enum for development when an error occurs related to the [`super::AccessToken`] struct.
// TODO: Enable when we add an item to the enum
#[repr(u32)]
#[derive(Error, Debug, PartialEq, Clone, AsRefStr, Serialize)]
#[serde(untagged)]
pub enum AccessTokenError {
    /// A wrapper for validation errors
    #[error(transparent)]
    ValidationError(#[from] ValidationError) = 400,

    #[error("Invalid requested grant type")]
    InvalidGrantType {
        /// Requested grant type in the access token request
        requested_grant_type: String,

        /// Accepted grant type(s) in the [`crate::credential_issuer::CredentialOffer`]
        accepted_grant_type: Vec<String>,
    } = 401,

    /// Authorized code flow is currently not supported. The option is already added to supply the
    /// functionality to keep breaking changes to a minimum
    #[error("The Authorized flow is currently not supported")]
    AuthorizedFlowNotSupported = 402,

    #[error("Supplied credential offer has no authorized, or pre-authorized, code flow")]
    NoFlowSupportedInCredentialOffer = 403,

    #[error("Requested pre-authorized code flow has invalid values")]
    InvalidPreAuthorizedCodeFlowValues {
        should_pin_be_supplied: bool,
        does_code_match: bool,
    } = 404,

    #[error("Both the authorized and pre-authorized are incorrect")]
    InvalidAuthorizedAndPreAuthorizedCodeFlow {
        authorized_error: Box<Self>,
        pre_authorized_error: Box<Self>,
    } = 405,

    #[error("Options are required when evaluating the access token request")]
    OptionsAreRequiredForEvaluation { reason: String } = 406,

    #[error("Provided user pin does not match user pin from access token request")]
    UserPinMismatch = 407,

    #[error("Access token request is not yet supported without a credential offer")]
    CredentialOfferMustBeSupplied = 409,
}

error_impl!(AccessTokenError, AccessTokenResult);

#[cfg(test)]
mod access_token_error_tests {
    // TODO: add test when we add errors to the enum
}
