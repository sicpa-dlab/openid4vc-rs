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

    /// Supplied credential offer has no supported code flows
    #[error("Supplied credential offer has no authorized, or pre-authorized, code flow")]
    NoFlowSupportedInCredentialOffer = 403,

    /// The requested pre-authorized code flow has invalid values
    #[error("Requested pre-authorized code flow has invalid values")]
    InvalidPreAuthorizedCodeFlowValues {
        /// Whether the pin should be supplied in the input
        should_pin_be_supplied: bool,

        /// Whether the pre-authorized code flow code matches
        does_code_match: bool,
    } = 404,

    /// Both the authorized and pre-authorized code flow errored out
    #[error("Both the authorized and pre-authorized are incorrect")]
    InvalidAuthorizedAndPreAuthorizedCodeFlow {
        /// Why the authorized code flow errored
        authorized_error: Box<Self>,
        /// Why the pre authorized code flow errored
        pre_authorized_error: Box<Self>,
    } = 405,

    /// Options must be supplied to some specific evaluate functionality
    #[error("Options are required when evaluating the access token request")]
    OptionsAreRequiredForEvaluation {
        /// Reason why the options were required for evaluation
        reason: String,
    } = 406,

    /// supplied user pin and provided user pin do not match
    #[error("Provided user pin does not match user pin from access token request")]
    UserPinMismatch = 407,

    /// Currently, credential offer is the only supported flow
    #[error("Access token request is not yet supported without a credential offer")]
    CredentialOfferMustBeSupplied = 409,
}

error_impl!(AccessTokenError, AccessTokenResult);

#[cfg(test)]
mod access_token_error_tests {
    // TODO: add test when we add errors to the enum
}
