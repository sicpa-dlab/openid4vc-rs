use thiserror::Error;

use crate::types::{
    credential::CredentialFormatProfile, credential_issuer_metadata::CredentialIssuerMetadata,
};

/// Error enum for development when an error occurs related to the `Credential` struct.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Authorized code flow is currently not supported. The option is already added to supply the
    /// functionality to keep breaking changes to a minimum
    #[error("The Authorized flow is currently not supported")]
    AuthorizedFlowNotSupported,
}

/// Enum that defines a type which may contain a [Credential] type or a string
pub enum CredentialOrUri {
    /// A full nested Credential object
    Credential(Option<CredentialFormatProfile>),

    /// A URI referencing a credential object on the [CredentialIssuerMetadata]
    Uri(Option<String>),
}

/// Field that defined the optional values for when the authorized code flow is used
pub struct AuthorizedCodeFlow {
    /// Issuer state that MUST be the same, if supplied, from the authorization request
    pub issuer_state: Option<String>,
}

/// Field that defines the optional values for when the pre-authorized code flow is used
pub struct PreAuthorizedCodeFlow {
    /// Optional code that will be used in the return value directly
    pub code: Option<String>,

    /// Whether the user must supply a pin later on. The default value `false` here.
    pub user_pin_required: Option<bool>,
}

/// Structure that contains the functionality for the credential issuer
pub struct CredentialIssuer;

impl CredentialIssuer {
    /// Create a credential offer
    ///
    /// ## Errors
    ///
    /// - When the authorized flow option is supplied
    pub fn create_offer(
        _issuer_metadata: &CredentialIssuerMetadata,
        _credentials: &[&CredentialOrUri],
        _credential_offer_endpoint: &Option<String>,
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        _pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> Result<(), Error> {
        if authorized_code_flow.is_some() {
            return Err(Error::AuthorizedFlowNotSupported);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test_credential {
    use super::*;

    #[test]
    fn should_error_when_using_authorized_flow() {
        let result = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            &[],
            &Some(String::default()),
            &Some(AuthorizedCodeFlow { issuer_state: None }),
            &None,
        );
        let expect = Err(Error::AuthorizedFlowNotSupported);
        assert_eq!(result, expect);
    }
}
