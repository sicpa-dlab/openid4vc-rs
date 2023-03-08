use thiserror::Error;

use crate::types::{credential::Credential, credential_issuer_metadata::CredentialIssuerMetadata};

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
    Credential(Option<Credential>),

    /// A URI referencing a credential object on the [CredentialIssuerMetadata]
    Uri(Option<String>),
}

/// Structure that defines the optional values for when the pre-authorized code flow is used
pub struct PreAuthorized {
    /// Optional code that will be used in the return value directly
    pub code: Option<String>,

    /// Whether the user must supply a pin later on. The default value `false` here.
    pub user_pin_required: Option<bool>,
}

/// Structure that defined the optional values for when the authorized code flow is used
pub struct Authorized {
    /// Issuer state that MUST be the same, if supplied, from the authorization request
    pub issuer_state: Option<String>,
}

/// Create a credential offer
///
/// ## Errors
pub fn create_offer(
    _issuer_metadata: &CredentialIssuerMetadata,
    _credentials: &[&CredentialOrUri],
    _credential_offer_endpoint: &Option<String>,
    _pre_authorized: &Option<PreAuthorized>,
    authorized: &Option<Authorized>,
) -> Result<(), Error> {
    if authorized.is_some() {
        return Err(Error::AuthorizedFlowNotSupported);
    }
    Ok(())
}

#[cfg(test)]
mod test_credential {
    use super::*;

    #[test]
    fn should_error_when_using_authorized_flow() {
        let result = create_offer(
            &CredentialIssuerMetadata::default(),
            &[],
            &Some(String::default()),
            &None,
            &Some(Authorized { issuer_state: None }),
        );
        let expect = Err(Error::AuthorizedFlowNotSupported);
        assert_eq!(result, expect);
    }
}
