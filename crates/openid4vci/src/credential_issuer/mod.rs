use self::error::CredentialIssuerError;
use self::error::Result;
use crate::types::credential::CredentialFormatProfile;
use crate::types::credential_issuer_metadata::CredentialIssuerMetadata;

/// Error module for the credential issuance module
pub mod error;

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
    ) -> Result<()> {
        if authorized_code_flow.is_some() {
            return Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test_credential {
    use crate::credential_issuer::error::CredentialIssuerError;

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
        let expect = Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        assert_eq!(result, expect);
    }
}
