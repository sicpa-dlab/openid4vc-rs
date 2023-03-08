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

/// Container for both the authorized Code Flow an the pre-authorized code flow options.
pub enum CodeFlow {
    /// Field that defined the optional values for when the authorized code flow is used
    Authorized {
        /// Issuer state that MUST be the same, if supplied, from the authorization request
        issuer_state: Option<String>,
    },

    /// Field that defines the optional values for when the pre-authorized code flow is used
    PreAuthorized {
        /// Optional code that will be used in the return value directly
        code: Option<String>,

        /// Whether the user must supply a pin later on. The default value `false` here.
        user_pin_required: Option<bool>,
    },
}

/// Create a credential offer
///
/// ## Errors
///
/// - When the authorized flow option is supplied
/// - When pre-authorized and authorized are supplied
pub fn create_credential_offer(
    _issuer_metadata: &CredentialIssuerMetadata,
    _credentials: &[&CredentialOrUri],
    _credential_offer_endpoint: &Option<String>,
    supported_code_flow: CodeFlow,
) -> Result<(), Error> {
    let (_, _) = match supported_code_flow {
        CodeFlow::Authorized { issuer_state: _ } => return Err(Error::AuthorizedFlowNotSupported),
        CodeFlow::PreAuthorized {
            code,
            user_pin_required,
        } => (code, user_pin_required),
    };

    Ok(())
}

#[cfg(test)]
mod test_credential {
    use super::*;

    #[test]
    fn should_error_when_using_authorized_flow() {
        let result = create_credential_offer(
            &CredentialIssuerMetadata::default(),
            &[],
            &Some(String::default()),
            CodeFlow::Authorized { issuer_state: None },
        );
        let expect = Err(Error::AuthorizedFlowNotSupported);
        assert_eq!(result, expect);
    }
}
