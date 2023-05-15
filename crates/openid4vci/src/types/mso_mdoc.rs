use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::credential::CredentialSubject;

/// The Credential format identifier is `mso_mdoc`.
pub const CREDENTIAL_FORMAT_IDENTIFIER: &str = "mso_mdoc";

/// The following additional Credential Issuer metadata are defined for this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuerMetadata {
    /// JSON string identifying the credential type.
    pub doctype: String,

    /// A JSON object containing a list of key value pairs, where the key is a certain namespace as
    /// defined in [ISO.18013-5](https://www.iso.org/standard/69084.html) (or any profile of it),
    /// and the value is a JSON object. This object also contains a list of key value pairs, where
    /// the key is a claim that is defined in the respective namespace and is offered in the
    /// Credential.
    pub claims: HashMap<String, CredentialSubject>,

    /// An array of claims.display.name values that lists them in the order they should be
    /// displayed by the Wallet.
    pub order: Option<Vec<String>>,
}

/// The following additional claims are defined for this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOffer {
    /// JSON string identifying the credential type.
    pub doctype: String,
}

/// The following additional claims are defined for authorization details of type
/// `openid_credential` and this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationDetails {
    /// JSON string identifying the credential type.
    pub doctype: String,

    /// A JSON object containing a list of key value pairs, where the key is a certain namespace as
    /// defined in [ISO.18013-5](https://www.iso.org/standard/69084.html) (or any profile of it),
    /// and the value is a JSON object. This object also contains a list of key value pairs, where
    /// the key is a claim that is defined in the respective namespace and is offered in the
    /// Credential.
    pub claims: HashMap<String, CredentialSubject>,
}

/// The following additional parameters are defined for Credential Requests and this Credential
/// format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// JSON string identifying the credential type.
    pub doctype: String,

    /// A JSON object containing a list of key value pairs, where the key is a certain namespace as
    /// defined in [ISO.18013-5](https://www.iso.org/standard/69084.html) (or any profile of it),
    /// and the value is a JSON object. This object also contains a list of key value pairs, where
    /// the key is a claim that is defined in the respective namespace and is offered in the
    /// Credential.
    pub claims: HashMap<String, CredentialSubject>,
}

/// The value of the credential claim in the Credential Response MUST be a JSON string that is the base64url-encoded representation of the issued Credential.
pub struct CredentialResponse(String);

impl From<CredentialResponse> for String {
    fn from(response: CredentialResponse) -> Self {
        response.0
    }
}
