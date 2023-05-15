use super::credential::CredentialSubject;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The Credential format identifier is `jwt_vc_json`.
pub const CREDENTIAL_FORMAT_IDENTIFIER: &str = "jwt_vc_json";

/// The following additional Credential Issuer metadata are defined for this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuerMetadata {
    ///  JSON array designating the types a certain credential type supports according to
    ///  [VC_DATA](https://www.w3.org/TR/vc-data-model), Section 4.3.
    pub types: Vec<String>,

    /// A JSON object containing a list of key value pairs, where the key identifies the claim
    /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
    /// full (potentially deeply nested) structure of the verifiable credential to be issued.
    pub credential_subject: HashMap<String, CredentialSubject>,

    /// An array of claims.display.name values that lists them in the order they should be
    /// displayed by the Wallet.
    pub order: Option<Vec<String>>,
}

/// The following additional claims are defined for this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOffer {
    /// JSON array as defined in [Appendix E.1.1.2 of the openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#server_metadata_jwt_vc_json).
    /// This claim contains the type values the Wallet shall request in the subsequent Credential
    /// Request.
    pub types: Vec<String>,
}

/// The following additional claims are defined for authorization details of type `openid_credential`
/// and this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationDetails {
    ///  JSON array as defined in [Appendix E.1.1.2 of the openid4vci
    ///  specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#server_metadata_jwt_vc_json).
    ///  This claim contains the type values the Wallet requests authorization for at the issuer.
    pub types: Vec<String>,

    /// A JSON object containing a list of key value pairs, where the key identifies the claim
    /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
    /// full (potentially deeply nested) structure of the verifiable credential to be issued.
    pub credential_subject: HashMap<String, CredentialSubject>,
}

/// The following additional parameters are defined for Credential Requests and this Credential
/// format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    ///  JSON array as defined in [Appendix E.1.1.2 of the openid4vci
    ///  specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#server_metadata_jwt_vc_json).
    ///  This claim contains the type values the Wallet requests authorization for at the issuer.
    pub types: Vec<String>,

    /// A JSON object containing a list of key value pairs, where the key identifies the claim
    /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
    /// full (potentially deeply nested) structure of the verifiable credential to be issued.
    pub credential_subject: HashMap<String, CredentialSubject>,
}

/// The value of the credential claim in the Credential Response MUST be a JSON string. Credentials
/// of this format are already a sequence of base64url-encoded values separated by period
/// characters and MUST NOT be re-encoded.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialResponse(String);

impl From<CredentialResponse> for String {
    fn from(response: CredentialResponse) -> Self {
        response.0
    }
}
