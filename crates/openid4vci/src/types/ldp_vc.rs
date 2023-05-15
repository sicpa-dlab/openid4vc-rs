use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::credential::{CredentialSubject, LinkedDataContext};

/// The Credential format identifier is `ldp_vc`.
pub const CREDENTIAL_FORMAT_IDENTIFIER: &str = "ldp_vc";

/// The following additional Credential Issuer metadata are defined for this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssuerMetadata {
    /// JSON array as defined in [VC_DATA](https://www.w3.org/TR/vc-data-model), Section 4.1.
    #[serde(rename = "@context")]
    pub context: Vec<LinkedDataContext>,

    ///  JSON array designating the types a certain credential type supports according to
    ///  [VC_DATA](https://www.w3.org/TR/vc-data-model), Section 4.3.
    pub types: Vec<String>,

    /// A JSON object containing a list of key value pairs, where the key identifies the claim
    /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
    /// full (potentially deeply nested) structure of the verifiable credential to be issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<HashMap<String, CredentialSubject>>,

    /// An array of claims.display.name values that lists them in the order they should be
    /// displayed by the Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
}

/// The following additional claims are defined for this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOffer {
    /// JSON object containing (and isolating) the detailed description of the credential type. This
    /// object MUST be processed using full JSON-LD processing.
    pub credential_definition: CredentialDefinition,
}

/// The following additional claims are defined for authorization details of type
/// `openid_credential` and this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationDetails {
    /// JSON object containing (and isolating) the detailed description of the credential type. This
    /// object MUST be processed using full JSON-LD processing.
    pub credential_definition: CredentialDefinition,
}

/// The following additional claims are defined for authorization details of type
/// `openid_credential` and this Credential format.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// JSON object containing (and isolating) the detailed description of the credential type. This
    /// object MUST be processed using full JSON-LD processing.
    pub credential_definition: CredentialDefinition,
}

/// JSON object containing (and isolating) the detailed description of the credential type. This
/// object MUST be processed using full JSON-LD processing.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinition {
    /// JSON array as defined in [VC_DATA](https://www.w3.org/TR/vc-data-model), Section 4.1.
    #[serde(rename = "@context")]
    pub context: Vec<LinkedDataContext>,

    ///  JSON array designating the types a certain credential type supports according to
    ///  [VC_DATA](https://www.w3.org/TR/vc-data-model), Section 4.3.
    pub types: Vec<String>,
}

/// The value of the credential claim in the Credential Response MUST be a JSON object. Credentials
/// of this format MUST NOT be re-encoded.
///
/// TODO: determine correct inner type
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialResponse(serde_json::Value);

#[cfg(test)]
mod test_ldp_vc {
    use crate::types::{
        credential_issuer_metadata::{CredentialIssuerMetadataFormat, CredentialSupported},
        ldp_vc,
    };

    fn valid_ldp_vc_format() -> serde_json::Value {
        serde_json::json!({
            "format": "ldp_vc",
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ],
            "cryptographic_binding_methods_supported": [
                "did"
            ],
            "cryptographic_suites_supported": [
                "Ed25519Signature2018"
            ],
            "display": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ],
            "credentialSubject": {
                "given_name": {
                    "display": [
                        {
                            "name": "Given Name",
                            "locale": "en-US"
                        }
                    ]
                },
                "last_name": {
                    "display": [
                        {
                            "name": "Surname",
                            "locale": "en-US"
                        }
                    ]
                },
                "degree": {},
                "gpa": {
                    "display": [
                        {
                            "name": "GPA"
                        }
                    ]
                }
            }
        })
    }

    #[test]
    fn should_deserialize_from_example() {
        let j = valid_ldp_vc_format();

        let ldp_vc_supported_credential: CredentialSupported =
            serde_json::from_value(j).expect("Unable to deserialize supported credential");

        assert!(matches!(
            ldp_vc_supported_credential.format,
            CredentialIssuerMetadataFormat::LdpVc(ldp_vc::CredentialIssuerMetadata { .. })
        ));
    }

    #[test]
    fn should_round_trip() {
        let j = valid_ldp_vc_format();

        let ldp_vc_supported_credential: CredentialSupported =
            serde_json::from_value(j.clone()).expect("Unable to deserialize supported credential");

        let j_roundtrip =
            serde_json::to_value(ldp_vc_supported_credential).expect("Unable to serialize ldp_vc");

        assert_eq!(j, j_roundtrip);
    }
}
