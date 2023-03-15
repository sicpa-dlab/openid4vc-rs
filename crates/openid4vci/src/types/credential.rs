use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// FIXME: These might miss some properties, like `id`, `cryptographic_binding_methods_supported`,
/// etc.
///
/// A struct mapping a `credential` type as defined in Appendix E in the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum CredentialFormatProfile {
    /// `jwt_vc_json`
    ///
    /// VC signed as a JWT, not using JSON-LD
    #[serde(rename = "jwt_vc_json", rename_all = "camelCase")]
    JwtVcJson {
        /// JSON array designating the types a certain credential type supports according to
        /// [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.3.
        ///
        /// TODO: needs to be filled in
        types: Vec<String>,

        /// A JSON object containing a list of key value pairs, where the key identifies the claim
        /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
        /// full (potentially deeply nested) structure of the verifiable credential to be issued.
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_subject: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        #[serde(skip_serializing_if = "Option::is_none")]
        order: Option<Vec<String>>,
    },

    /// `jwt_vc_json-ld`
    ///
    /// VC signed as a JWT, using JSON-LD
    #[serde(rename = "jwt_vc_json-ld", rename_all = "camelCase")]
    JwtVcJsonLd {
        /// JSON array designating the types a certain credential type supports according to
        /// [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.3.
        types: Vec<String>,

        /// A JSON object containing a list of key value pairs, where the key identifies the claim
        /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
        /// full (potentially deeply nested) structure of the verifiable credential to be issued.
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_subject: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        #[serde(skip_serializing_if = "Option::is_none")]
        order: Option<Vec<String>>,
    },

    /// `ldp_vc`
    ///
    /// VC secured using Data Integrity, using JSON-LD, with proof suite requiring Linked Data
    /// canonicalization
    #[serde(rename = "ldp_vc", rename_all = "camelCase")]
    LdpVc {
        /// JSON array as defined in [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.1.
        #[serde(rename = "@context")]
        context: Vec<String>,

        /// JSON array designating the types a certain credential type supports according to
        /// [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.3.
        types: Vec<String>,

        /// A JSON object containing a list of key value pairs, where the key identifies the claim
        /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
        /// full (potentially deeply nested) structure of the verifiable credential to be issued.
        /// The value is a JSON object detailing the specifics about the support for the claim
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_subject: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        #[serde(skip_serializing_if = "Option::is_none")]
        order: Option<Vec<String>>,
    },

    /// `mso_mdoc`
    ///
    /// Credential Format Profile for credentials complying with
    /// [ISO.18013-5](https://www.iso.org/standard/69084.html)
    #[serde(rename = "mso_mdoc")]
    MsoMdoc {
        /// JSON string identifying the credential type.
        doctype: String,

        /// A JSON object containing a list of key value pairs, where the key is a certain
        /// namespace as defined in [ISO.18013-5](https://www.iso.org/standard/69084.html) (or any
        /// profile of it), and the value is a JSON object. This object also contains a list of key
        /// value pairs, where the key is a claim that is defined in the respective namespace and
        /// is offered in the Credential.
        #[serde(skip_serializing_if = "Option::is_none")]
        claims: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        #[serde(skip_serializing_if = "Option::is_none")]
        order: Option<Vec<String>>,
    },
}

/// A JSON object containing a list of key value pairs, where the key identifies the claim
/// offered in the Credential. The value MAY be a dictionary, which allows to represent the
/// full (potentially deeply nested) structure of the verifiable credential to be issued.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    /// Boolean which when set to true indicates the claim MUST be present in the issued Credential. If
    /// the mandatory property is omitted its default should be assumed to be false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,

    /// String value determining type of value of the claim. A non-exhaustive list of valid values
    /// defined by this specification are string, number, and image media types such as image/jpeg
    /// as defined in [IANA media type registry for
    /// images](https://www.iana.org/assignments/media-types/media-types.xhtml#image).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,

    /// An array of objects, where each object contains display properties of a certain claim in
    /// the Credential for a certain language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialSubjectDisplay>>,
}

/// A Struct containing the fields for the credentialSubjects dispay field.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialSubjectDisplay {
    /// String value of a display name for the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// String value that identifies language of this object represented as language tag values
    /// defined in BCP47 [RFC5646](https://www.rfc-editor.org/rfc/rfc5646.txt). There MUST be only
    /// one object with the same language identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn should_deserialize_jwt_vc_json_credential_from_json() {
        let jwt_vc_json = serde_json::json!(
        {
            "format": "jwt_vc_json",
            "id": "UniversityDegree_JWT",
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ],
            "cryptographic_binding_methods_supported": [
                "did"
            ],
            "cryptographic_suites_supported": [
                "ES256K"
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
        });

        let credential: CredentialFormatProfile =
            serde_json::from_value(jwt_vc_json).expect("Could not format credential");

        match credential {
            CredentialFormatProfile::JwtVcJson {
                types,
                credential_subject,
                order,
            } => {
                assert!(types.contains(&"VerifiableCredential".to_owned()));
                assert!(types.contains(&"UniversityDegreeCredential".to_owned()));
                assert!(credential_subject.is_some());
                assert!(order.is_none());
            }
            _ => panic!("invalid format type"),
        };
    }

    #[test]
    fn should_deserialize_jwt_vc_json_ld_credential_from_json() {
        let jwt_vc_json = serde_json::json!(
        {
            "format": "jwt_vc_json-ld",
            "id": "UniversityDegree_JWT",
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ],
            "cryptographic_binding_methods_supported": [
                "did"
            ],
            "cryptographic_suites_supported": [
                "ES256K"
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
        });

        let credential: CredentialFormatProfile =
            serde_json::from_value(jwt_vc_json).expect("Could not format credential");

        match credential {
            CredentialFormatProfile::JwtVcJsonLd {
                types,
                credential_subject,
                order,
            } => {
                assert!(types.contains(&"VerifiableCredential".to_owned()));
                assert!(types.contains(&"UniversityDegreeCredential".to_owned()));
                assert!(credential_subject.is_some());
                assert!(order.is_none());
            }
            _ => panic!("invalid format type"),
        };
    }

    #[test]
    fn should_deserialize_ldp_vc_credential_from_json() {
        let jwt_vc_json = serde_json::json!(
        {
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
        }
                    );

        let credential: CredentialFormatProfile =
            serde_json::from_value(jwt_vc_json).expect("Could not format credential");

        match credential {
            CredentialFormatProfile::LdpVc {
                types,
                order,
                credential_subject,
                context,
            } => {
                assert!(context.contains(&"https://www.w3.org/2018/credentials/v1".to_owned()));
                assert!(
                    context.contains(&"https://www.w3.org/2018/credentials/examples/v1".to_owned())
                );
                assert!(types.contains(&"VerifiableCredential".to_owned()));
                assert!(types.contains(&"UniversityDegreeCredential".to_owned()));
                assert!(credential_subject.is_some());
                assert!(order.is_none());
            }
            _ => panic!("invalid format type"),
        };
    }
}
