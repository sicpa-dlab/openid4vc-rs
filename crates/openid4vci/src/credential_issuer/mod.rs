use serde::Deserialize;
use serde::Serialize;

use self::error::CredentialIssuerError;
use self::error::Result;
use crate::types::credential::CredentialFormatProfile;
use crate::types::credential_issuer_metadata::CredentialIssuerMetadata;

/// Error module for the credential issuance module
pub mod error;

/// Enum that defines a type which may contain a [`CredentialFormatProfile`] type or a string
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CredentialOrId {
    /// A URI referencing a credential object on the [`CredentialIssuerMetadata`]
    CredentialId(String),

    /// A full nested Credential object
    Credential(CredentialFormatProfile),
}

impl Default for CredentialOrId {
    fn default() -> Self {
        Self::CredentialId(String::new())
    }
}

impl CredentialOrId {
    /// Resolve the id from the issuer metadata
    ///
    /// # Errors
    ///
    /// - when the id is not in the `credentials_supported` of the [`CredentialIssuerMetadata`]
    pub fn resolve(
        &self,
        issuer_metadata: &CredentialIssuerMetadata,
    ) -> Result<CredentialFormatProfile> {
        match self {
            Self::Credential(c) => Ok(c.clone()),
            Self::CredentialId(s) => {
                let credential = issuer_metadata
                    .credentials_supported
                    .iter()
                    .find(|c| c.id == Some(s.to_string()))
                    .map(|c| c.format.clone());

                credential.ok_or_else(|| CredentialIssuerError::CredentialIdNotInIssuerMetadata {
                    id: s.clone(),
                })
            }
        }
    }
}

/// Container structure for the a list of credentials or references to credentials
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct CredentialOrIds(Vec<CredentialOrId>);

impl CredentialOrIds {
    /// Construct a new list of credentials or references to credentials
    #[must_use]
    pub fn new(credential_or_ids: Vec<CredentialOrId>) -> Self {
        Self(credential_or_ids)
    }

    /// Resolve all the identifiers
    ///
    /// # Errors
    ///
    /// - When the first id could not be resolved from the [`CredentialIssuerMetadata`]
    pub fn resolve_all(
        &self,
        issuer_metadata: &CredentialIssuerMetadata,
    ) -> Result<Vec<CredentialFormatProfile>> {
        let mut format_profiles = vec![];
        for credential in &self.0 {
            let credential = credential.resolve(issuer_metadata)?;
            format_profiles.push(credential);
        }
        Ok(format_profiles)
    }
}

impl From<&[&CredentialOrId]> for CredentialOrIds {
    fn from(val: &[&CredentialOrId]) -> Self {
        let v = val.to_vec().iter().map(|c| (*c).clone()).collect();
        CredentialOrIds::new(v)
    }
}

/// Field that defined the optional values for when the authorized code flow is used
#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizedCodeFlow {
    /// Issuer state that MUST be the same, if supplied, from the authorization request
    pub issuer_state: Option<String>,
}

/// Field that defines the optional values for when the pre-authorized code flow is used
#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PreAuthorizedCodeFlow {
    /// The code representing the Credential Issuer's authorization for the Wallet to obtain
    /// Credentials of a certain type. This code MUST be short lived and single-use. If the Wallet
    /// decides to use the Pre-Authorized Code Flow, this parameter value MUST be include in the
    /// subsequent Token Request with the Pre-Authorized Code Flow.
    #[serde(rename = "pre-authorized_code")]
    pub code: String,

    /// Boolean value specifying whether the Credential Issuer expects presentation of a user PIN
    /// along with the Token Request in a Pre-Authorized Code Flow. Default is false. This PIN is
    /// intended to bind the Pre-Authorized Code to a certain transaction in order to prevent
    /// replay of this code by an attacker that, for example, scanned the QR code while standing
    /// behind the legit user. It is RECOMMENDED to send a PIN via a separate channel. If the
    /// Wallet decides to use the Pre-Authorized Code Flow, a PIN value MUST be sent in the
    /// user_pin parameter with the respective Token Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin_required: Option<bool>,
}

/// Struct mapping the `credential offer parameters` as defined in section 4.1.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct CredentialOffer {
    /// The URL of the Credential Issuer, the Wallet is requested to obtain one or more Credentials
    /// from.
    pub credential_issuer: String,

    /// A JSON array, where every entry is a JSON object or a JSON string. If the entry is an
    /// object, the object contains the data related to a certain credential type the Wallet MAY
    /// request. Each object MUST contain a format Claim determining the format of the credential
    /// to be requested and further parameters characterising the type of the credential to be
    /// requested as defined in Appendix E. If the entry is a string, the string value MUST be one
    /// of the id values in one of the objects in the credentials_supported Credential Issuer
    /// metadata parameter. When processing, the Wallet MUST resolve this string value to the
    /// respective object.
    pub credentials: CredentialOrIds,

    /// A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
    /// to process for this credential offer. Every grant is represented by a key and an object. The
    /// key value is the Grant Type identifier, the object MAY contain parameters either determining
    /// the way the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with
    /// the respective request(s). If grants is not present or empty, the Wallet MUST determine the
    /// Grant Types the Credential Issuer's AS supports using the respective metadata. When multiple
    /// grants are present, it's at the Wallet's discretion which one to use.
    pub grants: CredentialOfferGrants,
}

impl CredentialOffer {
    /// Constructor for a credential offer
    #[must_use]
    pub fn new(
        credential_issuer: &str,
        credentials: &[&CredentialOrId],
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> Self {
        Self {
            credential_issuer: credential_issuer.to_owned(),
            credentials: credentials.into(),
            grants: CredentialOfferGrants {
                authorized_code_flow: authorized_code_flow.clone(),
                pre_authorized_code_flow: pre_authorized_code_flow.clone(),
            },
        }
    }

    /// Convert the credential offer to a url-encoded string
    ///
    /// # Errors
    ///
    /// - When the structure could not url encoded
    pub fn to_url(&self) -> Result<String> {
        let s =
            serde_json::to_string(self).map_err(|e| CredentialIssuerError::SerializationError {
                error_message: e.to_string(),
            })?;
        let url = urlencoding::encode(&s).into_owned();
        Ok(url)
    }
}

/// A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
/// to process for this credential offer. Every grant is represented by a key and an object. The
/// key value is the Grant Type identifier, the object MAY contain parameters either determining
/// the way the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with
/// the respective request(s). If grants is not present or empty, the Wallet MUST determine the
/// Grant Types the Credential Issuer's AS supports using the respective metadata. When multiple
/// grants are present, it's at the Wallet's discretion which one to use.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct CredentialOfferGrants {
    /// Adds support for the authorized code flow as defined in section 3.4 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
    #[serde(skip_serializing_if = "Option::is_none", rename = "authorization_code")]
    pub authorized_code_flow: Option<AuthorizedCodeFlow>,

    /// Adds support for the pre-authorized code flow as defined in section 3.5 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    )]
    pub pre_authorized_code_flow: Option<PreAuthorizedCodeFlow>,
}

/// Structure that contains the functionality for the credential issuer
pub struct CredentialIssuer;

impl CredentialIssuer {
    /// Create a credential offer
    ///
    /// ## Errors
    ///
    /// - When the authorized flow option is supplied
    /// - When a credential id is supplied and could not be located inside the [`CredentialIssuerMetadata`]
    /// - When a credential is supplied with an invalid format. For now, only `ldp_vc` is supported
    ///
    pub fn create_offer(
        issuer_metadata: &CredentialIssuerMetadata,
        credentials: &[&CredentialOrId],
        credential_offer_endpoint: &Option<String>,
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> Result<(CredentialOffer, String)> {
        // authorized code flow is only supported for now
        if authorized_code_flow.is_some() {
            return Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        }

        // Resolve all the credential ids, if supplied
        // This also checks if the credential is supported by the issuer
        let resolved_credentials =
            Into::<CredentialOrIds>::into(credentials).resolve_all(issuer_metadata)?;

        // Match statement to extract the values from the supported credentials
        // Only `CredentialFormatProfile::LdpVc` is supported
        for resolved_credential in resolved_credentials {
            match resolved_credential {
                CredentialFormatProfile::LdpVc { .. } => Ok(()),

                CredentialFormatProfile::JwtVcJson { .. } => {
                    Err(CredentialIssuerError::UnsupportedCredentialFormat {
                        requested_format: "jwt_vs_json".to_owned(),
                        supported_formats: vec!["ldp_vc".to_owned()],
                    })
                }

                CredentialFormatProfile::JwtVcJsonLd { .. } => {
                    Err(CredentialIssuerError::UnsupportedCredentialFormat {
                        requested_format: "jwt_vs_json-ld".to_owned(),
                        supported_formats: vec!["ldp_vc".to_owned()],
                    })
                }

                CredentialFormatProfile::MsoMdoc { .. } => {
                    Err(CredentialIssuerError::UnsupportedCredentialFormat {
                        requested_format: "mso_mdoc".to_owned(),
                        supported_formats: vec!["ldp_vc".to_owned()],
                    })
                }
            }?;
        }

        // Create a credential offer based on the input
        let credential_offer = CredentialOffer::new(
            issuer_metadata.credential_issuer.as_str(),
            credentials,
            authorized_code_flow,
            pre_authorized_code_flow,
        );

        // Create a url from the credential offer
        let credential_offer_url = credential_offer.to_url()?;

        // Prepend the credential offer url if it is provided
        let credential_offer_url = match credential_offer_endpoint {
            Some(e) => format!("{e}/credential_offer?credential_offer={credential_offer_url}"),
            None => format!("/credential_offer?credential_offer={credential_offer_url}"),
        };

        Ok((credential_offer, credential_offer_url))
    }
}

#[cfg(test)]
mod test_credential {
    use crate::credential_issuer::error::CredentialIssuerError;

    use super::*;

    #[test]
    fn happy_flow() {
        let (offer, url) = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            &[&CredentialOrId::Credential(
                CredentialFormatProfile::LdpVc {
                    context: vec!["context_one".to_owned()],
                    types: vec!["type_one".to_owned()],
                    credential_subject: None,
                    order: None,
                },
            )],
            &Some(String::default()),
            &None,
            &Some(PreAuthorizedCodeFlow {
                code: "ABC".to_owned(),
                user_pin_required: None,
            }),
        )
        .expect("Unable to create the credential offer");

        assert_eq!(url, "/credential_offer?credential_offer=%7B%22credential_issuer%22%3A%22%22%2C%22credentials%22%3A%5B%7B%22Credential%22%3A%7B%22format%22%3A%22ldp_vc%22%2C%22%40context%22%3A%5B%22context_one%22%5D%2C%22types%22%3A%5B%22type_one%22%5D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22ABC%22%7D%7D%7D");

        assert_eq!(offer.credential_issuer, String::new());

        assert!(offer.grants.pre_authorized_code_flow.is_some());
        assert!(offer.grants.authorized_code_flow.is_none());
    }

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

    #[test]
    fn should_error_when_supplying_credential_id_that_is_not_in_issuer_metadata() {
        let result = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            &[&CredentialOrId::CredentialId("id_one".to_owned())],
            &Some(String::default()),
            &None,
            &Some(PreAuthorizedCodeFlow::default()),
        );
        let expect = Err(CredentialIssuerError::CredentialIdNotInIssuerMetadata {
            id: "id_one".to_owned(),
        });
        assert_eq!(result, expect);
    }

    #[test]
    fn should_error_when_supplying_credential_with_invalid_format() {
        let result = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            &[&CredentialOrId::Credential(
                CredentialFormatProfile::MsoMdoc {
                    doctype: "1".to_owned(),
                    claims: None,
                    order: None,
                },
            )],
            &Some(String::default()),
            &None,
            &Some(PreAuthorizedCodeFlow::default()),
        );
        let expect = Err(CredentialIssuerError::UnsupportedCredentialFormat {
            requested_format: "mso_mdoc".to_owned(),
            supported_formats: vec!["ldp_vc".to_owned()],
        });
        assert_eq!(result, expect);
    }
}
