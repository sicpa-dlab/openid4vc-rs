use serde::Deserialize;
use serde::Serialize;

use self::error::CredentialIssuerError;
use self::error::Result;
use crate::types::credential::CredentialFormatProfile;
use crate::types::credential_issuer_metadata::CredentialIssuerMetadata;

/// Error module for the credential issuance module
pub mod error;

/// Enum that defines a type which may contain a [`CredentialFormatProfile`] type or a string
#[derive(Clone)]
pub enum CredentialOrId {
    /// A full nested Credential object
    Credential(CredentialFormatProfile),

    /// A URI referencing a credential object on the [`CredentialIssuerMetadata`]
    CredentialId(String),
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
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct AuthorizedCodeFlow {
    /// Issuer state that MUST be the same, if supplied, from the authorization request
    pub issuer_state: Option<String>,
}

/// Field that defines the optional values for when the pre-authorized code flow is used
#[derive(Default, Serialize, Deserialize, Debug)]
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
    /// - When a credential id is supplied and could not be located inside the [`CredentialIssuerMetadata`]
    /// - When a credential is supplied with an invalid format. For now, only `ldp_vc` is supported
    ///
    pub fn create_offer(
        issuer_metadata: &CredentialIssuerMetadata,
        credentials: &[&CredentialOrId],
        _credential_offer_endpoint: &Option<String>,
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        _pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> Result<()> {
        // authorized code flow is only supported for now
        if authorized_code_flow.is_some() {
            return Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        }

        // Resolve all the credential ids, if supplied
        // This also checks if the credential is supported by the issuer
        let credentials =
            Into::<CredentialOrIds>::into(credentials).resolve_all(issuer_metadata)?;

        // Match statement to extract the values from the supported credentials
        // Only `CredentialFormatProfile::LdpVc` is supported
        for credential in credentials {
            match credential {
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
