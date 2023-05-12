use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::validate::{Validatable, ValidationError};

use super::credential::CredentialFormatProfile;

/// Struct mapping the `issuer_metadata` as defined in section 10.2.3 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-10.2.3)
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /// The Credential Issuer's identifier
    pub credential_issuer: String,

    /// Identifier of the OAuth 2.0 Authorization Server (as defined in
    /// [RFC8414](https://www.rfc-editor.org/rfc/rfc8414.txt)) the Credential Issuer relies on for
    /// authorization. If this element is omitted, the entity providing the Credential Issuer is
    /// also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0
    /// Issuer value to obtain the Authorization Server metadata as per
    /// [RFC8414](https://www.rfc-editor.org/rfc/rfc8414.txt).
    pub authorization_server: Option<String>,

    /// URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and
    /// MAY contain port, path and query parameter components.
    pub credential_endpoint: String,

    /// URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https
    /// scheme and MAY contain port, path and query parameter components. If omitted, the
    /// Credential Issuer does not support the Batch Credential Endpoint.
    pub batch_credential_endpoint: Option<String>,

    /// A JSON array containing a list of JSON objects, each of them representing metadata about a
    /// separate credential type that the Credential Issuer can issue.
    pub credentials_supported: Vec<CredentialSupported>,

    /// All the remaining fields that are not captured in the other fields.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub additional_fields: Option<HashMap<String, Value>>,
}

/// Struct mapping the `credential_supported` as defined in section 10.2.3.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#credential-metadata-object)
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CredentialSupported {
    /// A JSON string identifying the format of this credential, e.g. jwt_vc_json or ldp_vc.
    /// Depending on the format value, the object contains further elements defining the type and
    /// (optionally) particular claims the credential MAY contain, and information how to display
    /// the credential.
    #[serde(flatten)]
    pub format: CredentialFormatProfile,

    /// A JSON string identifying the respective object. The value MUST be unique across all
    /// `credentials_supported` entries in the Credential Issuer Metadata.
    pub id: Option<String>,

    /// Array of case sensitive strings that identify how the Credential is bound to the identifier
    /// of the End-User who possesses the Credential as defined in Section 7.1. Support for keys in
    /// JWK format [RFC7517](https://www.rfc-editor.org/rfc/rfc7517.txt) is indicated by the value
    /// jwk. Support for keys expressed as a COSE Key object
    /// [RFC8152](https://www.rfc-editor.org/rfc/rfc8152.txt) (for example, used in
    /// [ISO.18013-5](https://www.iso.org/standard/69084.html)) is indicated by the value cose_key.
    /// When Cryptographic Binding Method is a DID, valid values MUST be a did: prefix followed by
    /// a method-name using a syntax as defined in Sectio 3.1 of
    /// [DID-Core](https://www.w3.org/TR/did-core/), but without a :and method-specific-id. For
    /// example, support for the DID method with a method-name "example" would be represented by
    /// did:example. Support for all DID methods listed in Section 13 of
    /// [DID_Specification_Registries](https://www.w3.org/TR/did-spec-registries/) is indicated by
    /// sending a DID without any method-name.
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Array of case sensitive strings that identify the cryptographic suites that are supported
    /// for the cryptographic_binding_methods_supported. Cryptosuites for Credentials in jwt_vc
    /// format should use algorithm names defined in [IANA JOSE Algorithms
    /// Registry](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms).
    /// Cryptosuites for Credentials in ldp_vc format should use signature suites names defined in
    /// [Linked Data Cryptographic Suite
    /// Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/).
    pub cryptographic_suites_supported: Option<Vec<String>>,

    ///  An array of objects, where each object contains the display properties of the supported
    ///  credential for a certain language. Below is a non-exhaustive list of parameters that MAY
    ///  be included. Note that the display name of the supported credential is obtained from
    ///  display.name and individual claim names from claims.display.name values.
    pub display: Option<Vec<DisplayProperties>>,
}

/// Struct mapping the `display` type as defined in section 10.2.3.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-10.2.3.1)
#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct DisplayProperties {
    /// display name for the Credential.
    pub name: String,

    /// String value that identifies the language of this object represented as a language tag
    /// taken from values defined in BCP47 [RFC5646](https://www.rfc-editor.org/rfc/rfc5646.txt).
    /// Multiple display objects MAY be included for separate languages. There MUST be only one
    /// object with the same language identifier.
    pub locale: Option<String>,

    /// A JSON object with information about the logo of the Credential
    pub logo: Option<DisplayLogo>,

    /// String value of a description of the Credential.
    pub description: Option<String>,

    /// String value of a background color of the Credential represented as numerical color values
    /// defined in CSS Color Module Level 37 [CSS-Color](https://www.w3.org/TR/css-color-3/).
    pub background_color: Option<String>,

    /// String value of a text color of the Credential represented as numerical color values
    /// defined in CSS Color Module Level 37 [CSS-Color](https://www.w3.org/TR/css-color-3/).
    pub text_color: Option<String>,
}

/// Struct mapping the `logo` type as defined in section 10.2.3.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-10.2.3.1)
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisplayLogo {
    /// URL where the Wallet can obtain a logo of the Credential from the Credential Issuer.
    pub url: Option<String>,

    /// String value of an alternative text of a logo image.
    pub alt_text: Option<String>,
}

impl Validatable for CredentialIssuerMetadata {
    fn validate(&self) -> Result<(), ValidationError> {
        let mut uniques = HashSet::new();
        let are_ids_unique = &self
            .credentials_supported
            .iter()
            .all(|supported_credential| {
                // Only check for uniqueness if the value is supplied
                if let Some(id) = &supported_credential.id {
                    uniques.insert(id)
                // If no value is supplied, we return true to `Iterator::all`
                } else {
                    true
                }
            });

        if !are_ids_unique {
            return Err(ValidationError::Any {
                validation_message:
                    "Ids in supported credentials of the issuer metadata are not unique".to_owned(),
            });
        }

        for credential in &self.credentials_supported {
            credential.validate()?;
        }

        Ok(())
    }
}

impl Validatable for CredentialSupported {
    fn validate(&self) -> Result<(), ValidationError> {
        self.format.validate()?;

        if let Some(display) = &self.display {
            for property in display {
                property.validate()?;
            }
        }

        Ok(())
    }
}

impl Validatable for DisplayProperties {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(logo) = &self.logo {
            logo.validate()?;
        }

        Ok(())
    }
}

impl Validatable for DisplayLogo {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}
