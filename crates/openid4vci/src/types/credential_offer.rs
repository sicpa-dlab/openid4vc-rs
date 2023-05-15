use serde::{Deserialize, Serialize};

use crate::validate::{ValidationError, ValidationResult};

use super::{
    credential_issuer_metadata::CredentialIssuerMetadata, grants::Grants, jwt_vc_json,
    jwt_vc_json_ld, ldp_vc, mso_mdoc,
};

/// Struct mapping the `credential offer parameters` as defined in section 4.1.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-4.1.1)
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
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
    pub credentials: Vec<CredentialOfferFormatOrId>,

    /// A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
    /// to process for this credential offer. Every grant is represented by a key and an object. The
    /// key value is the Grant Type identifier, the object MAY contain parameters either determining
    /// the way the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with
    /// the respective request(s). If grants is not present or empty, the Wallet MUST determine the
    /// Grant Types the Credential Issuer's AS supports using the respective metadata. When multiple
    /// grants are present, it's at the Wallet's discretion which one to use.
    pub grants: Grants,
}

impl CredentialOffer {
    /// Convert the credential offer to a url-encoded string
    ///
    /// # Errors
    ///
    /// - When the structure could not url encoded
    pub fn url_encode(&self) -> ValidationResult<String> {
        let s = serde_json::to_string(self).map_err(ValidationError::from)?;
        let url = urlencoding::encode(&s).into_owned();
        Ok(url)
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum CredentialOfferFormat {
    /// `jwt_vc_json`
    ///
    /// VC signed as a JWT, not using JSON-LD
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(jwt_vc_json::CredentialOffer),

    /// `jwt_vc_json-ld`
    ///
    /// VC signed as a JWT, using JSON-LD
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd(jwt_vc_json_ld::CredentialOffer),

    /// `ldp_vc`
    ///
    /// VC secured using Data Integrity, using JSON-LD, with proof suite requiring Linked Data
    /// canonicalization
    #[serde(rename = "ldp_vc")]
    LdpVc(ldp_vc::CredentialOffer),

    /// `mso_mdoc`
    ///
    /// Credential Format Profile for credentials complying with
    /// [ISO.18013-5](https://www.iso.org/standard/69084.html)
    #[serde(rename = "mso_mdoc")]
    MsoMdoc(mso_mdoc::CredentialOffer),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum CredentialOfferFormatOrId {
    Id(String),
    CredentialOfferFormat(CredentialOfferFormat),
}

impl CredentialOfferFormatOrId {
    pub fn assert_id_in_issuer_metadata(
        &self,
        issuer_metadata: &CredentialIssuerMetadata,
    ) -> Result<(), ValidationError> {
        match self {
            CredentialOfferFormatOrId::Id(id) => {
                let ids: Vec<_> = issuer_metadata
                    .credentials_supported
                    .iter()
                    .filter_map(|c| c.id.clone())
                    .collect();

                if ids.contains(id) {
                    Ok(())
                } else {
                    Err(ValidationError::Any {
                        validation_message: format!("id `{id}` not found in the issuer metadata"),
                    })
                }
            }
            // `true` is returned here, because when the offer is not referring to a credential by
            // id, it does not have to be checked.
            CredentialOfferFormatOrId::CredentialOfferFormat(_) => Ok(()),
        }
    }
}
