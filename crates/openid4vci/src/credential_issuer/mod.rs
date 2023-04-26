use self::error::CredentialIssuerError;
use self::error::CredentialIssuerResult;
use self::error_code::CredentialIssuerErrorCode;
use crate::error_response::ErrorResponse;
use crate::jwt::ProofJwt;
use crate::jwt::ProofJwtAlgorithm;
use crate::types::authorization_server_metadata::AuthorizationServerMetadata;
use crate::types::credential::CredentialFormatProfile;
use crate::types::credential::CredentialFormatProfileOrEncoded;
use crate::types::credential_issuer_metadata::CredentialIssuerMetadata;
use crate::types::credential_request::CredentialRequest;
use crate::types::credential_request::CredentialRequestProof;
use crate::validate::Validatable;
use crate::validate::ValidationError;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

/// Error module for the credential issuance module
pub mod error;

/// Module for credential error response
pub mod error_code;

/// Struct mapping for a `credential error response` as defined in section 7.3.1 of the
/// [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.3.1)
pub type CredentialIssuerErrorResponse = ErrorResponse<CredentialIssuerErrorCode>;

/// Enum that defines a type which may contain a [`CredentialFormatProfile`] type or a string
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
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
    ) -> CredentialIssuerResult<CredentialFormatProfile> {
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
    ) -> CredentialIssuerResult<Vec<CredentialFormatProfile>> {
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

impl<T> From<Vec<T>> for CredentialOrIds
where
    T: Into<CredentialOrId> + Clone,
{
    fn from(value: Vec<T>) -> Self {
        Self::new(value.iter().map(|v| (*v).clone().into()).collect())
    }
}

impl From<String> for CredentialOrId {
    fn from(value: String) -> Self {
        Self::CredentialId(value)
    }
}

impl From<&str> for CredentialOrId {
    fn from(value: &str) -> Self {
        Self::CredentialId(value.to_owned())
    }
}

impl From<CredentialFormatProfile> for CredentialOrId {
    fn from(value: CredentialFormatProfile) -> Self {
        Self::Credential(value)
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
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1)
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

impl Validatable for CredentialOffer {
    fn validate(&self) -> Result<(), ValidationError> {
        self.credentials.validate()?;
        self.grants.validate()?;

        Ok(())
    }
}

/// TODO: implement if required
impl Validatable for CredentialOrIds {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl Validatable for CredentialOfferGrants {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl CredentialOffer {
    /// Constructor for a credential offer
    #[must_use]
    pub fn new(
        credential_issuer: &str,
        credentials: CredentialOrIds,
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> Self {
        Self {
            credential_issuer: credential_issuer.to_owned(),
            credentials,
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
    pub fn url_encode(&self) -> CredentialIssuerResult<String> {
        let s = serde_json::to_string(self).map_err(ValidationError::from)?;
        let url = urlencoding::encode(&s).into_owned();
        Ok(url)
    }
}

/// Enum value as a union for the input to either contain a [`CredentialFormatProfile`] or
/// `acceptance_token`
pub enum CredentialOrAcceptanceToken {
    /// Credential format profile
    Credential(CredentialFormatProfile),

    /// Acceptance token
    AcceptanceToken(String),
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
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.4).
    #[serde(skip_serializing_if = "Option::is_none", rename = "authorization_code")]
    pub authorized_code_flow: Option<AuthorizedCodeFlow>,

    /// Adds support for the pre-authorized code flow as defined in section 3.5 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5).
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    )]
    pub pre_authorized_code_flow: Option<PreAuthorizedCodeFlow>,
}

/// Structure that contains the functionality for the credential issuer
pub struct CredentialIssuer;

/// Return type of the [`CredentialIssuer::pre_evaluate_credential_request`]
#[derive(Debug, Serialize, PartialEq, Eq, Default)]
pub struct PreEvaluateCredentialRequestResponse {
    /// The DID that needs resolution before [`CredentialIssuer::evaluate_credential_request`] is
    /// called
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

/// Return type of the [`CredentialIssuer::evaluate_credential_request`]
#[derive(Debug, Serialize, PartialEq, Eq, Default)]
pub struct CredentialIssuerEvaluateRequestResponse {
    /// Proof of possession, wrapping [`ProofOfPossession`]
    pub proof_of_possession: Option<ProofOfPossession>,
}

/// Structure that contains the items to check a proof of possession
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ProofOfPossession {
    /// Algorithm used for signing
    pub algorithm: ProofJwtAlgorithm,

    /// Public key bytes that can be used for verification
    pub public_key: Vec<u8>,

    /// Message that needs to be verified by the consumer
    pub message: Vec<u8>,

    /// Signature over the message, using the public key, that can be used by the consumer to
    /// verify it
    pub signature: Vec<u8>,
}

/// Additional struct for metadata that will be used to verify
///
/// TODO: include nonce
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash)]
pub struct CredentialIssuerEvaluateRequestOptions {
    /// Id of the client that will be checked whether it is equal to the `iss` field inside the JWK
    client_id: Option<String>,
}

/// Response structure for a `credential_success`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CredentialSuccessResponse {
    /// JSON string denoting the format of the issued Credential.
    format: String,

    /// Contains issued Credential. MUST be present when `acceptance_token` is not returned. MAY be a
    /// JSON string or a JSON object, depending on the Credential format. See Appendix E of the
    /// [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#format_profiles)
    /// for the Credential format specific encoding requirements.
    credential: Option<CredentialFormatProfileOrEncoded>,

    /// A JSON string containing a security token subsequently used to obtain a Credential. MUST be
    /// present when credential is not returned.
    acceptance_token: Option<String>,

    /// JSON string containing a nonce to be used to create a proof of possession of key material
    /// when requesting a Credential (see Section 7.2 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#credential_request)).
    /// When received, the Wallet MUST use this nonce value for its subsequent credential requests
    /// until the Credential Issuer provides a fresh nonce.
    c_nonce: Option<String>,

    /// JSON integer denoting the lifetime in seconds of the c_nonce.
    c_nonce_expires_in: Option<u64>,
}

/// Struct value as a union for the input to either contain a `c_nonce` and a `c_nonce_expires_in` as
/// a [`Option<u64>`]. These values always have to be supplied together.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash)]
pub struct CNonce {
    /// JSON string containing a nonce to be used to create a proof of possession of key material
    /// when requesting a Credential (see Section 7.2 of the [openidvci
    /// specifciation](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2)).
    /// When received, the Wallet MUST use this nonce value for its subsequent credential requests
    /// until the Credential Issuer provides a fresh nonce.
    pub c_nonce: String,

    /// JSON integer denoting the lifetime in seconds of the `c_nonce`.
    pub c_nonce_expires_in: Option<u64>,
}

impl CredentialIssuer {
    /// Create a credential offer
    ///
    /// This function returns a [`CredentialOffer`] and a credential offer url. This url is either
    /// can be a deeplink or a normal url. If a `credential_offer_endpoint` is supplied, it will be
    /// used to create a normal link, and if [`None`] is supplied, a deeplink will be created.
    ///
    /// ## Errors
    ///
    /// - When the authorized flow option is supplied
    /// - When a credential id is supplied and could not be located inside the [`CredentialIssuerMetadata`]
    /// - When a credential is supplied with an invalid format. For now, only `ldp_vc` is supported
    ///
    pub fn create_offer(
        issuer_metadata: &CredentialIssuerMetadata,
        credentials: impl Into<CredentialOrIds>,
        credential_offer_endpoint: &Option<String>,
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> CredentialIssuerResult<(CredentialOffer, String)> {
        issuer_metadata.validate()?;

        // authorized code flow is only supported for now
        if authorized_code_flow.is_some() {
            return Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        }

        let credentials = credentials.into();

        // Resolve all the credential ids, if supplied
        // This also checks if the credential is supported by the issuer
        //
        // The resulting value is omitted as we use this check for now that they all reference a
        // credential inside the `issuer_metadata`
        let _ = credentials.resolve_all(issuer_metadata)?;

        // Create a credential offer based on the input
        let credential_offer = CredentialOffer::new(
            issuer_metadata.credential_issuer.as_str(),
            credentials,
            authorized_code_flow,
            pre_authorized_code_flow,
        );

        // url-encode the credential offer
        let credential_offer_url_encoded = credential_offer.url_encode()?;

        // Get the url prefix
        // This is a deeplink if no `credential_offer_endpoint` is provided
        let credential_offer_url_prefix = credential_offer_endpoint
            .clone()
            .map_or("openid-credential-offer://".to_owned(), |u| format!("{u}?"));

        let credential_offer_url =
            format!("{credential_offer_url_prefix}credential_offer={credential_offer_url_encoded}");

        Ok((credential_offer, credential_offer_url))
    }

    /// Pre evaluate the credential request
    ///
    /// This will check whether the [`CredentialRequest`] contains a DID as kid inside the JWT and
    /// return the value that needs resolution
    ///
    /// # Errors
    ///
    /// - When the credential request is invalid
    pub fn pre_evaluate_credential_request(
        credential_request: &CredentialRequest,
    ) -> CredentialIssuerResult<PreEvaluateCredentialRequestResponse> {
        credential_request.validate()?;

        let did = if let Some(CredentialRequestProof { jwt, .. }) = &credential_request.proof {
            let jwt = ProofJwt::from_str(jwt)?;
            jwt.validate()?;
            jwt.extract_kid()?
        } else {
            None
        };

        Ok(PreEvaluateCredentialRequestResponse { did })
    }

    /// Evaluate a credential request
    ///
    /// # Errors
    ///
    /// - When incorrect valdiation happens on the supplied input arguments
    /// - When a JWT is inside the proof and is not valid
    pub fn evaluate_credential_request(
        issuer_metadata: &CredentialIssuerMetadata,
        credential_request: &CredentialRequest,
        credential_offer: Option<&CredentialOffer>,
        authorization_server_metadata: Option<&AuthorizationServerMetadata>,
        did_document: Option<&ssi_dids::Document>,
    ) -> CredentialIssuerResult<CredentialIssuerEvaluateRequestResponse> {
        issuer_metadata.validate()?;
        credential_request.validate()?;

        if let Some(credential_offer) = credential_offer {
            credential_offer.validate()?;
        };

        if let Some(authorization_server_metadata) = authorization_server_metadata {
            authorization_server_metadata.validate()?;
        };

        if let Some(CredentialRequestProof { jwt, .. }) = &credential_request.proof {
            let jwt = ProofJwt::from_str(jwt)?;
            jwt.validate()?;

            let (public_key, algorithm) = jwt.extract_key_and_alg(did_document)?;
            let signature = jwt.extract_signature()?;
            let message = jwt.to_signable_message()?;

            return Ok(CredentialIssuerEvaluateRequestResponse {
                proof_of_possession: Some(ProofOfPossession {
                    algorithm,
                    public_key,
                    message,
                    signature,
                }),
            });
        };

        Ok(CredentialIssuerEvaluateRequestResponse::default())
    }

    /// Create a credential success response when all the previous steps are completed.
    ///
    /// # TODO
    ///
    /// - Should we error when the `credential` AND `acceptance_token` are both not supplied?
    /// - `c_nonce_expires_in` gives the seconds it lives from issuance. How can we get the
    ///   issuance timestamp?
    ///
    /// # Errors
    ///
    /// - When the `credential_request` is not valid
    /// - When the `c_nonce` is expired
    pub fn create_credential_success_response(
        credential_request: &CredentialRequest,
        credential_or_acceptance_token: Option<CredentialOrAcceptanceToken>,
        c_nonce: Option<CNonce>,
    ) -> CredentialIssuerResult<CredentialSuccessResponse> {
        credential_request.validate()?;

        let (c_nonce, c_nonce_expires_in) = match c_nonce {
            Some(CNonce {
                c_nonce,
                c_nonce_expires_in,
            }) => (Some(c_nonce), c_nonce_expires_in),
            None => (None, None),
        };

        let (credential, acceptance_token) = match credential_or_acceptance_token {
            Some(credential_or_acceptance_token) => match credential_or_acceptance_token {
                CredentialOrAcceptanceToken::Credential(credential) => {
                    let credential: CredentialFormatProfileOrEncoded = credential.try_into()?;
                    (Some(credential), None)
                }
                CredentialOrAcceptanceToken::AcceptanceToken(token) => (None, Some(token)),
            },
            None => (None, None),
        };

        let response = CredentialSuccessResponse {
            format: credential_request.format.get_format_name(),
            credential,
            acceptance_token,
            c_nonce,
            c_nonce_expires_in,
        };

        Ok(response)
    }

    /// Create an error response
    ///
    /// # Errors
    ///
    /// Unable to error, `Result` is used for consistency
    pub fn create_credential_error_response(
        error: &CredentialIssuerErrorCode,
        error_description: Option<String>,
        error_uri: Option<String>,
        error_additional_details: Option<serde_json::Value>,
    ) -> CredentialIssuerResult<CredentialIssuerErrorResponse> {
        let response = CredentialIssuerErrorResponse {
            error: error.clone(),
            error_description,
            error_uri,
            error_additional_details,
        };
        Ok(response)
    }
}

#[cfg(test)]
mod test_create_credential_offer {
    use crate::credential_issuer::error::CredentialIssuerError;

    use super::*;

    #[test]
    fn happy_flow() {
        let (offer, url) = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            vec![CredentialOrId::Credential(CredentialFormatProfile::LdpVc {
                context: vec!["context_one".to_owned()],
                types: vec!["type_one".to_owned()],
                credential_subject: None,
                order: None,
            })],
            &None,
            &None,
            &Some(PreAuthorizedCodeFlow {
                code: "ABC".to_owned(),
                user_pin_required: None,
            }),
        )
        .expect("Unable to create the credential offer");

        assert_eq!(url, "openid-credential-offer://credential_offer=%7B%22credential_issuer%22%3A%22%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22%40context%22%3A%5B%22context_one%22%5D%2C%22types%22%3A%5B%22type_one%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22ABC%22%7D%7D%7D");

        assert_eq!(offer.credential_issuer, String::new());

        assert!(offer.grants.pre_authorized_code_flow.is_some());
        assert!(offer.grants.authorized_code_flow.is_none());
    }

    #[test]
    fn should_error_when_using_authorized_flow() {
        let result = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            CredentialOrIds::new(vec![]),
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
            vec!["id_one"],
            &Some(String::default()),
            &None,
            &Some(PreAuthorizedCodeFlow::default()),
        );
        let expect = Err(CredentialIssuerError::CredentialIdNotInIssuerMetadata {
            id: "id_one".to_owned(),
        });
        assert_eq!(result, expect);
    }
}

#[cfg(test)]
mod test_pre_evaluate_credential_request {
    use crate::jwt::error::JwtError;

    use super::*;

    #[test]
    fn happy_flow() {
        let credential_request = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
        }),
        format: CredentialFormatProfile::LdpVc {
            context: vec![],
            types: vec![],
            credential_subject: None,
            order: None,
        },
    };

        let response = CredentialIssuer::pre_evaluate_credential_request(&credential_request)
            .expect("Unable to to pre evaluate the credential request");

        assert_eq!(
            response.did,
            Some("did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1".to_owned())
        );
    }

    #[test]
    fn should_not_work_with_jwk() {
        let credential_request: CredentialRequest = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "eyJqd2siOiJ1bmtub3duIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned()
        }),
        format: CredentialFormatProfile::LdpVc {
            context: vec![],
            types: vec![],
            credential_subject: None,
            order: None,
        },
    };

        let response =
            CredentialIssuer::pre_evaluate_credential_request(&credential_request).unwrap_err();

        assert_eq!(
            response,
            CredentialIssuerError::JwtError(JwtError::UnsupportedKeyTypeInJwtHeader {
                key_type: "unknown".to_owned(),
                key_name: "jwk".to_owned()
            })
        );
    }
}

#[cfg(test)]
mod test_evaluate_credential_request {
    use ssi_dids::Document;

    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn should_evaluate_credential_request() {
        let cfp = serde_json::json!({
            "format": "jwt_vc_json",
            "id": "UniversityDegree_JWT",
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
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

        let issuer_metadata: CredentialIssuerMetadata = serde_json::from_value(serde_json::json!({
            "credential_issuer": "01001110",
            "credential_endpoint": "https://example.org",
            "credentials_supported": [
                &cfp
            ],
        }))
        .expect("Unable to create issuer metadata");

        let credential_request = CredentialRequest {
         proof: Some(CredentialRequestProof {
             proof_type: "jwt".to_owned(),
             jwt: "ewogICJraWQiOiAiZGlkOmtleTp6Nk1rcFRIUjhWTnNCeFlBQVdIdXQyR2VhZGQ5alN3dUJWOHhSb0Fud1dzZHZrdEgjejZNa3BUSFI4Vk5zQnhZQUFXSHV0MkdlYWRkOWpTd3VCVjh4Um9BbndXc2R2a3RIIiwKICAiYWxnIjogIkVkRFNBIiwKICAidHlwIjogIm9wZW5pZDR2Y2ktcHJvb2Yrand0Igp9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
         }),
         format: CredentialFormatProfile::LdpVc {
             context: vec![],
             types: vec![],
             credential_subject: None,
             order: None,
         },
     };

        let did_document = serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
              "publicKeyJwk": {
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
              }
            }
          ],
          "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
          "verificationMethod": [
            {
              "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
              "type": "Ed25519VerificationKey2018",
              "controller": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "lJZrfAjkBXdfjebMHEUI9usidAPhAlssitLXR3OYxbI"
              }
            }
          ],
          "authentication": [
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
          ],
          "assertionMethod": [
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
          ]
        });

        let did_document: Document =
            serde_json::from_value(did_document).expect("Unable to create did document");

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            None,
            None,
            Some(&did_document),
        )
        .expect("Unable to evaluate credential request");

        let evaluated = evaluated
            .proof_of_possession
            .expect("No proof of possession found");

        assert_eq!(evaluated.algorithm, ProofJwtAlgorithm::EdDSA);
        assert_eq!(
            evaluated.public_key,
            vec![
                148, 150, 107, 124, 8, 228, 5, 119, 95, 141, 230, 204, 28, 69, 8, 246, 235, 34,
                116, 3, 225, 2, 91, 44, 138, 210, 215, 71, 115, 152, 197, 178
            ]
        );

        assert_eq!(
            evaluated.message,
            vec![
                123, 34, 116, 121, 112, 34, 58, 34, 111, 112, 101, 110, 105, 100, 52, 118, 99, 105,
                45, 112, 114, 111, 111, 102, 43, 106, 119, 116, 34, 44, 34, 97, 108, 103, 34, 58,
                34, 69, 100, 68, 83, 65, 34, 44, 34, 107, 105, 100, 34, 58, 34, 100, 105, 100, 58,
                107, 101, 121, 58, 122, 54, 77, 107, 112, 84, 72, 82, 56, 86, 78, 115, 66, 120, 89,
                65, 65, 87, 72, 117, 116, 50, 71, 101, 97, 100, 100, 57, 106, 83, 119, 117, 66, 86,
                56, 120, 82, 111, 65, 110, 119, 87, 115, 100, 118, 107, 116, 72, 35, 122, 54, 77,
                107, 112, 84, 72, 82, 56, 86, 78, 115, 66, 120, 89, 65, 65, 87, 72, 117, 116, 50,
                71, 101, 97, 100, 100, 57, 106, 83, 119, 117, 66, 86, 56, 120, 82, 111, 65, 110,
                119, 87, 115, 100, 118, 107, 116, 72, 34, 125, 46, 123, 34, 105, 115, 115, 34, 58,
                34, 115, 54, 66, 104, 100, 82, 107, 113, 116, 51, 34, 44, 34, 97, 117, 100, 34, 58,
                34, 104, 116, 116, 112, 115, 58, 47, 47, 115, 101, 114, 118, 101, 114, 46, 101,
                120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 34, 44, 34, 105, 97, 116, 34, 58,
                34, 50, 48, 49, 56, 45, 48, 57, 45, 49, 52, 84, 50, 49, 58, 49, 57, 58, 49, 48, 90,
                34, 44, 34, 110, 111, 110, 99, 101, 34, 58, 34, 116, 90, 105, 103, 110, 115, 110,
                70, 98, 112, 34, 125
            ]
        );

        assert_eq!(
            evaluated.signature,
            vec![
                101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 34, 44, 34, 105, 97, 116, 34,
                58, 34, 50, 48, 49, 56, 45, 48, 57, 45, 49, 52, 84, 50, 49, 58, 49, 57, 58, 49, 48,
                90, 34, 44, 34, 110, 111, 110, 99, 101, 34, 58, 34, 116, 90, 105, 103, 110, 115,
                110, 70, 98, 112, 34, 125
            ]
        );
    }
}

#[cfg(test)]
mod test_create_credential_success_response {
    use super::*;
    use crate::base::base64url;

    #[test]
    fn should_create_success_response() {
        let cfp = serde_json::json!({
            "format": "jwt_vc_json",
            "id": "UniversityDegree_JWT",
            "types": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
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

        let credential_request = CredentialRequest {
         proof: Some(CredentialRequestProof {
             proof_type: "jwt".to_owned(),
             jwt: "ewogICJraWQiOiAiZGlkOmtleTp6Nk1rcFRIUjhWTnNCeFlBQVdIdXQyR2VhZGQ5alN3dUJWOHhSb0Fud1dzZHZrdEgjejZNa3BUSFI4Vk5zQnhZQUFXSHV0MkdlYWRkOWpTd3VCVjh4Um9BbndXc2R2a3RIIiwKICAiYWxnIjogIkVkRFNBIiwKICAidHlwIjogIm9wZW5pZDR2Y2ktcHJvb2Yrand0Igp9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
         }),
         format: CredentialFormatProfile::LdpVc {
             context: vec![],
             types: vec![],
             credential_subject: None,
             order: None,
         },
     };

        let credential = CredentialOrAcceptanceToken::Credential(
            serde_json::from_value(cfp.clone())
                .expect("Unable to create credential format profile"),
        );

        let success_response = CredentialIssuer::create_credential_success_response(
            &credential_request,
            Some(credential),
            Some(CNonce {
                c_nonce: "nonce".to_owned(),
                c_nonce_expires_in: Some(10),
            }),
        )
        .expect("Unable to create success response");

        let credential = match success_response
            .credential
            .as_ref()
            .expect("No credential found")
        {
            CredentialFormatProfileOrEncoded::CredentialFormatProfile(cfp) => cfp.clone(),
            CredentialFormatProfileOrEncoded::Encoded(e) => {
                serde_json::from_slice(&base64url::decode(e).expect("Unable to decode cfp"))
                    .expect("Unable to create cfp")
            }
        };

        assert_eq!(success_response.format, "ldp_vc");
        assert_eq!(
            credential,
            serde_json::from_value(cfp).expect("Unable to create cfp")
        );
        assert_eq!(success_response.acceptance_token, None);
        assert_eq!(success_response.c_nonce, Some("nonce".to_owned()));
        assert_eq!(success_response.c_nonce_expires_in, Some(10));
    }
}
