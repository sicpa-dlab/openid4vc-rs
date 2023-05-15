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
use crate::types::credential_offer::CredentialOffer;
use crate::types::credential_offer::CredentialOfferFormatOrId;
use crate::types::credential_request::CredentialRequest;
use crate::types::credential_request::CredentialRequestProof;
use crate::types::grants::AuthorizedCodeFlow;
use crate::types::grants::Grants;
use crate::types::grants::PreAuthorizedCodeFlow;
use crate::validate::Validatable;
use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

/// Error module for the credential issuance module
pub mod error;

/// Module for credential error response
pub mod error_code;

/// Struct mapping for a `credential error response` as defined in section 7.3.1 of the
/// [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.3.1)
pub type CredentialIssuerErrorResponse = ErrorResponse<CredentialIssuerErrorCode>;

/// Enum value as a union for the input to either contain a [`CredentialFormatProfile`] or
/// `acceptance_token`
pub enum CredentialOrAcceptanceToken {
    /// Credential format profile
    Credential(CredentialFormatProfile),

    /// Acceptance token
    AcceptanceToken(String),
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
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CredentialIssuerEvaluateRequestResponse {
    /// Proof of possession, wrapping [`ProofOfPossession`]
    pub proof_of_possession: Option<ProofOfPossession>,

    /// Identifier of the recipient. This identifier can be used when sending the credential.
    pub subject_id: Option<String>,
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

/// Response structure for a `credential_success`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CredentialSuccessResponse {
    /// JSON string denoting the format of the issued Credential.
    format: String,

    /// Contains issued Credential. MUST be present when `acceptance_token` is not returned. MAY be a
    /// JSON string or a JSON object, depending on the Credential format. See Appendix E of the
    /// [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#format_profiles)
    /// for the Credential format specific encoding requirements.
    credential: Option<CredentialFormatProfileOrEncoded>,

    /// A JSON string containing a security token subsequently used to obtain a Credential. MUST be
    /// present when credential is not returned.
    acceptance_token: Option<String>,

    /// JSON string containing a nonce to be used to create a proof of possession of key material
    /// when requesting a Credential (see Section 7.2 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#credential_request)).
    /// When received, the Wallet MUST use this nonce value for its subsequent credential requests
    /// until the Credential Issuer provides a fresh nonce.
    c_nonce: Option<String>,

    /// JSON integer denoting the lifetime in seconds of the c_nonce.
    c_nonce_expires_in: Option<u32>,
}

/// Struct value as a union for the input to either contain a `c_nonce` and a `c_nonce_expires_in` as
/// a [`Option<u32>`]. These values always have to be supplied together.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash)]
pub struct CNonce {
    /// JSON string containing a nonce to be used to create a proof of possession of key material
    /// when requesting a Credential (see Section 7.2 of the [openidvci
    /// specifciation](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.2)).
    /// When received, the Wallet MUST use this nonce value for its subsequent credential requests
    /// until the Credential Issuer provides a fresh nonce.
    pub c_nonce: String,

    /// JSON integer denoting the lifetime in seconds of the `c_nonce`.
    pub c_nonce_expires_in: Option<u32>,
}

/// Additional options for validation of the credential request
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct EvaluateCredentialRequestOptions {
    /// Additional nonce options for validation
    pub c_nonce: Option<CNonceOptions>,

    /// Id of the client that will be checked whether it is equal to the `iss` field inside the
    /// `JWT` proof
    ///
    /// For the Pre-Authorized Code Grant Type, authentication of the client is OPTIONAL, as
    /// described in Section 3.2.1 of OAuth 2.0 [RFC6749](https://www.rfc-editor.org/info/rfc6749)
    /// and consequently, the "client_id" is only needed when a form of Client Authentication that
    /// relies on the parameter is used.
    ///
    /// We deal with it being `OPTIONAL` by using the following algorithm:
    ///
    /// - If pre-authorized flow is used:
    ///     - If `client_id` is supplied:
    ///         - validate the `client_id` with the `iss` field in the `JWT`
    ///     - if `client_id` is not supplied:
    ///         - Do not validate even if the `iss` field is supplied within the `JWT`
    /// - if authorized code flow is used:
    ///     - validate the `client_id` with the `iss` field inside the `JWT`
    pub client_id: Option<String>,
}

/// Extra nonce options for validation
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct CNonceOptions {
    /// Lifetime of the nonce from [``Utc::now`] in seconds
    pub c_nonce_expires_in: u32,

    /// Expected nonce in the `JWT`
    pub expected_c_nonce: String,

    /// Timestamp of when the nonce was created
    pub c_nonce_created_at: DateTime<Utc>,
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
        credentials: Vec<CredentialOfferFormatOrId>,
        credential_offer_endpoint: &Option<String>,
        authorized_code_flow: &Option<AuthorizedCodeFlow>,
        pre_authorized_code_flow: &Option<PreAuthorizedCodeFlow>,
    ) -> CredentialIssuerResult<(CredentialOffer, String)> {
        issuer_metadata.validate()?;

        // authorized code flow is only supported for now
        if authorized_code_flow.is_some() {
            return Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        }

        for c in &credentials {
            c.assert_id_in_issuer_metadata(issuer_metadata)?;
        }

        // Create a credential offer based on the input
        let credential_offer = CredentialOffer {
            credential_issuer: issuer_metadata.credential_issuer.clone(),
            credentials,
            grants: Grants {
                authorized_code_flow: authorized_code_flow.clone(),
                pre_authorized_code_flow: pre_authorized_code_flow.clone(),
            },
        };

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
            jwt.extract_did()?
        } else {
            None
        };

        Ok(PreEvaluateCredentialRequestResponse { did })
    }

    /// Evaluate a credential request
    ///
    /// # Errors
    ///
    /// - When a credential offer is not supplied
    /// - When authorization server metadata is supplied
    /// - When incorrect valdiation happens on the supplied input arguments
    /// - when the `c_nonce` is expired
    /// - When a JWT is inside the proof and is not valid
    /// - When the `client_id` is not inside the `JWT` as `iss`
    /// - When the `issuer_metadata.credential_issuer` is not equal to `aud` inside the `JWT`
    pub fn evaluate_credential_request(
        issuer_metadata: &CredentialIssuerMetadata,
        credential_request: &CredentialRequest,
        credential_offer: Option<&CredentialOffer>,
        authorization_server_metadata: Option<&AuthorizationServerMetadata>,
        did_document: Option<&ssi_dids::Document>,
        evaluate_credential_request_options: Option<EvaluateCredentialRequestOptions>,
    ) -> CredentialIssuerResult<CredentialIssuerEvaluateRequestResponse> {
        issuer_metadata.validate()?;

        let credential_offer =
            credential_offer.ok_or(CredentialIssuerError::CredentialOfferMustBeSupplied)?;

        if let Some(authorization_server_metadata) = authorization_server_metadata {
            authorization_server_metadata.validate()?;
            return Err(CredentialIssuerError::AuthorizationServerMetadataNotSupported);
        };

        if let Some(c_nonce_options) = evaluate_credential_request_options
            .clone()
            .and_then(|o| o.c_nonce)
        {
            let expiry_timestamp = c_nonce_options.c_nonce_created_at
                + Duration::seconds(c_nonce_options.c_nonce_expires_in.into());
            let now = Utc::now();

            if expiry_timestamp < now {
                return Err(CredentialIssuerError::CNonceIsExpired {
                    now,
                    expiry_timestamp,
                });
            }
        }

        if let Some(CredentialRequestProof { jwt, .. }) = &credential_request.proof {
            let jwt = ProofJwt::from_str(jwt)?;
            jwt.validate()?;

            let expected_c_nonce = evaluate_credential_request_options
                .clone()
                .and_then(|o| o.c_nonce)
                .map(|c| c.expected_c_nonce);
            jwt.check_nonce(expected_c_nonce)?;

            let expected_issuer = evaluate_credential_request_options
                .clone()
                .and_then(|o| o.client_id);

            let should_validate_iss = match evaluate_credential_request_options {
                Some(EvaluateCredentialRequestOptions { client_id, .. }) => {
                    // We validate when the `client_id` has a value OR when the authorized code
                    // flow is chosen.
                    let should_validate = client_id.is_some()
                        || credential_offer.grants.authorized_code_flow.is_some();

                    // We do not validate when the `client_is` is none AND when the
                    // pre-authorized code flow is used.
                    let should_not_validate = client_id.is_none()
                        && credential_offer.grants.pre_authorized_code_flow.is_some();

                    // Here we choose the stricted combination which only results in no validation
                    // when:
                    //
                    // 1. pre-authorized code flow is ONLY chosen
                    // 2. supplied `client_id` is none
                    //
                    // Every other case will be validated
                    should_validate || !should_not_validate
                }
                None => false,
            };

            if should_validate_iss {
                jwt.check_iss(expected_issuer)?;
            }

            jwt.check_aud(&issuer_metadata.credential_issuer)?;

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
                subject_id: jwt.extract_did()?,
            });
        }

        Err(CredentialIssuerError::NoProofInCredentialRequest)
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
    ) -> CredentialIssuerResult<(CredentialSuccessResponse, DateTime<Utc>)> {
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

        Ok((response, Utc::now()))
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
    use super::*;
    use crate::{
        credential_issuer::error::CredentialIssuerError,
        types::{credential::LinkedDataContext, credential_offer::CredentialOfferFormat, ldp_vc},
    };

    #[test]
    fn happy_flow() {
        let (offer, url) = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            vec![CredentialOfferFormatOrId::CredentialOfferFormat(
                CredentialOfferFormat::LdpVc(ldp_vc::CredentialOffer {
                    credential_definition: ldp_vc::CredentialDefinition {
                        context: vec![LinkedDataContext::String("some_context".to_owned())],
                        types: vec!["type_one".to_owned()],
                    },
                }),
            )],
            &None,
            &None,
            &Some(PreAuthorizedCodeFlow {
                code: "ABC".to_owned(),
                user_pin_required: None,
            }),
        )
        .expect("Unable to create the credential offer");

        assert_eq!(url, "openid-credential-offer://credential_offer=%7B%22credential_issuer%22%3A%22%22%2C%22credentials%22%3A%5B%7B%22credentialDefinition%22%3A%7B%22%40context%22%3A%5B%22some_context%22%5D%2C%22types%22%3A%5B%22type_one%22%5D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22ABC%22%7D%7D%7D");

        assert_eq!(offer.credential_issuer, String::new());

        assert!(offer.grants.pre_authorized_code_flow.is_some());
        assert!(offer.grants.authorized_code_flow.is_none());
    }

    #[test]
    fn should_error_when_using_authorized_flow() {
        let result = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            vec![],
            &Some(String::default()),
            &Some(AuthorizedCodeFlow { issuer_state: None }),
            &None,
        );
        let expect = Err(CredentialIssuerError::AuthorizedFlowNotSupported);
        assert_eq!(result, expect);
    }

    #[test]
    fn should_error_when_supplying_credential_id_that_is_not_in_issuer_metadata() {
        let id = "id_one".to_owned();

        let result = CredentialIssuer::create_offer(
            &CredentialIssuerMetadata::default(),
            vec![CredentialOfferFormatOrId::Id(id.clone())],
            &Some(String::default()),
            &None,
            &Some(PreAuthorizedCodeFlow::default()),
        );
        let expect = Err(CredentialIssuerError::ValidationError(
            ValidationError::Any {
                validation_message: format!("id `{id}` not found in the issuer metadata"),
            },
        ));
        assert_eq!(result, expect);
    }
}

#[cfg(test)]
mod test_pre_evaluate_credential_request {
    use super::*;
    use crate::{
        jwt::error::JwtError,
        types::{
            credential_request::CredentialRequestFormat,
            ldp_vc::{self, CredentialDefinition},
        },
    };

    #[test]
    fn happy_flow() {
        let credential_request = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
        }),
        format: CredentialRequestFormat::LdpVc(ldp_vc::CredentialRequest {credential_definition: CredentialDefinition { context: vec![], types: vec![] }}),
    };

        let response = CredentialIssuer::pre_evaluate_credential_request(&credential_request)
            .expect("Unable to to pre evaluate the credential request");

        assert_eq!(
            response.did,
            Some("did:example:ebfeb1f712ebc6f1c276e12ec21".to_owned())
        );
    }

    #[test]
    fn should_not_work_with_jwk() {
        let credential_request: CredentialRequest = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "eyJqd2siOiJ1bmtub3duIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned()
        }),
        format: CredentialRequestFormat::LdpVc(ldp_vc::CredentialRequest {credential_definition: CredentialDefinition { context: vec![], types: vec![] }}),
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
    use super::*;
    use crate::{
        jwt::error::JwtError,
        types::{
            credential_request::CredentialRequestFormat,
            ldp_vc::{self, CredentialDefinition},
        },
    };
    use ssi_dids::Document;

    fn valid_credential_format_profile() -> serde_json::Value {
        serde_json::json!({
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
        })
    }

    fn valid_issuer_metadata() -> CredentialIssuerMetadata {
        serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://server.example.com",
            "credential_endpoint": "https://example.org",
            "credentials_supported": [
                valid_credential_format_profile(),
            ],
        }))
        .expect("Unable to create issuer metadata")
    }

    fn invalid_issuer_metadata_wrong_credential_issuer() -> CredentialIssuerMetadata {
        serde_json::from_value(serde_json::json!({
            "credential_issuer": "some-invalid-id",
            "credential_endpoint": "https://example.org",
            "credentials_supported": [
                valid_credential_format_profile(),
            ],
        }))
        .expect("Unable to create issuer metadata")
    }

    fn valid_credential_request_format() -> CredentialRequestFormat {
        CredentialRequestFormat::LdpVc(ldp_vc::CredentialRequest {
            credential_definition: CredentialDefinition {
                types: vec![],
                context: vec![],
            },
        })
    }

    fn valid_credential_request() -> CredentialRequest {
        CredentialRequest {
         proof: Some(CredentialRequestProof {
             proof_type: "jwt".to_owned(),
             jwt: "ewogICJraWQiOiAiZGlkOmtleTp6Nk1rcFRIUjhWTnNCeFlBQVdIdXQyR2VhZGQ5alN3dUJWOHhSb0Fud1dzZHZrdEgjejZNa3BUSFI4Vk5zQnhZQUFXSHV0MkdlYWRkOWpTd3VCVjh4Um9BbndXc2R2a3RIIiwKICAiYWxnIjogIkVkRFNBIiwKICAidHlwIjogIm9wZW5pZDR2Y2ktcHJvb2Yrand0Igp9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
         }),
         format:  valid_credential_request_format()   }
    }

    fn valid_authorized_server_metadata() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {}
    }

    fn valid_did_document() -> Document {
        serde_json::from_value(serde_json::json!({
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
        })).expect("Unable to create did document")
    }

    fn valid_credential_offer() -> CredentialOffer {
        let (credential_offer, _) = CredentialIssuer::create_offer(
            &valid_issuer_metadata(),
            vec![CredentialOfferFormatOrId::Id(
                "UniversityDegree_JWT".to_owned(),
            )],
            &Some(String::default()),
            &None,
            &Some(PreAuthorizedCodeFlow::default()),
        )
        .expect("Unable to create credential offer");

        credential_offer
    }

    fn valid_evaluate_credential_request_options() -> EvaluateCredentialRequestOptions {
        EvaluateCredentialRequestOptions {
            c_nonce: Some(CNonceOptions {
                c_nonce_expires_in: 1000,
                expected_c_nonce: "tZignsnFbp".to_owned(),
                c_nonce_created_at: Utc::now(),
            }),
            client_id: Some("s6BhdRkqt3".to_owned()),
        }
    }

    fn invalid_evaluate_credential_request_options_mismatch_nonce(
    ) -> EvaluateCredentialRequestOptions {
        EvaluateCredentialRequestOptions {
            c_nonce: Some(CNonceOptions {
                c_nonce_expires_in: 1000,
                expected_c_nonce: "some_invalid_nonce".to_owned(),
                c_nonce_created_at: Utc::now(),
            }),
            client_id: Some("s6BhdRkqt3".to_owned()),
        }
    }

    fn invalid_evaluate_credential_request_options_expired_nonce(
    ) -> EvaluateCredentialRequestOptions {
        EvaluateCredentialRequestOptions {
            c_nonce: Some(CNonceOptions {
                c_nonce_expires_in: 1000,
                expected_c_nonce: "tZignsnFbp".to_owned(),
                c_nonce_created_at: Utc::now() - Duration::hours(100),
            }),
            client_id: Some("s6BhdRkqt3".to_owned()),
        }
    }

    fn valid_evaluate_credential_request_options_pre_authorized_code_flow_and_no_client_id_to_check(
    ) -> EvaluateCredentialRequestOptions {
        EvaluateCredentialRequestOptions {
            c_nonce: Some(CNonceOptions {
                c_nonce_expires_in: 1000,
                expected_c_nonce: "tZignsnFbp".to_owned(),
                c_nonce_created_at: Utc::now(),
            }),
            client_id: None,
        }
    }

    #[test]
    fn should_evaluate_credential_request() {
        let issuer_metadata = valid_issuer_metadata();
        let did_document = valid_did_document();
        let credential_request = valid_credential_request();
        let credential_offer = valid_credential_offer();
        let evaluate_credential_request_options = valid_evaluate_credential_request_options();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            None,
            Some(&did_document),
            Some(evaluate_credential_request_options),
        )
        .expect("Unable to evaluate credential request");

        assert_eq!(
            evaluated.subject_id,
            Some("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned())
        );

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
                120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 34, 44, 34, 115, 117, 98, 34, 58,
                110, 117, 108, 108, 44, 34, 105, 97, 116, 34, 58, 34, 50, 48, 49, 56, 45, 48, 57,
                45, 49, 52, 84, 50, 49, 58, 49, 57, 58, 49, 48, 90, 34, 44, 34, 110, 111, 110, 99,
                101, 34, 58, 34, 116, 90, 105, 103, 110, 115, 110, 70, 98, 112, 34, 125, 46
            ]
        );

        assert_eq!(
            evaluated.signature,
            vec![
                101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 34, 44, 34, 115, 117, 98, 34,
                58, 110, 117, 108, 108, 44, 34, 105, 97, 116, 34, 58, 34, 50, 48, 49, 56, 45, 48,
                57, 45, 49, 52, 84, 50, 49, 58, 49, 57, 58, 49, 48, 90, 34, 44, 34, 110, 111, 110,
                99, 101, 34, 58, 34, 116, 90, 105, 103, 110, 115, 110, 70, 98, 112, 34, 125, 46
            ]
        );
    }

    #[test]
    fn should_not_evaluate_credential_request_without_offer() {
        let issuer_metadata = valid_issuer_metadata();
        let did_document = valid_did_document();
        let credential_request = valid_credential_request();
        let evaluate_credential_request_options = valid_evaluate_credential_request_options();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            None,
            None,
            Some(&did_document),
            Some(evaluate_credential_request_options),
        );

        assert_eq!(
            evaluated,
            Err(CredentialIssuerError::CredentialOfferMustBeSupplied)
        );
    }

    #[test]
    fn should_not_evaluate_credential_request_with_authorized_server_metadata() {
        let issuer_metadata = valid_issuer_metadata();
        let did_document = valid_did_document();
        let credential_offer = valid_credential_offer();
        let authorized_server_metadata = valid_authorized_server_metadata();
        let credential_request = valid_credential_request();
        let evaluate_credential_request_options = valid_evaluate_credential_request_options();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            Some(&authorized_server_metadata),
            Some(&did_document),
            Some(evaluate_credential_request_options),
        );

        assert_eq!(
            evaluated,
            Err(CredentialIssuerError::AuthorizationServerMetadataNotSupported)
        );
    }

    #[test]
    fn should_not_evaluate_credential_request_without_did_document_when_kid_in_jwk() {
        let issuer_metadata = valid_issuer_metadata();
        let credential_request = valid_credential_request();
        let credential_offer = valid_credential_offer();
        let evaluate_credential_request_options = valid_evaluate_credential_request_options();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            None,
            None,
            Some(evaluate_credential_request_options),
        );

        assert_eq!(
            evaluated,
            Err(CredentialIssuerError::JwtError(
                JwtError::NoDidDocumentProvidedForKidAsDid
            ))
        );
    }

    #[test]
    fn should_not_evaluate_credential_request_with_nonce_mismatch() {
        let issuer_metadata = valid_issuer_metadata();
        let credential_request = valid_credential_request();
        let did_document = valid_did_document();
        let credential_offer = valid_credential_offer();
        let evaluate_credential_request_options =
            invalid_evaluate_credential_request_options_mismatch_nonce();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            None,
            Some(&did_document),
            Some(evaluate_credential_request_options),
        );

        assert_eq!(
            evaluated,
            Err(CredentialIssuerError::JwtError(JwtError::NonceMismatch {
                expected_nonce: Some("some_invalid_nonce".to_owned()),
                actual_nonce: "tZignsnFbp".to_owned()
            }))
        );
    }

    #[test]
    fn should_not_evaluate_credential_request_with_expired_nonce() {
        let issuer_metadata = valid_issuer_metadata();
        let credential_request = valid_credential_request();
        let did_document = valid_did_document();
        let credential_offer = valid_credential_offer();
        let evaluate_credential_request_options =
            invalid_evaluate_credential_request_options_expired_nonce();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            None,
            Some(&did_document),
            Some(evaluate_credential_request_options),
        );

        assert!(matches!(
            evaluated,
            Err(CredentialIssuerError::CNonceIsExpired { .. })
        ));
    }

    #[test]
    fn should_evaluate_credential_request_with_when_pre_authorized_code_flow_is_used_and_no_client_id(
    ) {
        let issuer_metadata = valid_issuer_metadata();
        let credential_request = valid_credential_request();
        let did_document = valid_did_document();
        let credential_offer = valid_credential_offer();
        let evaluate_credential_request_options =
            valid_evaluate_credential_request_options_pre_authorized_code_flow_and_no_client_id_to_check();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            None,
            Some(&did_document),
            Some(evaluate_credential_request_options),
        );

        assert!(evaluated.is_ok());
    }

    #[test]
    fn should_not_evaluate_credential_request_with_credential_issuer_mismatch_in_metadata_and_proof(
    ) {
        let issuer_metadata = invalid_issuer_metadata_wrong_credential_issuer();
        let credential_request = valid_credential_request();
        let did_document = valid_did_document();
        let credential_offer = valid_credential_offer();
        let evaluate_credential_request_options = valid_evaluate_credential_request_options();

        let evaluated = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            Some(&credential_offer),
            None,
            Some(&did_document),
            Some(evaluate_credential_request_options),
        );

        assert_eq!(
            evaluated,
            Err(CredentialIssuerError::JwtError(
                JwtError::AudienceMismatch {
                    expected_aud_in_jwt: "some-invalid-id".to_owned(),
                    actual_aud_in_jwt: "https://server.example.com".to_owned()
                }
            ))
        );
    }
}

#[cfg(test)]
mod test_create_credential_success_response {
    use super::*;
    use crate::{
        base::base64url,
        types::{
            credential_request::CredentialRequestFormat,
            ldp_vc::{self, CredentialDefinition},
        },
    };

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
         format: CredentialRequestFormat::LdpVc(ldp_vc::CredentialRequest { credential_definition: CredentialDefinition {types: vec![],context: vec![]} }),
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
            .0
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

        assert_eq!(success_response.0.format, "ldp_vc");
        assert_eq!(
            credential,
            serde_json::from_value(cfp).expect("Unable to create cfp")
        );
        assert_eq!(success_response.0.acceptance_token, None);
        assert_eq!(success_response.0.c_nonce, Some("nonce".to_owned()));
        assert_eq!(success_response.0.c_nonce_expires_in, Some(10));
    }
}
