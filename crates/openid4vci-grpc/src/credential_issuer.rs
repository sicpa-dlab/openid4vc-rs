use crate::error::{GrpcError, GrpcResult};
use crate::grpc_openid4vci::credential_issuer_service_server::CredentialIssuerService;
use crate::grpc_openid4vci::{
    create_credential_error_response_response, create_credential_offer_response,
    create_credential_success_response_response, evaluate_credential_request_response,
    pre_evaluate_credential_request_response, CreateCredentialErrorResponseRequest,
    CreateCredentialErrorResponseResponse, CreateCredentialSuccessResponseRequest,
    CreateCredentialSuccessResponseResponse, PreEvaluateCredentialRequestRequest,
    PreEvaluateCredentialRequestResponse,
};
use crate::utils::{
    deserialize_optional_slice, deserialize_slice, serialize_to_optional_slice, serialize_to_slice,
};
use crate::CreateCredentialOfferResponse;
use crate::{
    CreateCredentialOfferRequest, EvaluateCredentialRequestRequest,
    EvaluateCredentialRequestResponse,
};
use openid4vci::credential_issuer::error::CredentialIssuerError;
use openid4vci::credential_issuer::error_code::CredentialIssuerErrorCode;
use openid4vci::credential_issuer::{
    AuthorizedCodeFlow, CNonce, CredentialIssuer, CredentialOffer, CredentialOrAcceptanceToken,
    CredentialOrIds, EvaluateCredentialRequestOptions, PreAuthorizedCodeFlow,
};
use openid4vci::types::authorization_server_metadata::AuthorizationServerMetadata;
use openid4vci::types::credential_issuer_metadata::CredentialIssuerMetadata;
use openid4vci::types::credential_request::CredentialRequest;
use openid4vci::Document;
use tonic::{Request, Response};

/// Issuer structure to implement `gRPC` traits on.
///
/// This wraps mainly around [`CredentialIssuer`]
#[derive(Debug, Default)]
pub struct GrpcCredentialIssuer;

#[tonic::async_trait]
impl CredentialIssuerService for GrpcCredentialIssuer {
    async fn create_credential_offer(
        &self,
        request: Request<CreateCredentialOfferRequest>,
    ) -> GrpcResult<Response<CreateCredentialOfferResponse>> {
        let CreateCredentialOfferRequest {
            issuer_metadata,
            authorized_code_flow,
            pre_authorized_code_flow,
            credential_offer_endpoint,
            credentials,
        } = request.into_inner();

        let issuer_metadata = deserialize_slice::<CredentialIssuerMetadata>(&issuer_metadata)?;

        let authorized_code_flow =
            deserialize_optional_slice::<AuthorizedCodeFlow>(&authorized_code_flow)?;

        let pre_authorized_code_flow =
            deserialize_optional_slice::<PreAuthorizedCodeFlow>(&pre_authorized_code_flow)?;

        let credentials = deserialize_slice::<CredentialOrIds>(&credentials)?;

        let response = match CredentialIssuer::create_offer(
            &issuer_metadata,
            credentials,
            &credential_offer_endpoint,
            &authorized_code_flow,
            &pre_authorized_code_flow,
        )
        .map_err(GrpcError::CredentialIssuerError)
        {
            Ok(response) => create_credential_offer_response::Response::Success(
                create_credential_offer_response::Success {
                    credential_offer: serialize_to_slice(response.0)?,
                    credential_offer_url: response.1,
                },
            ),
            Err(e) => create_credential_offer_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(CreateCredentialOfferResponse {
            response: Some(response),
        }))
    }

    async fn pre_evaluate_credential_request(
        &self,
        request: Request<PreEvaluateCredentialRequestRequest>,
    ) -> GrpcResult<Response<PreEvaluateCredentialRequestResponse>> {
        let PreEvaluateCredentialRequestRequest { credential_request } = request.into_inner();

        let credential_request = deserialize_slice::<CredentialRequest>(&credential_request)?;

        let response = match CredentialIssuer::pre_evaluate_credential_request(&credential_request)
            .map_err(GrpcError::CredentialIssuerError)
        {
            Ok(response) => pre_evaluate_credential_request_response::Response::Success(
                pre_evaluate_credential_request_response::Success { did: response.did },
            ),
            Err(e) => pre_evaluate_credential_request_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(PreEvaluateCredentialRequestResponse {
            response: Some(response),
        }))
    }

    async fn evaluate_credential_request(
        &self,
        request: Request<EvaluateCredentialRequestRequest>,
    ) -> GrpcResult<Response<EvaluateCredentialRequestResponse>> {
        let EvaluateCredentialRequestRequest {
            issuer_metadata,
            credential_request,
            credential_offer,
            did_document,
            authorization_server_metadata,
            evaluate_credential_request_options,
        } = request.into_inner();

        let issuer_metadata = deserialize_slice::<CredentialIssuerMetadata>(&issuer_metadata)?;

        let credential_request = deserialize_slice::<CredentialRequest>(&credential_request)?;

        let credential_offer = deserialize_optional_slice::<CredentialOffer>(&credential_offer)?;

        let authorization_server_metadata = deserialize_optional_slice::<
            AuthorizationServerMetadata,
        >(&authorization_server_metadata)?;

        let did_document = deserialize_optional_slice::<Document>(&did_document)?;

        let evaluate_credential_request_options = deserialize_optional_slice::<
            EvaluateCredentialRequestOptions,
        >(&evaluate_credential_request_options)?;

        let response = match CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            credential_offer.as_ref(),
            authorization_server_metadata.as_ref(),
            did_document.as_ref(),
            evaluate_credential_request_options,
        )
        .map_err(GrpcError::CredentialIssuerError)
        {
            Ok(response) => evaluate_credential_request_response::Response::Success(
                evaluate_credential_request_response::Success {
                    proof_of_possession: serialize_to_optional_slice(response.proof_of_possession)?,
                },
            ),
            Err(e) => evaluate_credential_request_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(EvaluateCredentialRequestResponse {
            response: Some(response),
        }))
    }

    async fn create_credential_success_response(
        &self,
        request: Request<CreateCredentialSuccessResponseRequest>,
    ) -> GrpcResult<Response<CreateCredentialSuccessResponseResponse>> {
        let CreateCredentialSuccessResponseRequest {
            credential_request,
            credential,
            acceptance_token,
            c_nonce,
            c_nonce_expires_in,
        } = request.into_inner();

        let credential_request = deserialize_slice::<CredentialRequest>(&credential_request)?;

        let credential_or_acceptance_token = match (credential, acceptance_token) {
            (None, None) => Ok(None),
            (None, Some(token)) => Ok(Some(CredentialOrAcceptanceToken::AcceptanceToken(token))),
            (Some(credential), None) => {
                let credential = deserialize_slice(&credential)?;
                Ok(Some(CredentialOrAcceptanceToken::Credential(credential)))
            }
            (Some(_), Some(_)) => Err(GrpcError::CredentialIssuerError(
                CredentialIssuerError::CredentialAndAcceptanceTokenSupplied,
            )),
        }?;

        let c_nonce = c_nonce.map(|c_nonce| CNonce {
            c_nonce,
            c_nonce_expires_in,
        });

        let response = match CredentialIssuer::create_credential_success_response(
            &credential_request,
            credential_or_acceptance_token,
            c_nonce,
        )
        .map_err(GrpcError::CredentialIssuerError)
        {
            Ok((response, created_at)) => {
                create_credential_success_response_response::Response::Success(
                    create_credential_success_response_response::Success {
                        success_response: serialize_to_slice(response)?,
                        created_at: created_at.to_string(),
                    },
                )
            }
            Err(e) => create_credential_success_response_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(CreateCredentialSuccessResponseResponse {
            response: Some(response),
        }))
    }

    async fn create_credential_error_response(
        &self,
        request: Request<CreateCredentialErrorResponseRequest>,
    ) -> GrpcResult<Response<CreateCredentialErrorResponseResponse>> {
        let CreateCredentialErrorResponseRequest {
            error,
            error_description,
            error_uri,
            error_additional_details,
        } = request.into_inner();

        let error =
            CredentialIssuerErrorCode::try_from(error).map_err(GrpcError::ValidationError)?;
        let error_additional_details = deserialize_optional_slice(&error_additional_details)?;

        let response = match CredentialIssuer::create_credential_error_response(
            &error,
            error_description,
            error_uri,
            error_additional_details,
        )
        .map_err(GrpcError::CredentialIssuerError)
        {
            Ok(response) => create_credential_error_response_response::Response::Success(
                create_credential_error_response_response::Success {
                    error_response: serialize_to_slice(response)?,
                },
            ),
            Err(e) => create_credential_error_response_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(CreateCredentialErrorResponseResponse {
            response: Some(response),
        }))
    }
}

#[cfg(test)]
mod credential_issuer_tests {
    use chrono::Utc;
    use openid4vci::{
        credential_issuer::{CNonceOptions, CredentialOfferGrants},
        types::{credential::CredentialFormatProfile, credential_request::CredentialRequestProof},
    };

    use crate::grpc_openid4vci::Error;

    use super::*;

    #[tokio::test]
    async fn should_create_minimal_offer() {
        let issuer = GrpcCredentialIssuer::default();

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

        let issuer_metadata = serde_json::json!({
            "credential_issuer": "01001110",
            "credential_endpoint": "https://example.org",
            "credentials_supported": [
                &cfp
            ],
        })
        .to_string()
        .as_bytes()
        .to_vec();

        let credentials = serde_json::json!([&cfp]).to_string().as_bytes().to_vec();

        let message = CreateCredentialOfferRequest {
            issuer_metadata,
            credentials,
            authorized_code_flow: None,
            pre_authorized_code_flow: None,
            credential_offer_endpoint: None,
        };

        issuer
            .create_credential_offer(Request::new(message))
            .await
            .expect("Unable to create offer");
    }

    #[tokio::test]
    async fn should_error_when_authorized_is_provided() {
        let issuer = GrpcCredentialIssuer::default();

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

        let issuer_metadata = serde_json::json!({
            "credential_issuer": "01001110",
            "credential_endpoint": "https://example.org",
            "credentials_supported": [
                &cfp
            ],
        })
        .to_string()
        .as_bytes()
        .to_vec();

        let credentials = serde_json::json!([&cfp]).to_string().as_bytes().to_vec();

        let authorized_code_flow = serde_json::json!({
            "issuer_state": "abc"
        })
        .to_string()
        .as_bytes()
        .to_vec();

        let message = CreateCredentialOfferRequest {
            issuer_metadata,
            credentials,
            authorized_code_flow: Some(authorized_code_flow),
            pre_authorized_code_flow: None,
            credential_offer_endpoint: None,
        };

        let message = issuer
            .create_credential_offer(Request::new(message))
            .await
            .expect("Unable to create offer with error")
            .into_inner();

        let expected = create_credential_offer_response::Response::Error(Error {
            code: 102,
            name: "AuthorizedFlowNotSupported".to_owned(),
            description: "The Authorized flow is currently not supported".to_owned(),
            additional_information: None,
        });

        assert_eq!(message.response, Some(expected));
    }

    #[tokio::test]
    async fn should_pre_evaluate_request() {
        let expected = pre_evaluate_credential_request_response::Success {
            did: Some("did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1".to_owned()),
        };

        let issuer = GrpcCredentialIssuer::default();

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

        let credential_request = serde_json::to_vec(&credential_request)
            .expect("Unable to serialize credential request");

        let request =
            tonic::Request::new(PreEvaluateCredentialRequestRequest { credential_request });
        let response = issuer
            .pre_evaluate_credential_request(request)
            .await
            .expect("Unable to send request")
            .into_inner();

        assert_eq!(
            response.response,
            Some(pre_evaluate_credential_request_response::Response::Success(
                expected
            ))
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn should_evaluate_credential_request() {
        let issuer = GrpcCredentialIssuer::default();

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

        let issuer_metadata = serde_json::json!({
            "credential_issuer": "https://server.example.com",
            "credential_endpoint": "https://example.org",
            "credentials_supported": [
                &cfp
            ],
        })
        .to_string()
        .as_bytes()
        .to_vec();

        let credential_request = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "ewogICJraWQiOiAiZGlkOmtleTp6Nk1rcFRIUjhWTnNCeFlBQVdIdXQyR2VhZGQ5alN3dUJWOHhSb0Fud1dzZHZrdEgjejZNa3BUSFI4Vk5zQnhZQUFXSHV0MkdlYWRkOWpTd3VCVjh4Um9BbndXc2R2a3RIIiwKICAiYWxnIjogIkVkRFNBIiwKICAidHlwIjogIm9wZW5pZDR2Y2ktcHJvb2Yrand0Igp9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned()
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
        }

            );

        let did_document: Document =
            serde_json::from_value(did_document).expect("Unable to deserialize did_document");

        let did_document =
            serde_json::to_vec(&did_document).expect("Unable to serialize did_document");

        let credential_request = serde_json::to_vec(&credential_request)
            .expect("Unable to serialize credential request");

        let credential_offer = CredentialOffer {
            credential_issuer: "https://server.example.com".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: Some(AuthorizedCodeFlow { issuer_state: None }),
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: Some(true),
                }),
            },
        };

        let credential_offer =
            serde_json::to_vec(&credential_offer).expect("Unable to serialize credential offer");

        let options = EvaluateCredentialRequestOptions {
            c_nonce: Some(CNonceOptions {
                expected_c_nonce: "tZignsnFbp".to_owned(),
                c_nonce_expires_in: 1000,
                c_nonce_created_at: Utc::now(),
            }),
            client_id: Some("s6BhdRkqt3".to_owned()),
        };

        let options = serde_json::to_vec(&options).expect("Unable to serialize options");

        let request = tonic::Request::new(EvaluateCredentialRequestRequest {
            credential_request,
            did_document: Some(did_document),
            issuer_metadata,
            credential_offer: Some(credential_offer),
            authorization_server_metadata: None,
            evaluate_credential_request_options: Some(options),
        });
        let response = issuer
            .evaluate_credential_request(request)
            .await
            .expect("Unable to send request")
            .into_inner();
        let response = response.response.expect("No response found");

        let response = match response {
            evaluate_credential_request_response::Response::Success(s) => s.proof_of_possession,
            evaluate_credential_request_response::Response::Error(e) => {
                let additional_information = e.additional_information();
                let additional_information: serde_json::Value =
                    deserialize_slice(additional_information).expect("Unable to deserialize");
                panic!(
                    "[ERROR]: {:#?} \n info: {:#?}",
                    e.description, additional_information
                );
            }
        };

        assert!(response.is_some());
    }
}
