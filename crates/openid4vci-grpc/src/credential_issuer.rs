use crate::error::{GrpcError, Result};
use crate::grpc_openid4vci::credential_issuer_service_server::CredentialIssuerService;
use crate::grpc_openid4vci::{
    PreEvaluateCredentialRequestRequest, PreEvaluateCredentialRequestResponse,
};
use crate::utils::{deserialize_optional_slice, deserialize_slice, serialize_to_slice, serialize_to_optional_slice};
use crate::CreateCredentialOfferResponse;
use crate::{
    CreateCredentialOfferRequest, EvaluateCredentialRequestRequest,
    EvaluateCredentialRequestResponse,
};
use openid4vci::credential_issuer::{
    AuthorizedCodeFlow, CredentialIssuer, CredentialIssuerEvaluateRequestResponse, CredentialOffer,
    CredentialOrIds, PreAuthorizedCodeFlow,
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
    ) -> Result<Response<CreateCredentialOfferResponse>> {
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

        let (credential_offer, credential_offer_url) = CredentialIssuer::create_offer(
            &issuer_metadata,
            credentials,
            &credential_offer_endpoint,
            &authorized_code_flow,
            &pre_authorized_code_flow,
        )
        .map_err(GrpcError::CredentialIssuerError)?;

        let credential_offer = serialize_to_slice(credential_offer)?;
        let credential_offer_url = credential_offer_url.as_bytes().to_vec();
        let response = CreateCredentialOfferResponse {
            credential_offer,
            credential_offer_url,
        };

        Ok(Response::new(response))
    }

    async fn pre_evaluate_credential_request(
        &self,
        request: Request<PreEvaluateCredentialRequestRequest>,
    ) -> Result<Response<PreEvaluateCredentialRequestResponse>> {
        let PreEvaluateCredentialRequestRequest { credential_request } = request.into_inner();

        let credential_request = deserialize_slice::<CredentialRequest>(&credential_request)?;

        let response = CredentialIssuer::pre_evaluate_credential_request(&credential_request)
            .map_err(GrpcError::CredentialIssuerError)?;

        let response = PreEvaluateCredentialRequestResponse { did: response.did };

        Ok(Response::new(response))
    }

    async fn evaluate_credential_request(
        &self,
        request: Request<EvaluateCredentialRequestRequest>,
    ) -> Result<Response<EvaluateCredentialRequestResponse>> {
        let EvaluateCredentialRequestRequest {
            issuer_metadata,
            credential_request,
            credential_offer,
            did_document,
            authorization_server_metadata,
        } = request.into_inner();

        let issuer_metadata = deserialize_slice::<CredentialIssuerMetadata>(&issuer_metadata)?;

        let credential_request = deserialize_slice::<CredentialRequest>(&credential_request)?;

        let credential_offer = deserialize_optional_slice::<CredentialOffer>(&credential_offer)?;

        let authorization_server_metadata = deserialize_optional_slice::<
            AuthorizationServerMetadata,
        >(&authorization_server_metadata)?;

        let did_document = deserialize_optional_slice::<Document>(&did_document)?;

        let CredentialIssuerEvaluateRequestResponse {
            proof_of_possession,
        } = CredentialIssuer::evaluate_credential_request(
            &issuer_metadata,
            &credential_request,
            credential_offer.as_ref(),
            authorization_server_metadata.as_ref(),
            did_document.as_ref(),
        )
        .map_err(GrpcError::CredentialIssuerError)?;

        let response = EvaluateCredentialRequestResponse {
            proof_of_possession: serialize_to_optional_slice(proof_of_possession)?,
        };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod credential_issuer_tests {
    use openid4vci::types::{
        credential::CredentialFormatProfile, credential_request::CredentialRequestProof,
    };

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

        // A bit of a hacky test as we nest some of the errors and extracting the serialized
        // message is not the intended behaviour
        let message = issuer
            .create_credential_offer(Request::new(message))
            .await
            .unwrap_err();

        let message = message.message();
        let expected =
            openid4vci::credential_issuer::error::CredentialIssuerError::AuthorizedFlowNotSupported;
        assert_eq!(message.to_string(), expected.information().to_string());
    }

    #[tokio::test]
    async fn should_pre_evaluate_request() {
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
            response.did,
            Some("did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1".to_owned())
        );
    }

    #[tokio::test]
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
            "credential_issuer": "01001110",
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

        let request = tonic::Request::new(EvaluateCredentialRequestRequest {
            credential_request,
            did_document: Some(did_document),
            issuer_metadata,
            credential_offer: None,
            authorization_server_metadata: None,
        });
        let response = issuer
            .evaluate_credential_request(request)
            .await
            .expect("Unable to send request")
            .into_inner();

        println!("{response:#?}");
    }
}
