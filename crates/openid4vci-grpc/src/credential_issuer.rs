use crate::error::{GrpcError, Result};
use crate::grpc_openid4vci::credential_issuer_service_server::CredentialIssuerService;
use crate::utils::{deserialize_optional_slice, deserialize_slice, serialize_to_slice};
use crate::CreateOfferRequest;
use crate::CreateOfferResponse;
use openid4vci::credential_issuer::{
    AuthorizedCodeFlow, CredentialIssuer, CredentialOrIds, PreAuthorizedCodeFlow,
};
use openid4vci::types::credential_issuer_metadata::CredentialIssuerMetadata;
use tonic::{Request, Response};

/// Issuer structure to implement `gRPC` traits on.
///
/// This wraps mainly around [`CredentialIssuer`]
#[derive(Debug, Default)]
pub struct GrpcCredentialIssuer;

#[tonic::async_trait]
impl CredentialIssuerService for GrpcCredentialIssuer {
    async fn create_offer(
        &self,
        request: Request<CreateOfferRequest>,
    ) -> Result<Response<CreateOfferResponse>> {
        let CreateOfferRequest {
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
        let response = CreateOfferResponse {
            credential_offer,
            credential_offer_url,
        };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod credential_issuer_tests {
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

        let message = CreateOfferRequest {
            issuer_metadata,
            credentials,
            authorized_code_flow: None,
            pre_authorized_code_flow: None,
            credential_offer_endpoint: None,
        };

        issuer
            .create_offer(Request::new(message))
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

        let message = CreateOfferRequest {
            issuer_metadata,
            credentials,
            authorized_code_flow: Some(authorized_code_flow),
            pre_authorized_code_flow: None,
            credential_offer_endpoint: None,
        };

        // A bit of a hacky test as we nest some of the errors and extracting the serialized
        // message is not the intended behaviour
        let message = issuer
            .create_offer(Request::new(message))
            .await
            .unwrap_err();

        let message = message.message();
        let expected =
            openid4vci::credential_issuer::error::CredentialIssuerError::AuthorizedFlowNotSupported;
        assert_eq!(message.to_string(), expected.information().to_string());
    }
}
