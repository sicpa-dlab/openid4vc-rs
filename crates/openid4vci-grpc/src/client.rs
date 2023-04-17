//! Example client package

use openid4vci::types::credential_request::{CredentialRequest, CredentialRequestProof};
use openid4vci::validate::ValidationError;
use openid4vci::Document;
use openid4vci_grpc::access_token_client::AccessTokenServiceClient;
use openid4vci_grpc::credential_issuer_client::CredentialIssuerServiceClient;
use openid4vci_grpc::error::GrpcError;
use openid4vci_grpc::{
    CreateAccessTokenErrorResponseRequest, CreateAccessTokenSuccessResponseRequest,
    CreateCredentialOfferRequest, EvaluateCredentialRequestRequest,
    PreEvaluateCredentialRequestRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut credential_issuer_client =
        CredentialIssuerServiceClient::connect("http://0.0.0.0:50051").await?;
    let mut access_token_client = AccessTokenServiceClient::connect("http://0.0.0.0:50051").await?;

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

    let request = tonic::Request::new(CreateCredentialOfferRequest {
        issuer_metadata: issuer_metadata.clone(),
        credentials,
        credential_offer_endpoint: None,
        authorized_code_flow: None,
        pre_authorized_code_flow: None,
    });

    let response = credential_issuer_client
        .create_credential_offer(request)
        .await?;
    let response = response.into_inner();

    let credential_offer: serde_json::Value =
        serde_json::from_slice(&response.credential_offer).unwrap();
    let credential_offer_url = String::from_utf8_lossy(&response.credential_offer_url);

    println!("{credential_offer:#?}");
    println!("{credential_offer_url:#?}");

    let request = tonic::Request::new(CreateAccessTokenErrorResponseRequest {
        error: "invalid_request".to_string(),
        error_description: Some("An error".to_string()),
        error_uri: Some("https://uri.com".to_string()),
    });

    let response = access_token_client
        .create_error_response(request)
        .await?
        .into_inner();

    let error_response: serde_json::Value =
        serde_json::from_slice(&response.error_response).unwrap();

    println!("{error_response:#?}");

    let credential_request = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "ewogICJraWQiOiAiZGlkOmtleTp6RG5hZXJEYVRGNUJYRWF2Q3JmUlpFazMxNmRwYkxzZlBEWjNXSjVoUlRQRlUyMTY5I3pEbmFlckRhVEY1QlhFYXZDcmZSWkVrMzE2ZHBiTHNmUERaM1dKNWhSVFBGVTIxNjkiLAogICJhbGciOiAiRWREU0EiLAogICJ0eXAiOiAib3BlbmlkNHZjaS1wcm9vZitqd3QiCn0.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
        }),
        format: openid4vci::types::credential::CredentialFormatProfile::LdpVc {
            context: vec![],
            types: vec![],
            credential_subject: None,
            order: None,
        },
    };
    let credential_request = serde_json::to_vec(&credential_request)?;

    let request = tonic::Request::new(PreEvaluateCredentialRequestRequest { credential_request });
    let response = credential_issuer_client
        .pre_evaluate_credential_request(request)
        .await?
        .into_inner();

    println!("{response:#?}");

    let request = tonic::Request::new(CreateAccessTokenSuccessResponseRequest {
        access_token: "access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        scope: Some("Hello World".to_string()),
        c_nonce: Some("c_nonce".to_string()),
        c_nonce_expires_in: Some(1800),

        authorization_pending: Some(false),
        interval: Some(5),
    });

    let response = access_token_client
        .create_success_response(request)
        .await?
        .into_inner();

    let success_response: serde_json::Value =
        serde_json::from_slice(&response.success_response).unwrap();

    println!("{success_response:#?}");

    let credential_request = CredentialRequest {
        proof: Some(CredentialRequestProof {
            proof_type: "jwt".to_owned(),
            jwt: "ewogICJraWQiOiAiZGlkOmtleTp6Nk1rcFRIUjhWTnNCeFlBQVdIdXQyR2VhZGQ5alN3dUJWOHhSb0Fud1dzZHZrdEgjejZNa3BUSFI4Vk5zQnhZQUFXSHV0MkdlYWRkOWpTd3VCVjh4Um9BbndXc2R2a3RIIiwKICAiYWxnIjogIkVkRFNBIiwKICAidHlwIjogIm9wZW5pZDR2Y2ktcHJvb2Yrand0Igp9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
        }),
        format: openid4vci::types::credential::CredentialFormatProfile::LdpVc {
            context: vec![],
            types: vec![],
            credential_subject: None,
            order: None,
        },
    };
    let credential_request = serde_json::to_vec(&credential_request)?;

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

    let did_document: Document = serde_json::from_value(did_document)
        .map_err(|e| GrpcError::ValidationError(ValidationError::from(e)))?;

    let did_document = serde_json::to_vec(&did_document)
        .map_err(|e| GrpcError::ValidationError(ValidationError::from(e)))?;

    let request = tonic::Request::new(EvaluateCredentialRequestRequest {
        credential_request,
        did_document: Some(did_document),
        issuer_metadata,
        credential_offer: Some(serde_json::to_vec(&credential_offer).unwrap()),
        authorization_server_metadata: None,
    });
    let response = credential_issuer_client
        .evaluate_credential_request(request)
        .await?
        .into_inner();

    println!("{response:#?}");

    Ok(())
}
