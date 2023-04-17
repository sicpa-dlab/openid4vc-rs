//! Example client package

use openid4vci::types::credential_request::{CredentialRequest, CredentialRequestProof};
use openid4vci_grpc::access_token_client::AccessTokenServiceClient;
use openid4vci_grpc::credential_issuer_client::CredentialIssuerServiceClient;
use openid4vci_grpc::{
    CreateAccessTokenErrorResponseRequest, CreateCredentialOfferRequest, PreEvaluateCredentialRequestRequest,
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
        issuer_metadata,
        credentials,
        credential_offer_endpoint: None,
        authorized_code_flow: None,
        pre_authorized_code_flow: None,
    });

    let response = credential_issuer_client.create_credential_offer(request).await?;
    let response = response.into_inner();

    let credential_offer: serde_json::Value =
        serde_json::from_slice(&response.credential_offer).unwrap();
    let credential_offer_url = String::from_utf8_lossy(&response.credential_offer_url);

    let request = tonic::Request::new(CreateAccessTokenErrorResponseRequest {
        error: "invalid_request".to_string(),
        error_description: Some("An error".to_string()),
        error_uri: Some("https://uri.com".to_string()),
    });

    println!("{credential_offer:#?}");
    println!("{credential_offer_url:#?}");

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
            jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9".to_owned(),
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
    Ok(())
}
