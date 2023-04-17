//! Example client package

use openid4vci_grpc::access_token_client::AccessTokenServiceClient;
use openid4vci_grpc::credential_issuer_client::CredentialIssuerServiceClient;
use openid4vci_grpc::{CreateAccessTokenErrorResponseRequest, CreateOfferRequest};

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

    let request = tonic::Request::new(CreateOfferRequest {
        issuer_metadata,
        credentials,
        credential_offer_endpoint: None,
        authorized_code_flow: None,
        pre_authorized_code_flow: None,
    });

    let response = credential_issuer_client.create_offer(request).await?;
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

    Ok(())
}
