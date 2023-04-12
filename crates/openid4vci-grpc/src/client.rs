//! Example client package

use openid4vci_grpc::client::CredentialIssuerServiceClient;
use openid4vci_grpc::CreateOfferRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = CredentialIssuerServiceClient::connect("http://[::1]:50051").await?;

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

    let response = client.create_offer(request).await?;
    let response = response.into_inner();

    let credential_offer: serde_json::Value =
        serde_json::from_slice(&response.credential_offer).unwrap();
    let credential_offer_url = String::from_utf8_lossy(&response.credential_offer_url);

    println!("{credential_offer:#?}");
    println!("{credential_offer_url:#?}");

    Ok(())
}
