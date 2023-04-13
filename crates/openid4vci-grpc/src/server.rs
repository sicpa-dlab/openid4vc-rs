//! Example server

use openid4vci_grpc::access_token_server::AccessTokenServiceServer;
use openid4vci_grpc::credential_issuer_server::CredentialIssuerServiceServer;
use openid4vci_grpc::{GrpcAccessToken, GrpcCredentialIssuer};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let issuer = GrpcCredentialIssuer::default();
    let access_token = GrpcAccessToken::default();

    Server::builder()
        .add_service(CredentialIssuerServiceServer::new(issuer))
        .add_service(AccessTokenServiceServer::new(access_token))
        .serve(addr)
        .await?;

    Ok(())
}
