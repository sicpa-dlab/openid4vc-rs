//! Example server

use openid4vci_grpc::server::CredentialIssuerServiceServer;
use openid4vci_grpc::GrpcCredentialIssuer;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let issuer = GrpcCredentialIssuer::default();

    Server::builder()
        .add_service(CredentialIssuerServiceServer::new(issuer))
        .serve(addr)
        .await?;

    Ok(())
}
