use crate::error::GrpcError;
use crate::error::Result;
use crate::grpc_openid4vci::access_token_service_server::AccessTokenService;
use crate::utils::serialize_to_slice;
use crate::CreateAccessTokenErrorResponseRequest;
use crate::CreateAccessTokenErrorResponseResponse;
use openid4vci::access_token::{error_response::AccessTokenErrorCode, AccessToken};
use tonic::{Request, Response};

/// Access token structure to implement `gRPC` traits on.
///
/// This wraps mainly around [`AccessToken`]
#[derive(Debug, Default)]
pub struct GrpcAccessToken;

#[tonic::async_trait]
impl AccessTokenService for GrpcAccessToken {
    async fn create_error_response(
        &self,
        request: Request<CreateAccessTokenErrorResponseRequest>,
    ) -> Result<Response<CreateAccessTokenErrorResponseResponse>> {
        let CreateAccessTokenErrorResponseRequest {
            error,
            error_description,
            error_uri,
        } = request.into_inner();

        let error = AccessTokenErrorCode::try_from(error).map_err(GrpcError::ValidationError)?;

        let error_response =
            AccessToken::create_error_response(error, error_description, error_uri)
                .map_err(GrpcError::AccessTokenError)?;

        let error_response = serialize_to_slice(error_response)?;
        let response = CreateAccessTokenErrorResponseResponse { error_response };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod credential_issuer_tests {
    use super::*;
    use openid4vci::access_token::AccessTokenErrorResponse;

    #[tokio::test]
    async fn should_create_error_response() {
        let access_token = GrpcAccessToken::default();

        let message = CreateAccessTokenErrorResponseRequest {
            error: "invalid_request".to_string(),
            error_description: Some("Some Error".to_string()),
            error_uri: Some("error_uri".to_string()),
        };

        let response = access_token
            .create_error_response(Request::new(message))
            .await
            .expect("Unable to create error response");

        let expected_error_response = AccessTokenErrorResponse {
            error: AccessTokenErrorCode::InvalidRequest,
            error_description: Some("Some Error".to_string()),
            error_uri: Some("error_uri".to_string()),
        };

        let response = response.into_inner();
        let error_response = serialize_to_slice(&expected_error_response)
            .expect("Unable to serialize error response");

        assert_eq!(
            response,
            CreateAccessTokenErrorResponseResponse { error_response }
        );
    }
}
