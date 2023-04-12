use crate::error::{GrpcError, Result};
use crate::grpc_openid4vci::access_token_service_server::AccessTokenService;
use crate::CreateAccessTokenErrorResponseRequest;
use crate::CreateAccessTokenErrorResponseResponse;
use openid4vci::access_token::{error_response::AccessTokenErrorCode, AccessToken};
use tonic::{Request, Response};

/// Issuer structure to implement `gRPC` traits on.
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

        // FIXME: do not use `unwrap`.
        let error = AccessTokenErrorCode::try_from(error).unwrap();

        let error_response =
            AccessToken::create_error_response(error, error_description, error_uri)
                .map_err(GrpcError::AccessTokenError)?;

        let error_response = serde_json::to_vec(&error_response).unwrap();
        let response = CreateAccessTokenErrorResponseResponse { error_response };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod credential_issuer_tests {
    use openid4vci::access_token::AccessTokenErrorResponse;

    use super::*;

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

        assert_eq!(
            response,
            CreateAccessTokenErrorResponseResponse {
                error_response: serde_json::to_vec(&expected_error_response).unwrap()
            }
        );
    }
}
