use crate::error::GrpcError;
use crate::error::Result;
use crate::grpc_openid4vci::access_token_service_server::AccessTokenService;
use crate::utils::serialize_to_slice;
use crate::CreateAccessTokenErrorResponseRequest;
use crate::CreateAccessTokenErrorResponseResponse;
use crate::CreateAccessTokenSuccessResponseRequest;
use crate::CreateAccessTokenSuccessResponseResponse;

use openid4vci::access_token::{error_response::AccessTokenErrorCode, AccessToken};
use openid4vci::types::token_type::AccessTokenType;
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

    async fn create_success_response(
        &self,
        request: Request<CreateAccessTokenSuccessResponseRequest>,
    ) -> Result<Response<CreateAccessTokenSuccessResponseResponse>> {
        let CreateAccessTokenSuccessResponseRequest {
            access_token,
            token_type,
            expires_in,
            scope,
            c_nonce,
            c_nonce_expires_in,
            authorization_pending,
            interval,
        } = request.into_inner();

        let token_type =
            AccessTokenType::try_from(token_type).map_err(GrpcError::ValidationError)?;

        let success_response = AccessToken::create_success_response(
            access_token,
            token_type,
            expires_in,
            scope,
            c_nonce,
            c_nonce_expires_in,
            authorization_pending,
            interval,
        )
        .map_err(GrpcError::AccessTokenError)?;

        let success_response = serialize_to_slice(success_response)?;
        let response: CreateAccessTokenSuccessResponseResponse =
            CreateAccessTokenSuccessResponseResponse { success_response };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod credential_issuer_tests {
    use super::*;
    use openid4vci::access_token::{AccessTokenErrorResponse, AccessTokenSuccessResponse};

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

    #[tokio::test]
    async fn should_create_success_response() {
        let access_token = GrpcAccessToken::default();

        let message = CreateAccessTokenSuccessResponseRequest {
            access_token: "access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            scope: Some("Hello World".to_string()),
            c_nonce: Some("c_nonce".to_string()),
            c_nonce_expires_in: Some(1800),

            authorization_pending: Some(false),
            interval: Some(5),
        };

        let response = access_token
            .create_success_response(Request::new(message))
            .await
            .expect("Unable to create success response");

        let expected_success_response = AccessTokenSuccessResponse {
            access_token: "access_token".to_string(),
            token_type: AccessTokenType::Bearer,
            expires_in: Some(3600),
            scope: Some("Hello World".to_string()),
            c_nonce: Some("c_nonce".to_string()),
            c_nonce_expires_in: Some(1800),
            authorization_pending: Some(false),
            interval: Some(5),
        };

        let response: CreateAccessTokenSuccessResponseResponse = response.into_inner();
        let success_response = serialize_to_slice(&expected_success_response)
            .expect("Unable to serialize success response");

        assert_eq!(
            response,
            CreateAccessTokenSuccessResponseResponse { success_response }
        );
    }
}
