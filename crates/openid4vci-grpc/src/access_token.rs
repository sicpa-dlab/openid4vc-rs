use crate::error::GrpcError;
use crate::error::GrpcResult;
use crate::evaluate_access_token_request_response;
use crate::grpc_openid4vci::access_token_service_server::AccessTokenService;
use crate::grpc_openid4vci::create_access_token_error_response_response;
use crate::grpc_openid4vci::create_access_token_success_response_response;
use crate::grpc_openid4vci::EvaluateAccessTokenRequestRequest;
use crate::grpc_openid4vci::EvaluateAccessTokenRequestResponse;
use crate::utils::deserialize_optional_slice;
use crate::utils::deserialize_slice;
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
    async fn create_access_token_error_response(
        &self,
        request: Request<CreateAccessTokenErrorResponseRequest>,
    ) -> GrpcResult<Response<CreateAccessTokenErrorResponseResponse>> {
        let CreateAccessTokenErrorResponseRequest {
            error,
            error_description,
            error_uri,
            error_additional_details,
        } = request.into_inner();

        let error = AccessTokenErrorCode::try_from(error).map_err(GrpcError::ValidationError)?;
        let error_additional_details = deserialize_optional_slice(&error_additional_details)?;

        let response = match AccessToken::create_access_token_error_response(
            error,
            error_description,
            error_uri,
            error_additional_details,
        )
        .map_err(GrpcError::AccessTokenError)
        {
            Ok(response) => create_access_token_error_response_response::Response::Success(
                create_access_token_error_response_response::Success {
                    error_response: serialize_to_slice(response)?,
                },
            ),
            Err(e) => create_access_token_error_response_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(CreateAccessTokenErrorResponseResponse {
            response: Some(response),
        }))
    }

    async fn create_access_token_success_response(
        &self,
        request: Request<CreateAccessTokenSuccessResponseRequest>,
    ) -> GrpcResult<Response<CreateAccessTokenSuccessResponseResponse>> {
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

        let response = match AccessToken::create_access_token_success_response(
            access_token,
            token_type,
            expires_in,
            scope,
            c_nonce,
            c_nonce_expires_in,
            authorization_pending,
            interval,
        )
        .map_err(GrpcError::AccessTokenError)
        {
            Ok(response) => create_access_token_success_response_response::Response::Success(
                create_access_token_success_response_response::Success {
                    success_response: serialize_to_slice(response)?,
                },
            ),
            Err(e) => create_access_token_success_response_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(CreateAccessTokenSuccessResponseResponse {
            response: Some(response),
        }))
    }

    async fn evaluate_access_token_request(
        &self,
        request: Request<EvaluateAccessTokenRequestRequest>,
    ) -> GrpcResult<Response<EvaluateAccessTokenRequestResponse>> {
        let EvaluateAccessTokenRequestRequest {
            access_token_request,
            credential_offer,
            evaluate_access_token_request_options,
        } = request.into_inner();

        let access_token_request = deserialize_slice(&access_token_request)?;
        let credential_offer = deserialize_optional_slice(&credential_offer)?;
        let evaluate_access_token_request_options =
            deserialize_optional_slice(&evaluate_access_token_request_options)?;

        let response = match AccessToken::evaluate_access_token_request(
            &access_token_request,
            credential_offer,
            evaluate_access_token_request_options,
        )
        .map_err(GrpcError::AccessTokenError)
        {
            Ok(response) => evaluate_access_token_request_response::Response::Success(
                evaluate_access_token_request_response::Success {
                    success_response: serialize_to_slice(response)?,
                },
            ),
            Err(e) => evaluate_access_token_request_response::Response::Error(e.try_into()?),
        };

        Ok(Response::new(EvaluateAccessTokenRequestResponse {
            response: Some(response),
        }))
    }
}

#[cfg(test)]
mod test_access_token {
    use super::*;
    use openid4vci::access_token::{AccessTokenErrorResponse, AccessTokenSuccessResponse};

    #[tokio::test]
    async fn should_create_error_response() {
        let access_token = GrpcAccessToken::default();

        let expected_error_response = AccessTokenErrorResponse {
            error: AccessTokenErrorCode::InvalidRequest,
            error_description: Some("Some Error".to_string()),
            error_uri: Some("error_uri".to_string()),
            error_additional_details: Some(serde_json::json!({"hello": "world"})),
        };
        let expected = create_access_token_error_response_response::Response::Success(
            create_access_token_error_response_response::Success {
                error_response: serialize_to_slice(expected_error_response)
                    .expect("Unable to serialize error response"),
            },
        );

        let message = CreateAccessTokenErrorResponseRequest {
            error: "invalid_request".to_string(),
            error_description: Some("Some Error".to_string()),
            error_uri: Some("error_uri".to_string()),
            error_additional_details: Some(
                serde_json::to_vec(&serde_json::json!({"hello": "world"}))
                    .expect("Unable to create slice from json"),
            ),
        };

        let response = access_token
            .create_access_token_error_response(Request::new(message))
            .await
            .expect("Unable to create error response");

        let response = response.into_inner();

        assert_eq!(response.response, Some(expected));
    }

    #[tokio::test]
    async fn should_create_success_response() {
        let access_token = GrpcAccessToken::default();

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

        let expected = create_access_token_success_response_response::Response::Success(
            create_access_token_success_response_response::Success {
                success_response: serialize_to_slice(expected_success_response)
                    .expect("Unable to serialize success response"),
            },
        );

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
            .create_access_token_success_response(Request::new(message))
            .await
            .expect("Unable to create success response");

        let response: CreateAccessTokenSuccessResponseResponse = response.into_inner();

        assert_eq!(response.response, Some(expected));
    }
}
