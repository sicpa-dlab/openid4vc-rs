use serde::Deserialize;
use serde::Serialize;

use crate::validate::ValidationError;

/// Enum containing error codes for an access token request. This is a direct implementation of section
/// 6.3 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.3).
#[derive(Debug, PartialEq, Clone, AsRefStr, Serialize, Deserialize)]
pub enum AccessTokenErrorCode {
    /// `invalid_request`
    ///
    /// - (OAuth2) The request is missing a required parameter, includes an invalid parameter value,
    /// includes a parameter more than once, or is otherwise malformed
    ///
    /// - (OpenID4VCI) the Authorization Server does not expect a PIN in the pre-authorized flow but the client
    /// provides a PIN
    ///
    /// - (OpenID4VCI) the Authorization Server expects a PIN in the pre-authorized flow but the client does not
    /// provide a PIN
    InvalidRequest,

    /// `invalid_grant`
    ///
    /// - (OpenID4VCI) the Authorization Server expects a PIN in the pre-authorized flow but the client provides
    /// the wrong PIN
    ///
    /// - (OpenID4VCI) the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has
    /// expired
    InvalidGrant,

    /// `invalid_client`
    ///
    /// - (OpenID4VCI) the client tried to send a Token Request with a Pre-Authorized Code without Client ID but
    /// the Authorization Server does not support anonymous access
    InvalidClient,

    /// `access_denied`
    ///
    /// - (OAuth2) The resource owner or authorization server denied the request.
    AccessDenied,

    /// `unsupported_response_type`
    ///
    /// - (OAuth2) The authorization server does not support obtaining an authorization code using this method.
    UnsupportedResponseType,

    /// `invalid_scope`
    ///
    /// - (OAuth2) The requested scope is invalid, unknown, or malformed.
    InvalidScope,

    /// `server_error`
    ///
    /// - (OAuth2) The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
    /// This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.
    ServerError,

    /// `temporarily_unavailable`
    ///
    /// - (OAuth2) The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
    /// This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.
    TemporarilyUnavailable,
}

impl From<AccessTokenErrorCode> for &str {
    fn from(value: AccessTokenErrorCode) -> Self {
        match value {
            AccessTokenErrorCode::InvalidRequest => "invalid_request",
            AccessTokenErrorCode::InvalidClient => "invalid_client",
            AccessTokenErrorCode::InvalidGrant => "invalid_grant",
            AccessTokenErrorCode::AccessDenied => "access_denied",
            AccessTokenErrorCode::UnsupportedResponseType => "unsupported_response_type",
            AccessTokenErrorCode::InvalidScope => "invalid_scope",
            AccessTokenErrorCode::ServerError => "server_error",
            AccessTokenErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

impl TryFrom<String> for AccessTokenErrorCode {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "invalid_request" => Ok(AccessTokenErrorCode::InvalidRequest),
            "invalid_client" => Ok(AccessTokenErrorCode::InvalidClient),
            "invalid_grant" => Ok(AccessTokenErrorCode::InvalidGrant),
            "access_denied" => Ok(AccessTokenErrorCode::AccessDenied),
            "unsupported_response_type" => Ok(AccessTokenErrorCode::UnsupportedResponseType),
            "invalid_scope" => Ok(AccessTokenErrorCode::InvalidScope),
            "server_error" => Ok(AccessTokenErrorCode::ServerError),
            "temporarily_unavailable" => Ok(AccessTokenErrorCode::TemporarilyUnavailable),
            _ => Err(ValidationError::Any {
                validation_message: "Invalid access token error code".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests_error_response {
    use super::*;

    #[test]
    fn should_convert_valid_error_names_to_enum() {
        let result: &str = AccessTokenErrorCode::InvalidRequest.into();
        let expect = "invalid_request";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::InvalidGrant.into();
        let expect = "invalid_grant";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::InvalidClient.into();
        let expect = "invalid_client";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::AccessDenied.into();
        let expect = "access_denied";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::UnsupportedResponseType.into();
        let expect = "unsupported_response_type";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::InvalidScope.into();
        let expect = "invalid_scope";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::ServerError.into();
        let expect = "server_error";
        assert_eq!(result, expect);

        let result: &str = AccessTokenErrorCode::TemporarilyUnavailable.into();
        let expect = "temporarily_unavailable";
        assert_eq!(result, expect);
    }
}
