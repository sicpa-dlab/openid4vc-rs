use serde::Deserialize;
use serde::Serialize;

use crate::error_response::ErrorResponse;
use crate::types::token_type::AccessTokenType;

use self::error::Result;
use self::error_response::AccessTokenErrorCode;

/// Error module for the access token module
pub mod error;

/// Module containing a structure for the error response
pub mod error_response;

/// Struct mapping for a `token error response` as defined in section 6.3 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.3)
pub type AccessTokenErrorResponse = ErrorResponse<AccessTokenErrorCode>;

/// Token structure which contains methods to create responses and evaluate input
pub struct AccessToken;

/// Struct mapping for a `token success response` as defined in section 6.2 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2)
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AccessTokenSuccessResponse {
    /// (OAuth2) The access token issued by the authorization server.
    pub access_token: String,

    /// (OAuth2) The type of the token issued as described in Section 7.1 of the [OAuth2 specification](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1).
    /// Value is case insensitive.
    pub token_type: AccessTokenType,

    /// (OAuth2) RECOMMENDED. The lifetime in seconds of the access token.  For example, the value "3600" denotes that the access token will
    /// expire in one hour from the time the response was generated. If omitted, the authorization server SHOULD provide the
    /// expiration time via other means or document the default value.
    pub expires_in: Option<u64>,

    /// (OAuth2) OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.
    /// The scope of the access token as described by Section 3.3 of the [OAuth2 Specification](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
    pub scope: Option<String>,

    /// Nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2). When received,
    /// the Wallet MUST use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce.
    pub c_nonce: Option<String>,

    /// The lifetime in seconds of the `c_nonce`
    pub c_nonce_expires_in: Option<u64>,

    /// In the Pre-Authorized Code Flow, the Token Request is still pending as the Credential Issuer is waiting
    /// for the End-User interaction to complete. The client SHOULD repeat the Token Request. Before each new request,
    /// the client MUST wait at least the number of seconds specified by the `interval` response parameter.
    pub authorization_pending: Option<bool>,

    /// The minimum amount of time in seconds that the client SHOULD wait between polling requests to the
    /// Token Endpoint in the Pre-Authorized Code Flow. If no value is provided, clients MUST use 5 as the default.
    pub interval: Option<u64>,
}

impl AccessToken {
    /// Create an error response
    ///
    /// # Errors
    ///
    /// Unable to error, `Result` is used for consistency
    pub fn create_access_token_error_response(
        error: error_response::AccessTokenErrorCode,
        error_description: Option<String>,
        error_uri: Option<String>,
        error_additional_details: Option<serde_json::Value>,
    ) -> Result<AccessTokenErrorResponse> {
        let error_response = AccessTokenErrorResponse {
            error,
            error_description,
            error_uri,
            error_additional_details,
        };

        Ok(error_response)
    }

    /// Create a success response
    ///
    /// # Errors
    ///
    /// Unable to error, `Result` is used for consistency
    #[allow(clippy::too_many_arguments)]
    pub fn create_access_token_success_response(
        access_token: String,
        token_type: AccessTokenType,
        expires_in: Option<u64>,
        scope: Option<String>,
        c_nonce: Option<String>,
        c_nonce_expires_in: Option<u64>,
        authorization_pending: Option<bool>,
        interval: Option<u64>,
    ) -> Result<AccessTokenSuccessResponse> {
        let token_response = AccessTokenSuccessResponse {
            access_token,
            token_type,
            expires_in,
            scope,
            c_nonce,
            c_nonce_expires_in,
            authorization_pending,
            interval,
        };

        Ok(token_response)
    }
}

#[cfg(test)]
mod test_access_token {
    use super::*;

    #[test]
    fn error_response() {
        let error_response = AccessToken::create_error_response(
            AccessTokenErrorCode::InvalidRequest,
            Some("error description".to_owned()),
            Some("error uri".to_owned()),
            None,
        )
        .expect("Unable to create access token error response");

        assert_eq!(error_response.error, AccessTokenErrorCode::InvalidRequest);
        assert_eq!(
            error_response.error_description,
            Some("error description".to_string())
        );
        assert_eq!(error_response.error_uri, Some("error uri".to_string()));
    }

    #[test]
    fn success_response() {
        let success_response: AccessTokenSuccessResponse = AccessToken::create_success_response(
            "Hello".to_string(),
            AccessTokenType::Bearer,
            Some(3600),
            Some("scope".to_string()),
            Some("c_nonce".to_string()),
            Some(3600),
            Some(true),
            Some(5),
        )
        .expect("Unable to create access token success response");

        assert_eq!(success_response.access_token, "Hello".to_string());
        assert_eq!(success_response.token_type, AccessTokenType::Bearer);
        assert_eq!(success_response.expires_in, Some(3600));
        assert_eq!(success_response.scope, Some("scope".to_string()));
        assert_eq!(success_response.c_nonce, Some("c_nonce".to_string()));
        assert_eq!(success_response.c_nonce_expires_in, Some(3600));
        assert_eq!(success_response.authorization_pending, Some(true));
        assert_eq!(success_response.interval, Some(5));
    }
}
