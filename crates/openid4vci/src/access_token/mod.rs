use serde::Deserialize;
use serde::Serialize;

use self::error::Result;
use self::error_response::AccessTokenErrorCode;

/// Error module for the access token module
pub mod error;

/// Module containing a structure for the error response
pub mod error_response;

/// Token structure which contains methods to create responses and evaluate input
pub struct AccessToken;

/// Struct mapping of the `token error response` as defined in section 6.3 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.3)
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AccessTokenErrorResponse {
    /// Error code indicating why the token request failed.
    pub error: AccessTokenErrorCode,

    /// Human-readable ASCII text providing additional information,
    /// used to assist the client developer in understanding the error that occurred.
    pub error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    pub error_uri: Option<String>,
}

impl AccessToken {
    /// Create an error response
    ///
    /// # Errors
    ///
    /// Unable to error, `Result` is used for consistency
    pub fn create_error_response(
        error: error_response::AccessTokenErrorCode,
        error_description: Option<String>,
        error_uri: Option<String>,
    ) -> Result<AccessTokenErrorResponse> {
        let error_response = AccessTokenErrorResponse {
            error,
            error_description,
            error_uri,
        };

        Ok(error_response)
    }
}

#[cfg(test)]
mod test_access_token {
    use super::*;

    #[test]
    fn happy_flow() {
        let error_response = AccessToken::create_error_response(
            AccessTokenErrorCode::InvalidRequest,
            Some("error description".to_owned()),
            Some("error uri".to_owned()),
        )
        .expect("Unable to create access token error response");

        assert_eq!(error_response.error, AccessTokenErrorCode::InvalidRequest);
        assert_eq!(
            error_response.error_description,
            Some("error description".to_string())
        );
        assert_eq!(error_response.error_uri, Some("error uri".to_string()));
    }
}
