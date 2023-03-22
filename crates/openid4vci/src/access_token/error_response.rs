/// Enum containing error responses for an access token request. This is a direct implementation of section
/// 6.3 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.3).
#[derive(Debug, PartialEq)]
pub enum ErrorResponse {
    /// `invalid_request`
    ///
    /// - the Authorization Server does not expect a PIN in the pre-authorized flow but the client
    /// provides a PIN
    ///
    /// - the Authorization Server expects a PIN in the pre-authorized flow but the client does not
    /// provide a PIN
    InvalidRequest,

    /// `invalid_grant`
    ///
    /// - the Authorization Server expects a PIN in the pre-authorized flow but the client provides
    /// the wrong PIN
    ///
    /// - the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has
    /// expired
    InvalidGrant,

    /// `invalid_client`
    ///
    /// - the client tried to send a Token Request with a Pre-Authorized Code without Client ID but
    /// the Authorization Server does not support anonymous access
    InvalidClient,
}

impl From<ErrorResponse> for &str {
    fn from(value: ErrorResponse) -> Self {
        match value {
            ErrorResponse::InvalidRequest => "invalid_request",
            ErrorResponse::InvalidClient => "invalid_client",
            ErrorResponse::InvalidGrant => "invalid_grant",
        }
    }
}

#[cfg(test)]
mod tests_error_response {
    use super::*;

    #[test]
    fn should_convert_valid_error_names_to_enum() {
        let result: &str = ErrorResponse::InvalidRequest.into();
        let expect = "invalid_request";
        assert_eq!(result, expect);

        let result: &str = ErrorResponse::InvalidGrant.into();
        let expect = "invalid_grant";
        assert_eq!(result, expect);

        let result: &str = ErrorResponse::InvalidClient.into();
        let expect = "invalid_client";
        assert_eq!(result, expect);
    }
}
