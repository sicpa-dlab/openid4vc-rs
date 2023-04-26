use crate::validate::ValidationError;
use serde::{Deserialize, Serialize};

/// Enum containing error codes for an access token request. This is a direct implementation of section
/// 7.3.1 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.3.1).
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum CredentialIssuerErrorCode {
    /// Credential Request was malformed. One or more of the parameters (i.e. format, proof) are
    /// missing or malformed.
    InvalidRequest,

    /// Credential Request contains the wrong `Access Token` or the `Access Token` is missing
    InvalidToken,

    /// requested credential type is not supported
    UnsupportedCredentialType,

    /// requested credential format is not supported
    UnsupportedCredentialFormat,

    /// Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to
    /// a Credential Issuer provided nonce
    InvalidOrMissingProof,
}

impl From<CredentialIssuerErrorCode> for &str {
    fn from(value: CredentialIssuerErrorCode) -> Self {
        match value {
            CredentialIssuerErrorCode::InvalidRequest => "invalid_request",
            CredentialIssuerErrorCode::InvalidToken => "invalid_token",
            CredentialIssuerErrorCode::UnsupportedCredentialType => "unsupported_credential_type",
            CredentialIssuerErrorCode::UnsupportedCredentialFormat => {
                "unsupported_credential_format"
            }
            CredentialIssuerErrorCode::InvalidOrMissingProof => "invalid_or_missing_proof",
        }
    }
}

impl TryFrom<String> for CredentialIssuerErrorCode {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "invalid_request" => Ok(CredentialIssuerErrorCode::InvalidRequest),
            "invalid_token" => Ok(CredentialIssuerErrorCode::InvalidToken),
            "unsupported_credential_type" => {
                Ok(CredentialIssuerErrorCode::UnsupportedCredentialType)
            }
            "unsupported_credential_format" => {
                Ok(CredentialIssuerErrorCode::UnsupportedCredentialFormat)
            }
            "invalid_or_missing_proof" => Ok(CredentialIssuerErrorCode::InvalidOrMissingProof),
            v => Err(ValidationError::Any {
                validation_message: format!("Invalid error code: {v}"),
            }),
        }
    }
}

#[cfg(test)]
mod test_credential_issuer_error_code {
    use super::*;

    macro_rules! test_serialize {
        ($expected:tt, $enum_value:ident) => {
            assert_eq!(
                <CredentialIssuerErrorCode as Into<&str>>::into(
                    CredentialIssuerErrorCode::$enum_value
                ),
                $expected
            );
        };
    }

    macro_rules! test_deserialize {
        ($input:tt, $expected:tt) => {
            assert_eq!(
                <String as TryInto<CredentialIssuerErrorCode>>::try_into($input.to_owned())
                    .expect("Unable to convert string"),
                CredentialIssuerErrorCode::$expected
            );
        };
    }

    #[test]
    fn should_transform_to_correct_string() {
        test_serialize!("invalid_request", InvalidRequest);
        test_serialize!("invalid_token", InvalidToken);
        test_serialize!("unsupported_credential_type", UnsupportedCredentialType);
        test_serialize!("unsupported_credential_format", UnsupportedCredentialFormat);
        test_serialize!("invalid_or_missing_proof", InvalidOrMissingProof);
    }

    #[test]
    fn should_transform_to_correct_enum_value() {
        test_deserialize!("invalid_request", InvalidRequest);
        test_deserialize!("invalid_token", InvalidToken);
        test_deserialize!("unsupported_credential_type", UnsupportedCredentialType);
        test_deserialize!("unsupported_credential_format", UnsupportedCredentialFormat);
        test_deserialize!("invalid_or_missing_proof", InvalidOrMissingProof);
    }
}
