use serde::{Deserialize, Serialize};

use crate::validate::ValidationError;

/// Enum containing token types for an access token response.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum AccessTokenType {
    /// `Bearer` token type, as defined in Section 6.1.1 of [OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1).
    Bearer,
}

impl From<AccessTokenType> for &str {
    fn from(token_type: AccessTokenType) -> Self {
        match token_type {
            AccessTokenType::Bearer => "Bearer",
        }
    }
}

impl TryFrom<String> for AccessTokenType {
    type Error = ValidationError;

    fn try_from(value: String) -> core::result::Result<Self, Self::Error> {
        match value.as_str() {
            "Bearer" => Ok(AccessTokenType::Bearer),
            _ => Err(ValidationError::Any {
                validation_message: "Invalid access token type".to_string(),
            }),
        }
    }
}
