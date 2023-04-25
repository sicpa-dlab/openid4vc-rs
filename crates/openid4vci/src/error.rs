use std::fmt;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

/// Wrapper around result to implement `to_return_object` on
pub type Result<T> = std::result::Result<T, ErrorInformation>;

/// Generic error structure that can be send over FFI, for example, that contains machine and human
/// readable information to resolve error.
///
/// `additional_information` can be used to help the user of this library with more information. It
/// accepts any `serde_json::Value` type.
#[derive(Error, Debug, Default, Serialize, Clone)]
pub struct ErrorInformation {
    /// Generic error code. See the specific error implementations, like
    /// [`crate::credential_issuer::error::CredentialIssuerError`]
    /// for the codes it defines
    pub code: u32,

    /// Human-readable error name
    pub name: String,

    /// Human-readable description of the error
    pub description: String,

    /// Additional information that might help the user debug the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_information: Option<Value>,
}

impl fmt::Display for ErrorInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_string(self);
        match s {
            Ok(s) => write!(f, "{s}"),
            Err(e) => write!(f, "{e}"),
        }
    }
}

impl ErrorInformation {
    /// Creates a new instance of the [`ErrorInformation`] struct
    #[must_use]
    pub fn new(
        code: impl Into<u32>,
        name: impl Into<String>,
        description: impl Into<String>,
        additional_information: Option<Value>,
    ) -> Self {
        Self {
            code: code.into(),
            name: name.into(),
            description: description.into(),
            additional_information,
        }
    }
}
