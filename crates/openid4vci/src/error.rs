use serde::Serialize;
use serde_json::Value;

/// Generic error structure that can be send over FFI, for example, that contains machine and human
/// readable information to resolve error.
///
/// `additional_information` can be used to help the user of this library with more information. It
/// accepts any `serde_json::Value` type.
#[derive(Debug, Default, Serialize)]
pub struct ErrorInformation {
    /// Generic error code. See the specific error implementations, like `CredentialIssuerError`
    /// for the codes it defines
    pub code: u32,

    /// Human-readable error name
    pub name: String,

    /// Human-readable description of the error
    pub description: String,

    /// Additional information that might help the user debug the error
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub additional_information: Value,
}

impl ErrorInformation {
    /// Creates a new instance of the `ErrorInformation` struct
    #[must_use]
    pub fn new(
        code: impl Into<u32>,
        name: impl Into<String>,
        description: impl Into<String>,
        additional_information: Value,
    ) -> Self {
        Self {
            code: code.into(),
            name: name.into(),
            description: description.into(),
            additional_information,
        }
    }
}
