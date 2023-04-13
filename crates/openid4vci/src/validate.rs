use serde::Serialize;
use thiserror::Error;

/// Error enum for development when an error occurs related to the [`Validatable`] trait
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize)]
#[repr(u32)]
#[serde(untagged)]
pub enum ValidationError {
    #[error("{validation_message}")]
    /// Any validation error occurred
    Any {
        /// Validation message that should help the user debug the issue
        validation_message: String,
    } = 1,
}

/// Validation result used for the [`ValidationError`]
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

impl From<base64::DecodeError> for ValidationError {
    fn from(e: base64::DecodeError) -> Self {
        ValidationError::Any {
            validation_message: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for ValidationError {
    fn from(e: serde_json::Error) -> Self {
        ValidationError::Any {
            validation_message: e.to_string(),
        }
    }
}

/// Trait for data types which need validation of being deserialized
pub trait Validatable {
    /// Validate a given struct and return a consise [`ValidationError`] object
    ///
    /// # Errors
    ///
    /// - When the validation fails for the implemation
    fn validate(&self) -> Result<(), ValidationError>;
}
