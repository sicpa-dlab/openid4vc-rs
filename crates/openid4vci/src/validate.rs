use serde::Serialize;
use thiserror::Error;

/// Error enum for development when an error occurs related to the [`Validatable`] trait
#[derive(Debug, Error, Clone, PartialEq, Eq, AsRefStr, Serialize)]
#[repr(u32)]
#[serde(untagged)]
pub enum ValidationError {
    #[error("An error occurred during validation, serialization or deserialization")]
    /// Any validation error occurred
    Any {
        /// Validation message that should help the user debug the issue
        validation_message: String,
    } = 1,
}

/// Validation result used for the [`ValidationError`]
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

error_impl!(ValidationError, ValidationResult);

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

impl From<serde_path_to_error::Error<serde_json::Error>> for ValidationError {
    fn from(e: serde_path_to_error::Error<serde_json::Error>) -> Self {
        ValidationError::Any {
            validation_message: e.to_string(),
        }
    }
}

/// Trait for data types which need validation of being deserialized
pub trait Validatable {
    /// Validate a given struct and return a concise [`ValidationError`] object
    ///
    /// # Errors
    ///
    /// - When the validation fails for the implementation
    fn validate(&self) -> Result<(), ValidationError>;
}

#[cfg(test)]
mod test_validation {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    struct Mock {
        x: String,
    }

    #[test]
    fn should_format_error_correctly() {
        let j = "{\"hello\": \"world\"}";
        let deserialize_error = serde_json::from_str::<Mock>(j).unwrap_err();
        let validation_error: ValidationError = ValidationError::from(deserialize_error);

        assert!(matches!(validation_error, ValidationError::Any { .. }));
    }
}
