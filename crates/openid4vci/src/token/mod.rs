use thiserror::Error;

/// Error enum for development when an error occurs related to the `Token` struct.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Error that is triggered when an [ErrorResponse] is instantiated with a name
    /// that does not map to a value in the enum.
    #[error("The name `{0}` is not a valid response name")]
    InvalidErrorName(String),
}

/// Module containing a structure for the error response
pub mod error_response;

/// Token structure which contains methods to create responses and evaluate input
pub struct Token;

#[cfg(test)]
mod tests_token {
    use super::*;

    #[test]
    fn should_convert_error_to_correct_message() {
        let result = Error::InvalidErrorName("error_name".to_owned());
        let expect = "The name `error_name` is not a valid response name";
        assert_eq!(result.to_string(), expect);
    }
}
