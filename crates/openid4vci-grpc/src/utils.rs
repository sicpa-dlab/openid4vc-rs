use openid4vci::credential_issuer::error::CredentialIssuerError;
use serde::de::DeserializeOwned;

use crate::error::GrpcError;

/// Deserialize a slice into a structure and convert the error into a [`GrpcError`]
pub fn deserialize_slice<T>(b: &[u8]) -> std::result::Result<T, GrpcError>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(b).map_err(|e| {
        GrpcError::CredentialIssuerError(CredentialIssuerError::SerializationError {
            error_message: e.to_string(),
        })
    })
}

/// Optionally, Deserialize a slice into a structure and convert the error into a [`GrpcError`]
pub fn deserialize_optional_slice<T>(
    b: &Option<Vec<u8>>,
) -> std::result::Result<Option<T>, GrpcError>
where
    T: DeserializeOwned,
{
    b.as_ref().map(|b| deserialize_slice(b)).transpose()
}

#[cfg(test)]
mod utils_tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[test]
    fn should_deserialize() {
        let input = serde_json::json!({"a": "b"});
        let str = input.to_string();
        let bytes = str.as_bytes();
        let output =
            deserialize_slice::<serde_json::Value>(bytes).expect("Unable to deserialize value");

        assert_eq!(input, output);
    }

    #[test]
    fn should_optionally_deserialize() {
        let input = serde_json::json!({"a": "b"});

        let optional_input = Some(input.to_string().as_bytes().to_vec());
        let output = deserialize_optional_slice::<serde_json::Value>(&optional_input)
            .expect("Unable to deserialize value");

        assert_eq!(Some(input), output);
    }

    #[test]
    fn should_optionally_deserialize_without_value() {
        let optional_input = None;
        let output = deserialize_optional_slice::<serde_json::Value>(&optional_input)
            .expect("Unable to deserialize value");

        assert_eq!(output, None);
    }

    #[test]
    fn should_fail_to_deserialize() {
        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        struct Foo {
            a: String,
        }

        let input = serde_json::json!({"not_a": "c"});
        let str = input.to_string();
        let bytes = str.as_bytes();
        let output = deserialize_slice::<Foo>(bytes);

        let e = output.unwrap_err();

        assert!(matches!(e, GrpcError::CredentialIssuerError(..)));
    }
}
