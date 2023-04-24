use crate::error::GrpcError;
use openid4vci::validate::ValidationError;
use serde::{de::DeserializeOwned, Serialize};

/// Deserialize a slice into a structure and convert the error into a [`GrpcError`]
pub fn deserialize_slice<T>(b: &[u8]) -> std::result::Result<T, GrpcError>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(b).map_err(|e| GrpcError::ValidationError(ValidationError::from(e)))
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

/// Serialize a struct that implements [`serde::Serialize`] to a byte array
pub fn serialize_to_slice<T>(item: T) -> std::result::Result<Vec<u8>, GrpcError>
where
    T: Serialize,
{
    serde_json::to_vec(&item).map_err(|e| GrpcError::ValidationError(ValidationError::from(e)))
}

/// Optionally, Serialize a struct that implements [`serde::Serialize`] to a byte array
pub fn serialize_to_optional_slice<T>(
    item: Option<T>,
) -> std::result::Result<Option<Vec<u8>>, GrpcError>
where
    T: Serialize,
{
    item.map(|i| serde_json::to_vec(&i))
        .transpose()
        .map_err(|e| GrpcError::ValidationError(ValidationError::from(e)))
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
    fn should_optionally_serialize() {
        let input = serde_json::json!({"a": "b"});
        let expected = Some(input.to_string().as_bytes().to_vec());

        let output = serialize_to_optional_slice(Some(input)).expect("Unable to deserialize value");

        assert_eq!(output, expected);
    }

    #[test]
    fn should_optionally_serialize_without_value() {
        let input: Option<()> = None;
        let output = serialize_to_optional_slice(input).expect("Unable to deserialize value");

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

        assert!(matches!(e, GrpcError::ValidationError(..)));
    }
}
