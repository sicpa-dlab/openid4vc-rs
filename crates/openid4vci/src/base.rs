/// base64 encoding and decoding module.
pub mod base64 {
    use base64::{engine::general_purpose, Engine as _};

    /// Decode bytes from base64
    #[allow(unused)]
    pub fn decode<T>(input: T) -> Result<Vec<u8>, base64::DecodeError>
    where
        T: AsRef<[u8]>,
    {
        general_purpose::STANDARD.decode(input)
    }

    /// Encode bytes into a base64 string
    #[allow(unused)]
    pub fn encode<T>(input: T) -> String
    where
        T: AsRef<[u8]>,
    {
        general_purpose::STANDARD.encode(input)
    }
}

/// base64 url-safe encoding and decoding module.
pub mod base64url {
    use base64::{engine::general_purpose, Engine as _};

    /// Decode bytes from base64 url-safe
    pub fn decode<T>(input: T) -> Result<Vec<u8>, base64::DecodeError>
    where
        T: AsRef<[u8]>,
    {
        general_purpose::URL_SAFE_NO_PAD.decode(input)
    }

    /// Encode bytes into a base64 url-safe string
    #[allow(unused)]
    pub fn encode<T>(input: T) -> String
    where
        T: AsRef<[u8]>,
    {
        general_purpose::URL_SAFE_NO_PAD.encode(input)
    }
}

/// No extensive testing is done here as this is a very thin wrapper directly around a common
/// base64 library
#[cfg(test)]
mod test_base {
    use super::*;
    use std::str;

    #[test]
    fn should_round_trip_base64() {
        let start = "Hello World!";
        let encoded = base64::encode(start);
        let decoded = base64::decode(encoded).expect("Unable to decode encoded value");
        let decoded_string = str::from_utf8(&decoded).expect("Unable to decode to utf8");

        assert_eq!(decoded_string, start);
    }

    #[test]
    fn should_round_trip_base64_url() {
        let start = "Hello World!";
        let encoded = base64url::encode(start);
        let decoded = base64url::decode(encoded).expect("Unable to decode encoded value");
        let decoded_string = str::from_utf8(&decoded).expect("Unable to decode to utf8");

        assert_eq!(decoded_string, start);
    }
}
