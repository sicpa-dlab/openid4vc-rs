use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::validate::ValidationError;

/// Error enum for development when an error occurs related to the [`super::ProofJwt`] struct.
#[derive(Error, Debug, AsRefStr, PartialEq, Eq, Serialize, Clone)]
#[repr(u32)]
#[serde(untagged)]
pub enum JwtError {
    /// A wrapper for a validation error
    #[error("An error occurred while validating")]
    ValidationError(#[from] ValidationError) = 300,

    /// `nbf` field in the JWT is after `now`
    #[error("JWT is not yet valid. Valid from: {valid_from} and checked at {now}")]
    NotYetValid {
        /// Timestamp from when the JWT is valid
        valid_from: DateTime<Utc>,

        /// Timestamp of when the validation happened
        now: DateTime<Utc>,
    } = 301,

    /// `exp` field in the JWT is before `now`
    #[error("JWT is not valid anymore. Valid until: {valid_until} and checked at {now}")]
    NotValidAnymore {
        /// Timestamp until when the JWT is valid
        valid_until: DateTime<Utc>,

        /// Timestamp of when the validation happened
        now: DateTime<Utc>,
    } = 302,

    /// Provided issuer, `client_id`, does not match the `iss` field
    #[error("`iss` field in the body mismatched with provided issuer")]
    IssuerMismatch {
        /// issuer id in the JWT
        iss: Option<String>,

        /// User provided client id that must match the `iss`
        client_id: Option<String>,
    } = 303,

    #[error("No `kid`, `jwk` or `x5c` found in the JWT header")]
    NoKeyFoundInProof = 304,

    #[error("No did document provided when the `kid` is a did")]
    NoDidDocumentProvidedForKidAsDid = 305,

    #[error("Unable to transform did, from `kid`, into a Did type")]
    UnableToTransformIntoDid {
        /// Key id that should be transformed into a did
        kid: String,

        /// Message supplied by the library to give additional context
        message: String,
    } = 306,

    #[error("Unable to find the verification method the did, `kid`, was referring to")]
    UnableToResolveDidInDidDocument {
        /// The absolute did that could not be found in the document
        did: String,

        /// Message supplied by the library to give additional context
        message: String,
    } = 307,

    #[error("Unable to map the verification method to a JWK")]
    UnableToMapVerificationMethodToJwk {
        /// Message supplied by the library to give additional context
        messsage: String,
    } = 308,

    #[error("Unable to convert '{original_string}' into a valid Jose Item")]
    UnableToTransformIntoJoseItem {
        /// Value that has to be transformed into a Jose Item
        original_string: String,

        /// Error message directly from [`serde`]
        serde_message: String,
    } = 309,

    #[error("supplied algorithm, '{algorithm}' is not valid")]
    UnsupportedAlgorithm {
        /// The invalid algorithm
        algorithm: String,
    } = 310,

    #[error("JWK with algorithm of 'edDSA' has no x coordinate")]
    EdDSAHasNoXCoordinate = 311,

    #[error("JWK with algorithm of '{algorithm}' has no 'x' or 'y' coordinate")]
    ESXXXHasNoXOrYCoordinate {
        /// Algorithm used
        algorithm: String,

        /// Optional x coordinate, this should not be missing
        x: Option<Vec<u8>>,

        /// Optional y coordinate
        y: Option<Vec<u8>>,
    } = 312,

    /// Signature was not supplied on the `jwt`
    #[error("Signature was expected but not found in the JWT")]
    SignatureNotInJwt {
        /// Stringified value of the JWT
        jwt: String,
    } = 313,

    /// Unsupported key type
    ///
    /// For now this includes: 'x5c' and 'jwk'
    #[error("Unsupported key type `{key_type}` found in JWT header")]
    UnsupportedKeyTypeInJwtHeader {
        /// Specified key type that is not supported
        key_type: String,
    },
}

/// JWT result used for the [`JwtError`]
pub type JwtResult<T> = std::result::Result<T, JwtError>;

error_impl!(JwtError);
