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

    /// Provided issuer, `issuer_id`, does not match the `iss` field
    #[error("`iss` field in the body mismatched with provided issuer")]
    IssuerMismatch {
        /// Supplied `iss`
        expected_issuer: Option<String>,

        /// `iss` in the `JWT`
        actual_issuer: Option<String>,
    } = 303,

    /// Could not find a specific key in the header
    #[error("No `kid`, `jwk` or `x5c` found in the JWT header")]
    NoKeyFoundInProof = 304,

    /// Did document was required because the `kid` was in the header, but none provided
    #[error("No did document provided when the `kid` is a did")]
    NoDidDocumentProvidedForKidAsDid = 305,

    /// `kid` could not be transformed into a did
    #[error("Unable to transform did, from `kid`, into a Did type")]
    UnableToTransformIntoDid {
        /// Key id that should be transformed into a did
        kid: String,

        /// Message supplied by the library to give additional context
        message: String,
    } = 306,

    /// did, `kid`, could not be found in the did document
    #[error("Unable to find the verification method the did, `kid`, was referring to")]
    UnableToResolveDidInDidDocument {
        /// The absolute did that could not be found in the document
        did: String,

        /// Message supplied by the library to give additional context
        message: String,
    } = 307,

    /// Verification method from the did document could not be mapped to a `JWK`
    #[error("Unable to map the verification method to a JWK")]
    UnableToMapVerificationMethodToJwk {
        /// Message supplied by the library to give additional context
        messsage: String,
    } = 308,

    /// Could not tranfrom a string into a valid jose item, e.g. jwk, jwt, etc.
    #[error("Unable to convert '{original_string}' into a valid Jose Item")]
    UnableToTransformIntoJoseItem {
        /// Value that has to be transformed into a Jose Item
        original_string: String,

        /// Error message directly from [`serde`]
        serde_message: String,
    } = 309,

    /// Algorithm that was supplied is not supported by this library
    #[error("supplied algorithm, '{algorithm}' is not valid")]
    UnsupportedAlgorithm {
        /// The invalid algorithm
        algorithm: String,
    } = 310,

    /// edDSA needs an `x` coordinate to determine the public key
    #[error("JWK with algorithm of 'edDSA' has no x coordinate")]
    EdDSAHasNoXCoordinate = 311,

    /// ESxxx needs both `x` and `y` coordinates to get the public key
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
        /// Name of the key used
        key_name: String,

        /// Specified key type that is not supported
        key_type: String,
    } = 314,

    /// Supplied nonce did not match the nonce inside the `JWT`
    #[error("Expected nonce was not found in the JWT")]
    NonceMismatch {
        /// Supplied nonce
        expected_nonce: Option<String>,

        /// Nonce in the `JWT`
        actual_nonce: String,
    } = 315,

    /// Supplied subject did not match the subject inside the `JWT`
    #[error("Expected subject was not found in the JWT")]
    SubjectMismatch {
        /// Supplied subject
        expected_subject: Option<String>,

        /// Subject in the `JWT`
        actual_subject: Option<String>,
    } = 316,
}

/// JWT result used for the [`JwtError`]
pub type JwtResult<T> = std::result::Result<T, JwtError>;

error_impl!(JwtError, JwtResult);
