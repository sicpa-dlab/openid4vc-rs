use serde::Serialize;
use thiserror::Error;

/// Result type which automatically sets the error type to [`AccessTokenError`]
pub type AccessTokenResult<T> = std::result::Result<T, AccessTokenError>;

/// Error enum for development when an error occurs related to the [`super::AccessToken`] struct.
// TODO: Enable when we add an item to the enum
// #[repr(u32)]
#[derive(Error, Debug, PartialEq, Clone, AsRefStr, Serialize)]
#[serde(untagged)]
pub enum AccessTokenError {}

error_impl!(AccessTokenError, AccessTokenResult);

#[cfg(test)]
mod access_token_error_tests {
    // TODO: add test when we add errors to the enum
}
