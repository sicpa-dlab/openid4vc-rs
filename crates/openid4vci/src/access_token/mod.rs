use thiserror::Error;

/// Error enum for development when an error occurs related to the `Token` struct.
#[derive(Error, Debug, PartialEq)]
pub enum Error {}

/// Module containing a structure for the error response
pub mod error_response;

/// Token structure which contains methods to create responses and evaluate input
pub struct AccessToken;
