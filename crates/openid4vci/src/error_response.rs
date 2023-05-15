use serde::Serialize;

/// Generic struct mapping for a `token error response`
#[derive(Serialize, Debug, PartialEq)]
pub struct ErrorResponse<T>
where
    T: Serialize + PartialEq,
{
    /// Error code indicating why the request failed.
    pub error: T,

    /// Human-readable ASCII text providing additional information,
    /// used to assist the client developer in understanding the error that occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,

    /// Optonal additional details containing metadata about the error
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub error_additional_details: Option<serde_json::Value>,
}
