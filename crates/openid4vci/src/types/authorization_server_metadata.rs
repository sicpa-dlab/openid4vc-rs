use serde::Serialize;

/// Authorization server metadata as defined in [RFC8414](https://www.rfc-editor.org/rfc/rfc8414.txt)
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct AuthorizationServerMetadata {}
