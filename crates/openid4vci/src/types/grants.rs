use serde::{Deserialize, Serialize};

/// A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
/// to process for this credential offer. Every grant is represented by a key and an object. The
/// key value is the Grant Type identifier, the object MAY contain parameters either determining
/// the way the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with
/// the respective request(s). If grants is not present or empty, the Wallet MUST determine the
/// Grant Types the Credential Issuer's AS supports using the respective metadata. When multiple
/// grants are present, it's at the Wallet's discretion which one to use.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Grants {
    /// Adds support for the authorized code flow as defined in section 3.4 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-3.4).
    #[serde(skip_serializing_if = "Option::is_none", rename = "authorization_code")]
    pub authorized_code_flow: Option<AuthorizedCodeFlow>,

    /// Adds support for the pre-authorized code flow as defined in section 3.5 of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-3.5).
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    )]
    pub pre_authorized_code_flow: Option<PreAuthorizedCodeFlow>,
}

/// Field that defined the optional values for when the authorized code flow is used
#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
pub struct AuthorizedCodeFlow {
    /// Issuer state that MUST be the same, if supplied, from the authorization request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Field that defines the optional values for when the pre-authorized code flow is used
#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
pub struct PreAuthorizedCodeFlow {
    /// The code representing the Credential Issuer's authorization for the Wallet to obtain
    /// Credentials of a certain type. This code MUST be short lived and single-use. If the Wallet
    /// decides to use the Pre-Authorized Code Flow, this parameter value MUST be include in the
    /// subsequent Token Request with the Pre-Authorized Code Flow.
    #[serde(rename = "pre-authorized_code")]
    pub code: String,

    /// Boolean value specifying whether the Credential Issuer expects presentation of a user PIN
    /// along with the Token Request in a Pre-Authorized Code Flow. Default is false. This PIN is
    /// intended to bind the Pre-Authorized Code to a certain transaction in order to prevent
    /// replay of this code by an attacker that, for example, scanned the QR code while standing
    /// behind the legit user. It is RECOMMENDED to send a PIN via a separate channel. If the
    /// Wallet decides to use the Pre-Authorized Code Flow, a PIN value MUST be sent in the
    /// user_pin parameter with the respective Token Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin_required: Option<bool>,
}
