use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;

use crate::credential_issuer::AuthorizedCodeFlow;
use crate::credential_issuer::CredentialOffer;
use crate::credential_issuer::CredentialOfferGrants;
use crate::credential_issuer::PreAuthorizedCodeFlow;
use crate::error_response::ErrorResponse;
use crate::types::token_type::AccessTokenType;
use crate::validate::Validatable;
use crate::validate::ValidationError;

use self::error::{AccessTokenError, AccessTokenResult};
use self::error_response::AccessTokenErrorCode;

/// Error module for the access token module
pub mod error;

/// Module containing a structure for the error response
pub mod error_response;

/// Struct mapping for a `token error response` as defined in section 6.3 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-6.3)
pub type AccessTokenErrorResponse = ErrorResponse<AccessTokenErrorCode>;

/// Token structure which contains methods to create responses and evaluate input
pub struct AccessToken;

/// Struct mapping for a `token success response` as defined in section 6.2 of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-6.2)
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AccessTokenSuccessResponse {
    /// (OAuth2) The access token issued by the authorization server.
    pub access_token: String,

    /// (OAuth2) The type of the token issued as described in Section 7.1 of the [OAuth2 specification](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1).
    /// Value is case insensitive.
    pub token_type: AccessTokenType,

    /// (OAuth2) RECOMMENDED. The lifetime in seconds of the access token.  For example, the value "3600" denotes that the access token will
    /// expire in one hour from the time the response was generated. If omitted, the authorization server SHOULD provide the
    /// expiration time via other means or document the default value.
    pub expires_in: Option<u32>,

    /// (OAuth2) OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.
    /// The scope of the access token as described by Section 3.3 of the [OAuth2 Specification](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
    pub scope: Option<String>,

    /// Nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2). When received,
    /// the Wallet MUST use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce.
    pub c_nonce: Option<String>,

    /// The lifetime in seconds of the `c_nonce`
    pub c_nonce_expires_in: Option<u32>,

    /// In the Pre-Authorized Code Flow, the Token Request is still pending as the Credential Issuer is waiting
    /// for the End-User interaction to complete. The client SHOULD repeat the Token Request. Before each new request,
    /// the client MUST wait at least the number of seconds specified by the `interval` response parameter.
    pub authorization_pending: Option<bool>,

    /// The minimum amount of time in seconds that the client SHOULD wait between polling requests to the
    /// Token Endpoint in the Pre-Authorized Code Flow. If no value is provided, clients MUST use 5 as the default.
    pub interval: Option<u32>,
}

impl Validatable for AccessTokenSuccessResponse {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.c_nonce.is_none() && self.c_nonce_expires_in.is_some() {
            return Err(ValidationError::Any {
                validation_message: "c_nonce_expires_in is provided, but c_nonce is not".to_owned(),
            });
        }
        Ok(())
    }
}

/// Grant type for the access token request as specified in section 6.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-6.1)
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "grant_type")]
pub enum GrantType {
    /// indicator for authorized code flow
    #[serde(rename = "authorization_code")]
    AuthorizedCodeFlow,
    /// indicator for pre-authorized code flow
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCodeFlow {
        /// The code representing the authorization to obtain Credentials of a certain type. This
        /// parameter is required if the grant_type is
        /// urn:ietf:params:oauth:grant-type:pre-authorized_code.
        pre_authorized_code: String,

        /// String value containing a user PIN. This value MUST be present if `user_pin_required`
        /// was set to true in the [`CredentialOffer`]. The string value MUST consist of maximum 8
        /// numeric characters (the numbers 0 - 9). This parameter MUST only be used, if the
        /// grant_type is `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
        user_pin: Option<u64>,
    },
}

impl Validatable for GrantType {
    fn validate(&self) -> Result<(), crate::validate::ValidationError> {
        match self {
            GrantType::AuthorizedCodeFlow => Ok(()),
            GrantType::PreAuthorizedCodeFlow { user_pin, .. } => {
                if let Some(user_pin) = user_pin {
                    let max = 8;
                    let length = user_pin.checked_ilog10().unwrap_or_default();
                    if length > max {
                        return Err(ValidationError::Any {
                            validation_message: format!(
                                "user pin exeeded length. Maximum is {max}, supplied is {length}"
                            ),
                        });
                    }
                }

                Ok(())
            }
        }
    }
}

/// Access token request structure that contains metadata about the request
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AccessTokenRequest {
    /// Grant type for the request
    grant_type: GrantType,
}

impl Validatable for AccessTokenRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.grant_type.validate()?;

        Ok(())
    }
}

/// Additional options for validation for the `access_token` request
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EvaluateAccessTokenRequestOptions {
    /// Provided user code to validate against
    user_code: Option<u64>,
}

impl AccessToken {
    /// Evaluate an access token request
    ///
    /// # Errors
    ///
    /// - When the authorized code flow is used
    /// - When the `user_pin` has more than 8 characters
    /// - When the `grant_type` of the [`AccessTokenRequest`] does not match the `grant_type` of
    ///   the [`CredentialOffer`]
    pub fn evaluate_access_token_request(
        access_token_request: &AccessTokenRequest,
        credential_offer: Option<CredentialOffer>,
        evaluate_access_token_request_options: Option<EvaluateAccessTokenRequestOptions>,
    ) -> AccessTokenResult<()> {
        access_token_request.validate()?;

        if access_token_request.grant_type == GrantType::AuthorizedCodeFlow {
            return Err(AccessTokenError::AuthorizedFlowNotSupported);
        };

        let validate_authorized_code_flow =
            |_: AuthorizedCodeFlow, grant_type: &GrantType| match &grant_type {
                GrantType::AuthorizedCodeFlow => Ok(()),
                GrantType::PreAuthorizedCodeFlow { .. } => {
                    Err(AccessTokenError::InvalidGrantType {
                        requested_grant_type: "pre_authorized_code_flow".to_owned(),
                        accepted_grant_type: vec!["authorized_code_flow".to_owned()],
                    })
                }
            };

        let validate_pre_authorized_code_flow =
            |p: PreAuthorizedCodeFlow, grant_type: &GrantType| match &grant_type {
                GrantType::AuthorizedCodeFlow => Err(AccessTokenError::InvalidGrantType {
                    requested_grant_type: "authorized_code_flow".to_owned(),
                    accepted_grant_type: vec!["pre_authorized_code_flow".to_owned()],
                }),
                GrantType::PreAuthorizedCodeFlow {
                    pre_authorized_code,
                    user_pin,
                } => {
                    if let Some(user_pin) = user_pin {
                        let evaluate_access_token_request_options =
                            evaluate_access_token_request_options.ok_or(
                                AccessTokenError::OptionsAreRequiredForEvaluation {
                                    reason: "user_pin was supplied in the access token request"
                                        .to_owned(),
                                },
                            )?;

                        let user_code_from_options = evaluate_access_token_request_options
                            .user_code
                            .ok_or(AccessTokenError::OptionsAreRequiredForEvaluation {
                                reason: "user_pin was supplied in the access token request"
                                    .to_owned(),
                            })?;

                        if user_pin != &user_code_from_options {
                            return Err(AccessTokenError::UserPinMismatch);
                        }
                    };

                    let should_pin_be_supplied = p.user_pin_required.unwrap_or_default();
                    let does_code_match = p.code == *pre_authorized_code;
                    let is_valid = user_pin.is_some() == should_pin_be_supplied && does_code_match;

                    if is_valid {
                        Ok(())
                    } else {
                        Err(AccessTokenError::InvalidPreAuthorizedCodeFlowValues {
                            should_pin_be_supplied,
                            does_code_match,
                        })
                    }
                }
            };

        if let Some(credential_offer) = credential_offer {
            let CredentialOfferGrants {
                authorized_code_flow,
                pre_authorized_code_flow,
            } = credential_offer.grants;

            match (authorized_code_flow, pre_authorized_code_flow) {
                (None, None) => Err(AccessTokenError::NoFlowSupportedInCredentialOffer),
                (None, Some(pre_authorized_code_flow)) => validate_pre_authorized_code_flow(
                    pre_authorized_code_flow,
                    &access_token_request.grant_type,
                ),
                (Some(authorized_code_flow), None) => validate_authorized_code_flow(
                    authorized_code_flow,
                    &access_token_request.grant_type,
                ),
                (Some(authorized_code_flow), Some(pre_authorized_code_flow)) => {
                    let is_authorized_valid = validate_authorized_code_flow(
                        authorized_code_flow,
                        &access_token_request.grant_type,
                    );
                    let is_pre_authorized_valid = validate_pre_authorized_code_flow(
                        pre_authorized_code_flow,
                        &access_token_request.grant_type,
                    );

                    match (is_authorized_valid, is_pre_authorized_valid) {
                        (Err(authorized_error), Err(pre_authorized_error)) => Err(
                            AccessTokenError::InvalidAuthorizedAndPreAuthorizedCodeFlow {
                                authorized_error: Box::new(authorized_error),
                                pre_authorized_error: Box::new(pre_authorized_error),
                            },
                        ),
                        _ => Ok(()),
                    }
                }
            }
        } else {
            Err(AccessTokenError::CredentialOfferMustBeSupplied)
        }
    }

    /// Create an error response
    ///
    /// # Errors
    ///
    /// Unable to error, `Result` is used for consistency
    pub fn create_access_token_error_response(
        error: error_response::AccessTokenErrorCode,
        error_description: Option<String>,
        error_uri: Option<String>,
        error_additional_details: Option<serde_json::Value>,
    ) -> AccessTokenResult<AccessTokenErrorResponse> {
        let error_response = AccessTokenErrorResponse {
            error,
            error_description,
            error_uri,
            error_additional_details,
        };

        Ok(error_response)
    }

    /// Create a success response
    ///
    /// # Errors
    ///
    /// Unable to error, `Result` is used for consistency
    #[allow(clippy::too_many_arguments)]
    pub fn create_access_token_success_response(
        access_token: String,
        token_type: AccessTokenType,
        expires_in: Option<u32>,
        scope: Option<String>,
        c_nonce: Option<String>,
        c_nonce_expires_in: Option<u32>,
        authorization_pending: Option<bool>,
        interval: Option<u32>,
    ) -> AccessTokenResult<(AccessTokenSuccessResponse, DateTime<Utc>)> {
        let token_response = AccessTokenSuccessResponse {
            access_token,
            token_type,
            expires_in,
            scope,
            c_nonce,
            c_nonce_expires_in,
            authorization_pending,
            interval,
        };

        Ok((token_response, Utc::now()))
    }
}

#[cfg(test)]
mod test_access_token_evaluate_request {
    use crate::credential_issuer::{AuthorizedCodeFlow, CredentialOrIds, PreAuthorizedCodeFlow};

    use super::*;

    #[test]
    fn should_evaluate_access_token_request() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "abc".to_owned(),
                user_pin: Some(123_213),
            },
        };
        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: Some(AuthorizedCodeFlow { issuer_state: None }),
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: Some(true),
                }),
            },
        };

        let evaluate_access_token_request_options = EvaluateAccessTokenRequestOptions {
            user_code: Some(123_213),
        };

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            Some(evaluate_access_token_request_options),
        );

        assert!(output.is_ok());
    }

    #[test]
    fn should_not_evaluate_access_token_request_without_credential_offer() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "0123".to_owned(),
                user_pin: Some(123_213),
            },
        };

        let evaluate_access_token_request_options = EvaluateAccessTokenRequestOptions {
            user_code: Some(123_213),
        };

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            None,
            Some(evaluate_access_token_request_options),
        );

        assert_eq!(output, Err(AccessTokenError::CredentialOfferMustBeSupplied));
    }

    #[test]
    fn should_not_evaluate_access_token_request_with_pin_mismatch() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "0123".to_owned(),
                user_pin: Some(123213),
            },
        };
        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: None,
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: Some(true),
                }),
            },
        };

        let evaluate_access_token_request_options = EvaluateAccessTokenRequestOptions {
            user_code: Some(111),
        };

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            Some(evaluate_access_token_request_options),
        );

        assert_eq!(output, Err(AccessTokenError::UserPinMismatch));
    }

    #[test]
    fn should_not_evaluate_access_token_request_with_pre_authorized_code_mismatch() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "0123".to_owned(),
                user_pin: Some(123213),
            },
        };
        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: None,
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: Some(true),
                }),
            },
        };

        let evaluate_access_token_request_options = EvaluateAccessTokenRequestOptions {
            user_code: Some(123213),
        };

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            Some(evaluate_access_token_request_options),
        );

        assert!(matches!(
            output,
            Err(AccessTokenError::InvalidPreAuthorizedCodeFlowValues {
                does_code_match: false,
                ..
            })
        ));
    }

    #[test]
    fn should_evaluate_access_token_with_both_grant_types_in_credential_offer() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "abc".to_owned(),
                user_pin: None,
            },
        };

        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: Some(AuthorizedCodeFlow { issuer_state: None }),
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: None,
                }),
            },
        };

        let evaluate_access_token_request_options = None;

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            evaluate_access_token_request_options,
        );

        assert!(output.is_ok());
    }

    #[test]
    fn should_evaluate_access_token_with_matching_grant_type_in_credential_offer() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "abc".to_owned(),
                user_pin: Some(123),
            },
        };

        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: None,
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: Some(true),
                }),
            },
        };

        let evaluate_access_token_request_options = EvaluateAccessTokenRequestOptions {
            user_code: Some(123),
        };

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            Some(evaluate_access_token_request_options),
        );

        assert!(output.is_ok());
    }

    #[test]
    fn should_not_evaluate_access_token_with_required_pin_but_none_supplied() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "abc".to_owned(),
                user_pin: None,
            },
        };

        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: None,
                pre_authorized_code_flow: Some(PreAuthorizedCodeFlow {
                    code: "abc".to_owned(),
                    user_pin_required: Some(true),
                }),
            },
        };

        let evaluate_access_token_request_options = None;

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            evaluate_access_token_request_options,
        );

        assert_eq!(
            output,
            Err(AccessTokenError::InvalidPreAuthorizedCodeFlowValues {
                should_pin_be_supplied: true,
                does_code_match: true
            })
        );
    }

    #[test]
    fn should_not_evaluate_access_token_request_when_user_pin_is_invalid() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "0123".to_owned(),
                user_pin: Some(11111111111),
            },
        };

        let credential_offer = None;

        let evaluate_access_token_request_options = None;

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            credential_offer,
            evaluate_access_token_request_options,
        );

        assert_eq!(
            output,
            Err(AccessTokenError::ValidationError(ValidationError::Any {
                validation_message: "user pin exeeded length. Maximum is 8, supplied is 10"
                    .to_owned()
            }))
        );
    }

    #[test]
    fn should_not_evaluate_access_token_request_when_authorized_code_flow_is_used() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::AuthorizedCodeFlow,
        };

        let credential_offer = None;

        let evaluate_access_token_request_options = None;

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            credential_offer,
            evaluate_access_token_request_options,
        );

        assert_eq!(output, Err(AccessTokenError::AuthorizedFlowNotSupported));
    }

    #[test]
    fn should_not_evaluate_access_token_request_when_grant_type_in_offer_does_not_match() {
        let access_token_request = AccessTokenRequest {
            grant_type: GrantType::PreAuthorizedCodeFlow {
                pre_authorized_code: "abc".to_owned(),
                user_pin: None,
            },
        };

        let credential_offer = CredentialOffer {
            credential_issuer: "me".to_owned(),
            credentials: CredentialOrIds::new(vec![]),
            grants: CredentialOfferGrants {
                authorized_code_flow: Some(AuthorizedCodeFlow { issuer_state: None }),
                pre_authorized_code_flow: None,
            },
        };

        let evaluate_access_token_request_options = None;

        let output = AccessToken::evaluate_access_token_request(
            &access_token_request,
            Some(credential_offer),
            evaluate_access_token_request_options,
        );

        assert!(matches!(
            output,
            Err(AccessTokenError::InvalidGrantType { .. })
        ));
    }
}

#[cfg(test)]
mod test_access_token_error_response {
    use super::*;

    #[test]
    fn error_response() {
        let error_response = AccessToken::create_access_token_error_response(
            AccessTokenErrorCode::InvalidRequest,
            Some("error description".to_owned()),
            Some("error uri".to_owned()),
            None,
        )
        .expect("Unable to create access token error response");

        assert_eq!(error_response.error, AccessTokenErrorCode::InvalidRequest);
        assert_eq!(
            error_response.error_description,
            Some("error description".to_string())
        );
        assert_eq!(error_response.error_uri, Some("error uri".to_string()));
    }
}

#[cfg(test)]
mod test_access_token_success_response {
    use super::*;

    #[test]
    fn success_response() {
        let (success_response, _) = AccessToken::create_access_token_success_response(
            "Hello".to_string(),
            AccessTokenType::Bearer,
            Some(3600),
            Some("scope".to_string()),
            Some("c_nonce".to_string()),
            Some(3600),
            Some(true),
            Some(5),
        )
        .expect("Unable to create access token success response");

        assert_eq!(success_response.access_token, "Hello".to_string());
        assert_eq!(success_response.token_type, AccessTokenType::Bearer);
        assert_eq!(success_response.expires_in, Some(3600));
        assert_eq!(success_response.scope, Some("scope".to_string()));
        assert_eq!(success_response.c_nonce, Some("c_nonce".to_string()));
        assert_eq!(success_response.c_nonce_expires_in, Some(3600));
        assert_eq!(success_response.authorization_pending, Some(true));
        assert_eq!(success_response.interval, Some(5));
    }
}
