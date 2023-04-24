use self::error::{JwtError, JwtResult};
use crate::base::base64url;
use crate::types::credential_request::OPENID4VCI_PROOF_TYPE;
use crate::validate::{Validatable, ValidationError, ValidationResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Error module for the JWT module
pub mod error;

/// IANA JSON Web Signature and Encryption Algorithms
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum ProofJwtAlgorithm {
    /// HMAC using SHA-256
    HS256,

    /// HMAC using SHA-384
    HS384,

    /// HMAC using SHA-512
    HS512,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,

    /// ECDSA using P-256 and SHA-256
    ES256,

    /// ECDSA using P-256 and SHA-384
    ES384,

    /// ECDSA using P-256 and SHA-512
    ES512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-384
    PS384,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-512
    PS512,

    /// EdDSA signature algorithms
    EdDSA,

    /// ECDSA using secp256k1 curve and SHA-256
    ES256K,

    /// ECDH-ES using Concat KDF
    #[serde(rename = "ECDH-ES")]
    ECDHES,

    /// No digital signature or MAC performed
    #[serde(rename = "none")]
    None,
}

/// Struct mapping of `jwt` in the `proof types` as defined in section 7.2.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof_types)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofJwt {
    /// JOSE header for a `jwt` proof
    pub header: ProofJwtHeader,

    /// JOSE body for a `jwt` proof
    pub body: ProofJwtBody,

    /// String value of the signature for a `jwt` proof
    pub signature: Option<String>,
}

impl FromStr for ProofJwt {
    type Err = ValidationError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut res = s.split('.');
        let header = res.next().ok_or(ValidationError::Any {
            validation_message: "No header found in the `JWT`".to_owned(),
        })?;

        let body = res.next().ok_or(ValidationError::Any {
            validation_message: "No body found in the `JWT`".to_owned(),
        })?;

        let signature = res.next();

        let header = base64url::decode(header)?;
        let body = base64url::decode(body)?;

        let header: ProofJwtHeader = serde_json::from_slice(&header)?;
        let body: ProofJwtBody = serde_json::from_slice(&body)?;

        Ok(ProofJwt {
            header,
            body,
            signature: signature.map(ToOwned::to_owned),
        })
    }
}

impl TryInto<String> for &ProofJwt {
    type Error = JwtError;

    fn try_into(self) -> Result<String, Self::Error> {
        let mut jwt = Vec::with_capacity(3);

        let s_header = serde_json::to_string(&self.header).map_err(|e| {
            JwtError::UnableToTransformIntoJoseItem {
                original_string: format!("{:?}", self.header),
                serde_message: e.to_string(),
            }
        })?;

        let s_body = serde_json::to_string(&self.body).map_err(|e| {
            JwtError::UnableToTransformIntoJoseItem {
                original_string: format!("{:?}", self.body),
                serde_message: e.to_string(),
            }
        })?;

        jwt.push(s_header);
        jwt.push(s_body);
        if let Some(s) = &self.signature {
            jwt.push(s.clone());
        }

        Ok(jwt.join("."))
    }
}

impl ProofJwt {
    /// Verify a JWT given additional input
    ///
    /// # Errors
    ///
    /// - When the [`ProofJwtBody::not_before`] is greater than [`chrono::Utc::now`]
    /// - When the [`ProofJwtBody::expires_at`] is smaller than [`chrono::Utc::now`]
    /// - When the [`ProofJwtBody::issuer_claim`] is not equal to the provided `client_id`
    pub fn verify(&self, client_id: Option<&str>) -> JwtResult<()> {
        let now = Utc::now();

        if let Some(not_before) = self.body.not_before {
            if now < not_before {
                return Err(JwtError::NotYetValid {
                    valid_from: not_before,
                    now,
                });
            }
        }

        if let Some(expires_at) = self.body.expires_at {
            if now > expires_at {
                return Err(JwtError::NotValidAnymore {
                    valid_until: expires_at,
                    now,
                });
            }
        }

        let client_id = client_id.map(ToOwned::to_owned);
        if self.body.issuer_claim != client_id {
            return Err(JwtError::IssuerMismatch {
                iss: self.body.issuer_claim.clone(),
                client_id,
            });
        }

        Ok(())
    }

    /// Extract the kid from the header. When `x5c` or `jwk` is used, nothing will be returned. Or
    /// when the kid is not a did
    ///
    /// # Errors
    ///
    /// - When
    pub fn extract_kid(&self) -> JwtResult<Option<String>> {
        if let Some(header) = &self.header.additional_header {
            match header {
                ProofJwtAdditionalHeader::KeyId(key_id) => {
                    let did = ssi_dids::DIDURL::try_from(key_id.clone()).map_err(|e| {
                        JwtError::UnableToTransformIntoDid {
                            kid: key_id.clone(),
                            message: e.to_string(),
                        }
                    })?;

                    Ok(Some(did.to_string()))
                }
                ProofJwtAdditionalHeader::Jwk(jwk) => {
                    Err(JwtError::UnsupportedKeyTypeInJwtHeader {
                        key_name: "jwk".to_owned(),
                        key_type: jwk.clone(),
                    })
                }
                ProofJwtAdditionalHeader::X5c(x5c) => {
                    Err(JwtError::UnsupportedKeyTypeInJwtHeader {
                        key_name: "x5c".to_owned(),
                        key_type: x5c.clone(),
                    })
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Extract the key and algorithm from the [`ProofJwtHeader`]
    ///
    /// # Errors
    ///
    /// - When [`ProofJwtHeader::extract_key_and_alg`] errors
    pub fn extract_key_and_alg(
        &self,
        did_document: Option<&ssi_dids::Document>,
    ) -> JwtResult<(Vec<u8>, ProofJwtAlgorithm)> {
        self.header.extract_key_and_alg(did_document)
    }

    /// Create a signable message of the JWT
    ///
    /// > NOTE: It is important to note that these bytes still need to be hashed with the algorithm
    /// specified in the JWT header.
    ///
    /// # Errors
    ///
    /// - When it could not convert the JWT to a string
    pub fn to_signable_message(&self) -> JwtResult<Vec<u8>> {
        // Convert the JWT into a string
        let message: String = self.try_into()?;

        // Remove the signature if its defined, detected by two occurences of "."
        let message = if message.matches('.').count() == 2 {
            let parts: Vec<_> = message.split('.').collect();
            format!("{}.{}", parts[0], parts[1])
        } else {
            message
        };

        // Return the message as bytes
        Ok(message.as_bytes().to_vec())
    }

    /// Extract the signature from the `jwt`.
    ///
    /// # Errors
    ///
    /// - When the signature is not defined
    pub fn extract_signature(&self) -> JwtResult<Vec<u8>> {
        // Convert the JWT into a string
        let s_jwt: String = self.try_into()?;

        // Split into 3 parts (header, payload, signature)
        let jwt = s_jwt.clone();
        let parts: Vec<_> = jwt.splitn(3, '.').collect();

        // Get the second index, the signature and error if not defined
        let signature = parts
            .get(2)
            .ok_or(JwtError::SignatureNotInJwt { jwt: s_jwt })?;

        // Return the bytes of the signature
        Ok(signature.as_bytes().to_vec())
    }
}

/// Struct mapping of `jwt header` in the `proof types` as defined in section 7.2.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof_types)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofJwtHeader {
    /// MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in
    /// Section 3.11 of [RFC8725](https://www.rfc-editor.org/rfc/rfc8725.txt).
    pub typ: String,

    /// A digital signature algorithm identifier such as per IANA "JSON Web Signature and
    /// Encryption Algorithms" registry. MUST NOT be none or an identifier for a symmetric
    /// algorithm (MAC).
    pub alg: ProofJwtAlgorithm,

    /// Optional additional field containing, `kid`, `jwk` or `x5c`.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub additional_header: Option<ProofJwtAdditionalHeader>,
}

impl ProofJwtHeader {
    /// Extract the key and algorithm from the JWT header
    ///
    /// TODO: Not every method is implemented yet
    /// TODO: reuse extract kid method
    ///
    /// # Errors
    pub fn extract_key_and_alg(
        &self,
        did_document: Option<&ssi_dids::Document>,
    ) -> JwtResult<(Vec<u8>, ProofJwtAlgorithm)> {
        match &self.additional_header {
            Some(additional_header) => {
                match additional_header {
                    ProofJwtAdditionalHeader::KeyId(key_id) => {
                        // TODO: can the `key_id` also be anything other than a `did`

                        let did = ssi_dids::DIDURL::try_from(key_id.clone()).map_err(|e| {
                            JwtError::UnableToTransformIntoDid {
                                kid: key_id.clone(),
                                message: e.to_string(),
                            }
                        })?;

                        let did_document = did_document
                            .as_ref()
                            .ok_or(JwtError::NoDidDocumentProvidedForKidAsDid)?;

                        let object = did_document.select_object(&did).map_err(|e| {
                            JwtError::UnableToResolveDidInDidDocument {
                                did: did.to_string(),
                                message: e.to_string(),
                            }
                        })?;

                        match object {
                            ssi_dids::Resource::VerificationMethod(verification_method) => {
                                // TODO: from the JWK we get an algorithm. Do we want to compare
                                // this to the algorithm in the header?
                                let jwk = verification_method.get_jwk().map_err(|e| {
                                    JwtError::UnableToMapVerificationMethodToJwk {
                                        messsage: e.to_string(),
                                    }
                                })?;

                                let public_key_bytes = Self::jwk_to_public_key_bytes(&jwk)?;

                                Ok((public_key_bytes, self.alg.clone()))
                            }
                            // This pattern is unreachable as `Resource::Verificationmethod` or an
                            // `Error` is returned by `select_object` on the did_document
                            _ => unreachable!(),
                        }
                    }
                    ProofJwtAdditionalHeader::Jwk(jwk) => {
                        let jwk: ssi_jwk::JWK = serde_json::from_str(jwk).map_err(|e| {
                            JwtError::UnableToTransformIntoJoseItem {
                                original_string: jwk.clone(),
                                serde_message: e.to_string(),
                            }
                        })?;

                        let public_key_bytes = Self::jwk_to_public_key_bytes(&jwk)?;

                        Ok((public_key_bytes, self.alg.clone()))
                    }
                    ProofJwtAdditionalHeader::X5c(x5c) => {
                        Err(JwtError::UnsupportedKeyTypeInJwtHeader {
                            key_name: "x5c".to_owned(),
                            key_type: x5c.clone(),
                        })
                    }
                }
            }
            None => Err(JwtError::NoKeyFoundInProof),
        }
    }

    /// Converts a given jwk to a public key
    ///
    /// For now only the following types are supported:
    ///
    /// - `EdDSA`
    ///
    /// # Errors
    ///
    /// - when an unsupported algorithm is used
    /// - When a symmetric key pair is used
    fn jwk_to_public_key_bytes(jwk: &ssi_jwk::JWK) -> JwtResult<Vec<u8>> {
        let alg = jwk.get_algorithm().unwrap_or_default();
        let alg_name = serde_json::to_string(&alg).unwrap();

        // TODO: how can we go from the parameters to the public key value
        match &jwk.params {
            ssi_jwk::Params::EC(params) => match alg {
                ssi_jwk::Algorithm::EdDSA => {
                    let x = params
                        .x_coordinate
                        .as_ref()
                        .ok_or(JwtError::EdDSAHasNoXCoordinate)?;

                    Ok(x.0.clone())
                }
                // ssi_jwk::Algorithm::ES256
                // | ssi_jwk::Algorithm::ES384
                // | ssi_jwk::Algorithm::ES256K => {
                //     let x_coordinate = params.x_coordinate.as_ref().map(|x| x.0.clone());
                //     let y_coordinate = params.y_coordinate.as_ref().map(|y| y.0.clone());

                //     let x = x_coordinate
                //         .clone()
                //         .ok_or(JwtError::ESXXXHasNoXOrYCoordinate {
                //             algorithm: alg_name.clone(),
                //             x: None,
                //             y: y_coordinate.clone(),
                //         })?;
                //     let y = y_coordinate.ok_or(JwtError::ESXXXHasNoXOrYCoordinate {
                //         algorithm: alg_name,
                //         x: x_coordinate,
                //         y: None,
                //     })?;
                //     let mut uncompressed_pk = Vec::with_capacity(1 + x.len() + y.len());
                //     uncompressed_pk.push(0x04);
                //     uncompressed_pk.extend(x);
                //     uncompressed_pk.extend(y);

                //     Ok(uncompressed_pk)
                // }
                _ => Err(JwtError::UnsupportedAlgorithm {
                    algorithm: alg_name,
                }),
            },
            ssi_jwk::Params::OKP(params) => Ok(params.public_key.0.clone()),
            _ => Err(JwtError::UnsupportedAlgorithm {
                algorithm: alg_name,
            }),
        }
    }
}

/// enum containing either a `kid`, `jwk` or `x5c`.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum ProofJwtAdditionalHeader {
    /// JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid
    /// refers to a DID URL which identifies a particular key in the DID Document that the
    /// Credential shall be bound to. MUST NOT be present if jwk or x5c is present.
    #[serde(rename = "kid")]
    KeyId(String),
    /// JOSE Header containing the key material the new Credential shall be bound to. MUST NOT be
    /// present if kid or x5c is present
    #[serde(rename = "jwk")]
    Jwk(String),
    /// JOSE Header containing a certificate or certificate chain corresponding to the key used to sign
    /// the JWT. This element MAY be used to convey a key attestation. In such a case, the actual
    /// key certificate will contain attributes related to the key properties. MUST NOT be present
    /// if kid or jwk is present.
    #[serde(rename = "x5c")]
    X5c(String),
}

/// Struct mapping of `jwt body` in the `proof types` as defined in section 7.2.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof_types)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofJwtBody {
    /// The value of this claim MUST be the client_id of the client making the credential request.
    /// This claim MUST be omitted if the Access Token authorizing the issuance call was obtained
    /// from a Pre-Authorized Code Flow through anonymous access to the Token Endpoint.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer_claim: Option<String>,

    /// The value of this claim MUST be the Credential Issuer URL of the Credential Issuer.
    #[serde(rename = "aud")]
    pub audience_claim: String,

    /// The value of this claim MUST be the time at which the proof was issued using the syntax
    /// defined in [RFC7519](https://www.rfc-editor.org/rfc/rfc7519.txt).
    #[serde(rename = "iat")]
    pub issued_at: DateTime<Utc>,

    /// The value type of this claim MUST be a string, where the value is a `c_nonce` provided by
    /// the Credential Issuer.
    pub nonce: String,

    /// The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted
    /// for processing. The processing of the "nbf" claim requires that the current date/time MUST
    /// be after or equal to the not-before date/time listed in the "nbf" claim.  Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to account for clock
    /// skew.  Its value MUST be a number containing a NumericDate value.  Use of this claim is
    /// OPTIONAL.
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,

    /// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT
    /// MUST NOT be accepted for processing.  The processing of the "exp" claim requires that the
    /// current date/time MUST be before the expiration date/time listed in the "exp" claim.
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew.  Its value MUST be a number containing a NumericDate value.  Use of
    /// this claim is OPTIONAL.
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl Validatable for ProofJwt {
    fn validate(&self) -> ValidationResult<()> {
        self.body.validate()?;
        self.header.validate()?;

        Ok(())
    }
}

impl Validatable for ProofJwtHeader {
    fn validate(&self) -> ValidationResult<()> {
        // Check whether the `typ` is set to any casing of [`OPENID4VCI_PROOF_TYPE`]
        if self.typ != OPENID4VCI_PROOF_TYPE {
            return Err(ValidationError::Any {
                validation_message: "jwt header `typ` MUST of of value `openid4vci-proof+jwt`"
                    .to_owned(),
            });
        }

        Ok(())
    }
}

impl Validatable for ProofJwtAdditionalHeader {
    fn validate(&self) -> ValidationResult<()> {
        match self {
            Self::KeyId(_) => Ok(()),
            Self::Jwk(_) => Err(ValidationError::Any {
                validation_message: "JWK is not supported as key type in the JWT header".to_owned(),
            }),
            Self::X5c(_) => Err(ValidationError::Any {
                validation_message: "X5c is not supported as key type in the JWT header".to_owned(),
            }),
        }
    }
}

impl Validatable for ProofJwtBody {
    fn validate(&self) -> ValidationResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test_jwt {
    use super::*;
    use chrono::Months;
    use ssi_dids::Document;

    #[test]
    fn should_create_structure_from_valid_jwt() {
        // unofficial test vector:
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1-5
        let jwt = "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9";

        let jwt = ProofJwt::from_str(jwt).expect("Unable to decode jwt");

        // result of encoding: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1-7
        assert_eq!(jwt.header.typ, "JWT");
        assert_eq!(jwt.header.alg, ProofJwtAlgorithm::ES256);
        assert_eq!(
            jwt.header.additional_header,
            Some(ProofJwtAdditionalHeader::KeyId(
                "did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1".to_owned()
            ))
        );

        assert_eq!(jwt.body.issuer_claim, Some("s6BhdRkqt3".to_owned()));
        assert_eq!(jwt.body.audience_claim, "https://server.example.com");
        assert_eq!(jwt.body.nonce, "tZignsnFbp");

        // Here is a different timestamp used as in the test vector, as the data there is
        // incorrect.
        assert_eq!(jwt.body.issued_at.timestamp(), 1_536_959_950);
    }

    #[test]
    fn should_verify_valid_jwt() {
        let jwt = "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9";

        let jwt = ProofJwt::from_str(jwt).expect("Unable to decode jwt");
        let res = jwt.verify(Some("s6BhdRkqt3"));

        assert!(res.is_ok());
    }

    #[test]
    fn should_error_on_invalid_issuer_id() {
        let jwt = "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9";

        let jwt = ProofJwt::from_str(jwt).expect("Unable to decode jwt");
        let res = jwt.verify(Some("invalid-id"));

        assert_eq!(
            res,
            Err(JwtError::IssuerMismatch {
                iss: Some("s6BhdRkqt3".to_owned()),
                client_id: Some("invalid-id".to_owned())
            })
        );
    }

    #[test]
    fn should_error_on_invalid_expires_date() {
        let now = Utc::now();
        let past = now
            .checked_sub_months(Months::new(32))
            .expect("Unable to go into the future");

        let jwt = ProofJwt {
            body: ProofJwtBody {
                issuer_claim: None,
                audience_claim: "aud".to_owned(),
                issued_at: now,
                nonce: "nonce".to_owned(),
                not_before: None,
                expires_at: Some(past),
            },
            header: ProofJwtHeader {
                typ: "JWT".to_owned(),
                alg: ProofJwtAlgorithm::HS256,
                additional_header: None,
            },
            signature: None,
        };

        let res = jwt.verify(None);

        assert!(matches!(res, Err(JwtError::NotValidAnymore { .. })));
    }

    #[test]
    fn should_error_on_invalid_not_before_date() {
        let now = Utc::now();
        let future = now
            .checked_add_months(Months::new(32))
            .expect("Unable to go into the future");

        let jwt = ProofJwt {
            body: ProofJwtBody {
                issuer_claim: None,
                audience_claim: "aud".to_owned(),
                issued_at: now,
                nonce: "nonce".to_owned(),
                not_before: Some(future),
                expires_at: None,
            },
            header: ProofJwtHeader {
                typ: "JWT".to_owned(),
                alg: ProofJwtAlgorithm::HS256,
                additional_header: None,
            },
            signature: None,
        };

        let res = jwt.verify(None);

        assert!(matches!(res, Err(JwtError::NotYetValid { .. })));
    }

    #[test]
    fn should_correctly_extract_public_key_from_did_and_did_doc() {
        let public_key = "abc";
        let public_key_bytes = base64url::decode(public_key).expect("Unable to decode public key");

        let did_document = r#"{
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
          ],
          "id": "did:example:123",
          "verificationMethod": [
            {
              "id": "did:example:123#key-0",
              "type": "JsonWebKey2020",
              "controller": "did:example:123",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "<KEY>"
              }
            }
          ]
        }"#;

        let did_document = did_document.replace("<KEY>", public_key);

        let did_document: Document =
            serde_json::from_str(&did_document).expect("Unable to deserialize did doc");

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::None,
            additional_header: Some(ProofJwtAdditionalHeader::KeyId(
                "did:example:123#key-0".to_owned(),
            )),
        };

        let (key, alg) = jwt_header
            .extract_key_and_alg(Some(&did_document))
            .expect("Unable to extract public key from did doc");

        assert_eq!(alg, ProofJwtAlgorithm::None);
        assert_eq!(key, public_key_bytes);
    }

    #[test]
    fn should_fail_if_did_is_not_in_did_doc() {
        let did_document = r#"{
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
          ],
          "id": "did:example:123",
          "verificationMethod": [
            {
              "id": "did:example:123#key-0",
              "type": "JsonWebKey2020",
              "controller": "did:example:123",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "abc"
              }
            }
          ]
        }"#;

        let did_document: Document =
            serde_json::from_str(did_document).expect("Unable to deserialize did doc");

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::None,
            additional_header: Some(ProofJwtAdditionalHeader::KeyId(
                "did:example:123#key-100".to_owned(),
            )),
        };

        let res = jwt_header.extract_key_and_alg(Some(&did_document));

        assert_eq!(
            res,
            Err(JwtError::UnableToResolveDidInDidDocument {
                did: "did:example:123#key-100".to_owned(),
                message: "Resource not found".to_owned()
            })
        );
    }

    #[test]
    fn should_error_if_did_is_supplied_without_did_doc() {
        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::None,
            additional_header: Some(ProofJwtAdditionalHeader::KeyId(
                "did:example/key1".to_owned(),
            )),
        };

        let res = jwt_header.extract_key_and_alg(None);

        assert_eq!(res, Err(JwtError::NoDidDocumentProvidedForKidAsDid));
    }

    #[test]
    fn should_correctly_extract_public_key_ed25519_as_jwk() {
        let public_key_bytes = vec![0, 1, 2, 3];
        let public_key = base64url::encode(&public_key_bytes);
        let jwk = r#"{
            "kty": "EC",
            "crv": "ed25519",
            "x": "<KEY>",
            "alg": "EdDSA"
        }"#;
        let jwk = jwk.replace("<KEY>", &public_key);

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::EdDSA,
            additional_header: Some(ProofJwtAdditionalHeader::Jwk(jwk)),
        };

        let (key, alg) = jwt_header
            .extract_key_and_alg(None)
            .expect("Unable to extract key and alg");

        assert_eq!(public_key_bytes, key);
        assert_eq!(alg, ProofJwtAlgorithm::EdDSA);
    }

    #[test]
    fn should_not_extract_ed25519_key_if_x_is_not_defined() {
        let jwk = r#"{
            "kty": "EC",
            "crv": "ed25519",
            "alg": "EdDSA"
        }"#;

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::EdDSA,
            additional_header: Some(ProofJwtAdditionalHeader::Jwk(jwk.to_owned())),
        };

        let res = jwt_header.extract_key_and_alg(None);

        assert_eq!(res, Err(JwtError::EdDSAHasNoXCoordinate));
    }

    #[test]
    fn should_not_extract_es256_key() {
        let jwk = r#"{
            "kty": "EC",
            "crv": "secpk256",
            "alg": "ES256"
        }"#;

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::ES256,
            additional_header: Some(ProofJwtAdditionalHeader::Jwk(jwk.to_owned())),
        };

        let res = jwt_header.extract_key_and_alg(None);

        assert!(matches!(res, Err(JwtError::UnsupportedAlgorithm { .. })));
    }

    #[test]
    fn should_fail_when_unsupported_rsa_algorithm_is_used() {
        let jwk = r#"{
            "kty": "EC",
            "alg": "RS256",
            "e": "a",
            "n": "bc"
        }"#;

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::RS256,
            additional_header: Some(ProofJwtAdditionalHeader::Jwk(jwk.to_owned())),
        };

        let res = jwt_header.extract_key_and_alg(None);

        assert!(matches!(res, Err(JwtError::UnsupportedAlgorithm { .. })));
    }

    #[test]
    fn should_fail_when_unsupported_rsassa_ps_algorithm_is_used() {
        let jwk = r#"{
            "kty": "EC",
            "alg": "PS256",
            "e": "a",
            "n": "bc"
        }"#;

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::PS256,
            additional_header: Some(ProofJwtAdditionalHeader::Jwk(jwk.to_owned())),
        };

        let res = jwt_header.extract_key_and_alg(None);

        assert!(matches!(res, Err(JwtError::UnsupportedAlgorithm { .. })));
    }

    #[test]
    fn should_fail_when_symmetric_is_used() {
        let jwk = r#"{
            "kty": "oct",
            "alg": "HS256",
            "k": "abc"
        }"#;

        let jwt_header = ProofJwtHeader {
            typ: "JWT".to_owned(),
            alg: ProofJwtAlgorithm::HS256,
            additional_header: Some(ProofJwtAdditionalHeader::Jwk(jwk.to_owned())),
        };

        let res = jwt_header.extract_key_and_alg(None);

        assert!(matches!(res, Err(JwtError::UnsupportedAlgorithm { .. })));
    }
}
