use super::credential::CredentialFormatProfile;
use crate::{
    jwt::ProofJwt,
    validate::{Validatable, ValidationError},
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Required `typ` field in the JOSE Header for a proof
pub const OPENID4VCI_PROOF_TYPE: &str = "openid4vci-proof+jwt";

/// Required `proof_type` field in a proof object in the [`CredentialRequest`]
pub const JWT_PROOF_TYPE: &str = "JWT";

/// Struct mapping the `credential_request` as defined in section 7.2 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10.2.3)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialRequest {
    /// Format of the Credential to be issued. This Credential format identifier determines further
    /// parameters required to determine the type and (optionally) the content of the credential to
    /// be issued. Credential Format Profiles consisting of the Credential format specific set of
    /// parameters are defined in Appendix E of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#format_profiles).
    #[serde(flatten)]
    pub format: CredentialFormatProfile,

    /// JSON object containing proof of possession of the key material the issued Credential shall
    /// be bound to. The specification envisions use of different types of proofs for different
    /// cryptographic schemes. The proof object MUST contain a proof_type claim of type JSON string
    /// denoting the concrete proof type. This type determines the further claims in the proof
    /// object and its respective processing rules. Proof types are defined in Section 7.2.1 of the
    /// [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof_types).
    pub proof: Option<CredentialRequestProof>,
}

/// Struct mapping of `proof types` as defined in section 7.2.1 of the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof_types)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialRequestProof {
    /// Type of proof used. MUST be of string `jwt`.
    #[serde(default = "default_proof_type")]
    pub proof_type: String,

    /// objects of this type contain a single jwt element with a JWS
    /// [RFC7515](https://www.rfc-editor.org/rfc/rfc7515.txt) as proof of possession.
    pub jwt: String,
}

/// Default for proof `proof_type` value
fn default_proof_type() -> String {
    JWT_PROOF_TYPE.to_owned()
}

impl Validatable for CredentialRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(proof) = &self.proof {
            proof.validate()?;
        }

        Ok(())
    }
}

impl Validatable for CredentialRequestProof {
    fn validate(&self) -> Result<(), ValidationError> {
        // Check whether the `proof_type` is set to any casing of [`JWT_PROOF_TYPE`]
        if self.proof_type.to_uppercase() != JWT_PROOF_TYPE {
            return Err(ValidationError::Any {
                validation_message: "`proof_type` MUST of of value `JWT`".to_owned(),
            });
        }

        let jwt = ProofJwt::from_str(&self.jwt)?;
        jwt.validate()?;

        Ok(())
    }
}
