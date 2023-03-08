use std::collections::HashMap;

/// A struct mapping a `credential` type as defined in Appendix E in the [openid4vci
/// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
pub struct Credential {
    /// Format Claim determining the format of the credential to be requested and further
    /// parameters characterising the type of the credential to be requested as defined in Appendix
    /// E of the [openid4vci
    /// specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
    pub format: CredentialFormat,
}

/// Enum for the available credential formats
pub enum CredentialFormat {
    /// `jwt_vc_json`
    ///
    /// VC signed as a JWT, not using JSON-LD
    JwtVcJson {
        /// JSON array designating the types a certain credential type supports according to
        /// [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.3.
        ///
        /// TODO: needs to be filled in
        types: Vec<String>,

        /// A JSON object containing a list of key value pairs, where the key identifies the claim
        /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
        /// full (potentially deeply nested) structure of the verifiable credential to be issued.
        credential_subject: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        order: Option<Vec<String>>,
    },

    /// `jwt_vc_json-ld`
    ///
    /// VC signed as a JWT, using JSON-LD
    JwtVcJsonLd {
        /// JSON array designating the types a certain credential type supports according to
        /// [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.3.
        types: Vec<String>,

        /// A JSON object containing a list of key value pairs, where the key identifies the claim
        /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
        /// full (potentially deeply nested) structure of the verifiable credential to be issued.
        credential_subject: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        order: Option<Vec<String>>,
    },

    /// `ldp_vc`
    ///
    /// VC secured using Data Integrity, using JSON-LD, with proof suite requiring Linked Data
    /// canonicalization
    LdpVc {
        /// JSON array as defined in [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.1.
        context: Vec<String>,

        /// JSON array designating the types a certain credential type supports according to
        /// [VC_DATA](https://www.w3.org/TR/vc-data-model/), Section 4.3.
        types: Vec<String>,

        /// A JSON object containing a list of key value pairs, where the key identifies the claim
        /// offered in the Credential. The value MAY be a dictionary, which allows to represent the
        /// full (potentially deeply nested) structure of the verifiable credential to be issued.
        /// The value is a JSON object detailing the specifics about the support for the claim
        credential_subject: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        order: Option<Vec<String>>
    },

    /// `mso_mdoc`
    ///
    /// Credential Format Profile for credentials complying with
    /// [ISO.18013-5](https://www.iso.org/standard/69084.html)
    MsoMdoc {
        /// JSON string identifying the credential type.
        doctype: String,

        /// A JSON object containing a list of key value pairs, where the key is a certain
        /// namespace as defined in [ISO.18013-5](https://www.iso.org/standard/69084.html) (or any
        /// profile of it), and the value is a JSON object. This object also contains a list of key
        /// value pairs, where the key is a claim that is defined in the respective namespace and
        /// is offered in the Credential. 
        claims: Option<HashMap<String, CredentialSubject>>,

        /// An array of claims.display.name values that lists them in the order they should be
        /// displayed by the Wallet.
        order: Option<Vec<String>>

    },
}

/// A JSON object containing a list of key value pairs, where the key identifies the claim
/// offered in the Credential. The value MAY be a dictionary, which allows to represent the
/// full (potentially deeply nested) structure of the verifiable credential to be issued.
pub struct CredentialSubject {
    /// Boolean which when set to true indicates the claim MUST be present in the issued Credential. If
    /// the mandatory property is omitted its default should be assumed to be false.
    pub mandatory: Option<bool>,

    /// String value determining type of value of the claim. A non-exhaustive list of valid values
    /// defined by this specification are string, number, and image media types such as image/jpeg
    /// as defined in [IANA media type registry for
    /// images](https://www.iana.org/assignments/media-types/media-types.xhtml#image).
    pub value_type: Option<String>,

    /// An array of objects, where each object contains display properties of a certain claim in
    /// the Credential for a certain language.
    pub display: Option<CredentialSubjectDisplay>,
}

/// A Struct containing the fields for the credentialSubjects dispay field.
pub struct CredentialSubjectDisplay {
    /// String value of a display name for the claim.
    pub name: Option<String>,

    /// String value that identifies language of this object represented as language tag values
    /// defined in BCP47 [RFC5646](https://www.rfc-editor.org/rfc/rfc5646.txt). There MUST be only
    /// one object with the same language identifier.
    pub locale: Option<String>,
}
