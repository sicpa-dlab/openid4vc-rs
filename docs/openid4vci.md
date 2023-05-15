# OpenID4VCI

This documents describes how to use the `openid4vci` and `openid4vci-grpc` crates. The `openid4vci-grpc` crate exposes a grpc interface that can be used to interact with the `openid4vci` crate, and thus both library expose the same functionality and methods. Due to the way protobuf works, the grpc interface is not 100% compatible with the `openid4vci` crate, but the differences are minimal.

## Creating an Issuer

### Prerequisites

- A JSON representation of the credential issuer metadata as defined in the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-issuer-metadata). See [Example Credential Issuer Metadata](#credential-issuer-metadata) below.
  - This should include the did methods, signature suites, and credential types supported by the issuer.
- A JSON representation of the authorization server metadata as defined in [TODO](). See [Example Authorization Server Metadata](#authorization-server-metadata) below.
- An HTTP server that is capable of handling GET and POST requests (see [Endpoints](#endpoints) below for more details).

### Endpoints

The following endpoints must be exposed by the issuer:

- **`GET /.well-known/openid-issuer`** - This should return the JSON representation of the Credential Issuer Metadata and should be publicly accessible.
- **`XXX /**

### Flow 1 - Pre-Authorized Issuance using `openid4vci`

### Pre-Authorized Issuance using `openid4vci`

```ignore
+--------------+   +-----------+                                    +-------------------+
| User         |   |   Wallet  |                                    | Credential Issuer |
+--------------+   +-----------+                                    +-------------------+
        |                |                                                    |
        |                |  (1) User provides information required           |
        |                |      for the issuance of a certain Credential      |
        |-------------------------------------------------------------------->|
        |                |                                                    |
        |                |  (2) Credential Offer (Pre-Authorized Code)        |
        |                |<---------------------------------------------------|
        |                |  (3) Obtains Issuer's Credential Issuer metadata   |
        |                |<-------------------------------------------------->|
        |   interacts    |                                                    |
        |--------------->|                                                    |
        |                |                                                    |
        |                |  (4) Token Request (Pre-Authorized Code, pin)      |
        |                |--------------------------------------------------->|
        |                |      Token Response (access_token)                 |
        |                |<---------------------------------------------------|
        |                |                                                    |
        |                |  (5) Credential Request (access_token, proof(s))   |
        |                |--------------------------------------------------->|
        |                |      Credential Response                           |
        |                |      (credential(s))                               |
        |                |<---------------------------------------------------|
```

_From section 3.5 of the [openid4vci
specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-3.5)_

In order to use this flow, the library has to be called in the following order
(with your business logic in between):

> NOTE: The steps number match the flow number

#### 1. No functionality required

Outside of the scope of this library

#### 2. `CredentialIssuer::create_offer`

When the `Wallet` would like to receive a credential, the `Credential Issuer`
would first have to create an offer. This offer can then be send to an endpoint
provided by the `Wallet` or it can be used as a deeplink for the `Wallet` to
open.

#### 3. No functionality required

Outside of the scope of this library

#### 4. `AccessToken::evaluate_access_token_request`

When the `Wallet` comes back with an access token request, we have to evaluate
it's validity.

#### 4.1. `AccessToken::create_success_response` or `AccessToken::create_error_response`

If the business logic or this library itself agrees with the access token
request, a success response can be created which can be send to the `Wallet`.
If any error occurred, an error response can be created with the correct
information. It is completely up to the user of this library to determine this.

#### 5. `CredentialIssuer::pre_evaluate_credential_request`

When the `wallet` creates a credential request, we first must pre-evaluate the
request. This is done, because this library does not implement a DID resolver
and the credential request might contain a DID. The pre-evaluate function
checks whether the `wallet` provided a did, and if so returns the did that must
be resolved.

#### 5.1. `CredentialIssuer::evaluate_credential_request`

This function evaluates the validity of the credential request from the
`Wallet` as the `Credential Issuer`. If the `kid` inside the `JWT` is a DID, a
DID Document must be supplied. This function returns some fields for any KMS to
do a proof of possession check, the DID of where to issue the credential to and
the credential itself without the filled-in data.

#### 5.2. `CredentialIssuer::create_success_response` or `CredentialIssuer::create_error_response`

If some business logic, or this library, determines that something went wrong,
e.g. the proof of possession check did not work, the jwt is not valid anymore,
etc. the user of this library can create an error response and send this
directly to the `Wallet`. If everything is correct, the `Credential Issuer` can
send a success reponse to `Wallet`.

## Examples

### Credential Issuer Metadata

This is an example of the credential issuer metadata. In this cas the following is true about the issuer:

- Only supports the `ldp_vc` format (JSON-LD credentials with data integrity proofs)
- Only supports `Ed25519Signature2018` as a cryptographic suite
- Only supports `did:web` as a cryptographic binding method
- Supports one credential, the `OpenBadgeCredential` (can support more by sending an inline credential object in a credential offer)
- Issuer is exposed at `https://openid4vci-issuer.example.com`

```json
{
  "credential_issuer": "https://openid4vci-issuer.example.com",
  "credential_endpoint": "https://openid4vci-issuer.example.com/issueCredential",
  "credentials_supported": [
    {
      "format": "ldp_vc",
      "id": "OpenBadgeCredential",
      "cryptographic_binding_methods_supported": ["did:web"],
      "cryptographic_suites_supported": ["Ed25519Signature2018"],
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://mattr.global/contexts/vc-extensions/v1",
        "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
        "https://w3c-ccg.github.io/vc-status-rl-2020/contexts/vc-revocation-list-2020/v1.jsonld"
      ],
      "types": [
        "VerifiableCredential",
        "VerifiableCredentialExtension",
        "OpenBadgeCredential"
      ]
    }
  ]
}
```

### Authorization Server Metadata

This is an example of the authorization server metadata. In this case the following is true about the authorization server:

- TODO

```json
{
  "todo": "todo"
}
```
