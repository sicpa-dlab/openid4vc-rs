# OpenID for Verifiable Credentials

> **Warning**
> NOTE: This library will not be maintained anymore, but it may be used as a reference implementation for openid4vci draft 11.

This repository contains a Rust implementation of the [OpenID for Verifiable Credentials](https://openid.net/openid4vc/) specifications. The specifications that are currently implemented, or in progress of being implemented are:

-   An implementation of the [openid4vci
    specification 1.0 - Draft
    11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html).

## Goals

The implementation in this repository has a few goals and design choices that are important to understand, before using it in your own project. Specifically the libraries:

-   are designed to be used as a building block for a larger system. It is not designed to be used as a standalone application, and is missing a lot of functionality that is required for a top-level application.
-   help in creating and evaluating/verifying the request and response objects from the various openid4vc specifications. However, it does not expose any of the needed HTTP(s) endpoints that are required by the specifications. This is left to the user of the libraries to implement.
-   are written to be un-opinionated about the system they will be used in. This means that the libraries do not enforce any specific cryptographic algorithms, or any specific storage mechanism. Things that are left to the user of these libraries to implement:
    -   Signing and verification of JWTs, Verifiable Credentials and other cryptographic operations.
    -   Resolving of DIDs to DID Documents
    -   Storage of the various objects that are created and evaluated by the libraries.

If you're looking for a fully working implementation of the openid4vc specifications, this repository is probably not what you're looking for. However, if you're trying to integrate the openid4vc specifications into a larger system that has things like resolving DID Documents, signing and verification, storage of objects, already figured out, this repository might be a good fit in helping you make sure you're aligning with the specifications. Method such as the `evaluate_credential_request` from the `openid4vci` crate help you understand whether a credential request is valid, which DIDs you need to resolve, and which bytes you need to cryptographically verify.

## Structure

Since this is a monorepo structure, it will contain multiple packages. Each of
these packages have their uses which are described below.

### `openid4vci`

This crate implements the [openid4vci
specification 1.0 - Draft 11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html)
as a consumable library.

Currently, this crate supports:

-   Creating pre-authorized credential offers
-   Evaluating pre-authorized access token requests
-   Evaluating credential requests with a did-bound proof of possession
-   Creating credential and access token success and error responses

## Flow

### Pre-Authorized Issuance using `openid4vci`

```ignore
+--------------+   +-----------+                                    +-------------------+
| User         |   |   Wallet  |                                    | Credential Issuer |
+--------------+   +-----------+                                    +-------------------+
        |                |                                                    |
        |                |  (1) User provides  information required           |
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

## License

The license used for this project is Apache 2.0 and can be found in the
[license file](./LICENSE).
