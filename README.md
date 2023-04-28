# OpenID4VC

This repository contains:

-   An implementation of the [openid4vci
    specification 1.0 - Draft
    11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html).
-   An implementation of the [siopv2 specification 1.0 - Draft
    12](https://openid.net/specs/openid-connect-self-issued-v2-1_0-12.html).

> NOTE: The pre-authorized code flow is only supported right now.

## Structure

Since this is a monorepo structure, it will contain multiple packages. Each of
these packages have their uses which are described below.

### `openid4vci`

This package will be an implementation of the [openid4vci
specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html)
as a consumable library. This means that the library will not contain any
endpoints as required by the specification. The functionality can be seen by
the two following points:

1. Create objects for the openid4vci specification (such as the credential
   offer)
1. Evaluate incoming requests
1. Generate error and success responses

### `openid4vci-grpc`

This package will expose the functionality of the library over gRPC. These
interfaces are not compatible with the endpoints as defined in the openid4vci
specification as those have to be expose over HTTP. This package can be used in
a micro-service architecture where the communication between the different
services is done with gRPC.

#### Running an example with Docker

A small example has been created for the
[client](./crates/openid4vci-grpc/src/client.rs) and
[server](./crates/openid4vci-grpc/src/server.rs). For the server there is a
Dockerfile created. This can be built with the following command (from the root
of the project):

```sh
docker build -f docker/server.Dockerfile -t server .
```

To run the image:

```sh
docker run -p50051:50051 server
```

And lastly, to send a message using the
[client](./crates/openid4vci-grpc/src/client):

```sh
cargo run --bin client
```

### `siopv2`

### `siopv2-grpc`

## Flow

### Pre Authorized Code Flow (as an issuer)

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
