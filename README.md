# OpenID for Verifiable Credentials

This repository contains a Rust implementation and gRPC bindings of the [OpenID for Verifiable Credentials](https://openid.net/openid4vc/) specifications. The specifications that are currently implemented, or in progress of being implemented are:

- An implementation of the [openid4vci
  specification 1.0 - Draft
  11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html).
- An implementation of the [siopv2 specification 1.0 - Draft
  12](https://openid.net/specs/openid-connect-self-issued-v2-1_0-12.html).

> **Warning**
> This repository is in active development, and only a part of the possible OpenID for Verifiable Credentials specifications and flows has been implemented.

For documentation on how to use this library, look at the [Documentation](./docs) folder.

## Goals

The implementation in this repository has a few goals and design choices that are important to understand, before using it in your own project. Specifically the libraries:

- are designed to be used as a building block for a larger system. It is not designed to be used as a standalone application, and is missing a lot of functionality that is required for a top-level application.
- help in creating and evaluating/verifying the request and response objects from the various openid4vc specifications. However, it does not expose any of the needed HTTP(s) endpoints that are required by the specifications. This is left to the user of the libraries to implement.
- are written to be un-opinionated about the system they will be used in. This means that the libraries do not enforce any specific cryptographic algorithms, or any specific storage mechanism. Things that are left to the user of these libraries to implement:
  - Signing and verification of JWTs, Verifiable Credentials and other cryptographic operations.
  - Resolving of DIDs to DID Documents
  - Storage of the various objects that are created and evaluated by the libraries.

If you're looking for a fully working implementation of the openid4vc specifications, this repository is probably not what you're looking for. However, if you're trying to integrate the openid4vc specifications into a larger system that has things like resolving DID Documents, signing and verification, storage of objects, already figured out, this repository might be a good fit in helping you make sure you're aligning with the specifications. Method such as the `evaluate_credential_request` from the `openid4vci` crate help you understand whether a credential request is valid, which DIDs you need to resolve, and which bytes you need to cryptographically verify.

## Structure

Since this is a monorepo structure, it will contain multiple packages. Each of
these packages have their uses which are described below.

### `openid4vci`

This crate implements the [openid4vci
specification 1.0 - Draft 11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html)
as a consumable library.

Currently, this crate supports:

- Creating pre-authorized credential offers
- Evaluating pre-authorized access token requests
- Evaluating credential requests with a did-bound proof of possession
- Creating credential and access token success and error responses

### `openid4vci-grpc`

This package exposes the functionality of the `openid4vci` crate over gRPC. These
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

This package is an implementation of the [siopv2 specification 1.0 - Draft 12](https://openid.net/specs/openid-connect-self-issued-v2-1_0-12.html).
as a consumable library.

Currently, this crate supports:

- No flows supported yet

In the future a separate `openid4vp` crate will be added that can work in combination with the `siopv2` crate.

### `siopv2-grpc`

This package will expose the functionality of the `siopv2` crate over gRPC. These
interfaces are not compatible with the endpoints as defined in the siopv2
specification as those have to be expose over HTTP. This package can be used in
a micro-service architecture where the communication between the different
services is done with gRPC.

## License

The license used for this project is Apache 2.0 and can be found in the
[license file](./LICENSE).
