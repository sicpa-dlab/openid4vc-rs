# OpenID4VC

This repository contains the code for an implementation of the [openid4vci specification 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
and the [openid4vp specification 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## Structure

Since this is a monorepo structure, it will contain multiple packages. Each of
these packages have their uses which are described below.

### `openid4vci`

This package will be an implementation of the [openid4vci specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
as a consumable library. This means that the library will not contain any
endpoints as required by the specification. The functionality can be seen by
the two following points:

1. Create objects for the openid4vci specification (such as the credential offer)
1. Evaluate incoming requests
1. Generate error and success responses

### `openid4vci-grpc`

This package will expose the functionality of the library over gRPC. These
interfaces are not compatible with the endpoints as defined in the openid4vci
specification as those have to be expose over HTTP. This package can be used
in a micro-service architecture where the communication between the different
services is done with gRPC.

#### Running an example with Docker

A small example has been created for the [client](./crates/openid4vci-grpc/src/client.rs) and [server](./crates/openid4vci-grpc/src/server.rs). For the server there is a Dockerfile created. This can be built with the following command (from the root of the project):

```sh
docker build -f docker/server.Dockerfile -t server .
```

To run the image:

```sh
docker run -p50051:50051 server
```

And lastly, to send a message using the [client](./crates/openid4vci-grpc/src/client):

```sh
cargo run --bin client
```

## License

The license used for this project is Apache 2.0 and can be found in the
[license file](./LICENSE).
