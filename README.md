# OpenID4VC

This repository contains the code for an implementation of the [openid4vci
specification
1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
and the [openid4vp specification
1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## Structure

Since this is a monorepo structure, it will contain multiple packages. Each of
these packages have their uses which are described below.

### `openid4vci`

This package will be an implementation of the openid4vci specification as a
consumable library. This means that the library will not contain any endpoints
as required by the specification. The functionality can be seen by the two
following points:

1. Evaluate incoming requests
2. Generate error and success responses

### `openid4vci-grpc`

This package will expose the functionality of the library over gRPC. These
interfaces are not compatible with the endpoints as defined in the openid4vci
specification as those have to be expose over HTTP. This package can be used
in a micro-service architecture where the communication between the different
services is done with gRPC.

## License

The license used for this project is Apache 2.0 and can be found in the
[license file](./LICENSE).
