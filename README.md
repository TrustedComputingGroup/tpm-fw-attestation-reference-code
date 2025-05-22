# Reference code for EK-Based Key Attestation with TPM Firmware Version

## Introduction

This reference code demonstrates how to perform the Import+Certify workflow
described in "EK-Based Key Attestation with TPM Firmware Version".

## How to Run

### Go

#### Unit Test

The unit test uses the built-in TPM simulator provided by Go-TPM.

From the `go` directory,

```sh
go test -v ./pkg/e2etest
```

#### TCP Tester

This standalone tool requires you to be running the TCP simulator already.

From the `go` directory,

```sh
go run ./cmd/tester --tpm_port 2321 --platform_port 2322
```

You may need to replace the TPM and platform ports with the actual ports of the
running TCP simulator on your system.
