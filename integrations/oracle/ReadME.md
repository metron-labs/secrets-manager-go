# Oracle Key Management
Keeper Secrets Manager integrates with **Oracle Key Management Service (OCI KMS)** to provide protection for Keeper Secrets Manager configuration files. With this integration, you can secure connection details on your machine while leveraging Keeper's **zero-knowledge encryption** for all your secret credentials.

## Features
* Encrypt and decrypt your Keeper Secrets Manager configuration files using **OCI KMS**.
* Protect against unauthorized access to your **Secrets Manager connections**.
* Requires only minor code modifications for immediate protection. Works with all Keeper Secrets Manager **GoLang SDK** functionality.

## Prerequisites
* Supports the GoLang Secrets Manager SDK.
* Requires the oci-keymanagement package from OCI SDK.
* OCI KMS Key needs `ENCRYPT` and `DECRYPT` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager oracle KSM module can be installed using npm

> `go get github.com/keeper-security/secrets-manager-go/core`
2. Configure oracle Connection

By default, the oci-keymanagement library will use the **default OCI configuration file** (`~/.oci/config`).

See the (OCI documentation)[https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm] for more details.

1. Add oracle KMS Storage to Your Code

Now that the oracle connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `OciKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an `Config file location`, `configuration profile`(if there are multiple profile configurations) and the OCI `KMS endpoint` as well as the name of the Secrets Manager configuration file which will be encrypted by Oracle KMS.