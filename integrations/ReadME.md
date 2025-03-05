# GCP Cloud Key Management

Protect Secrets Manager connection details with GCP Cloud Key Management 

Keeper Secrets Manager integrates with GCP Cloud Key Management in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

# Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP Cloud Key Management 
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Go-Lang SDK functionality

# Prerequisites
* Supports the Go-Lang Secrets Manager SDK.
* Requires GCP Cloud packages: kms/apiv1, kmspb, core, kms
* Works with just AES/RSA key types with `Encrypt` and `Decrypt` permissions.

# Setup
1. Install Secret-Manager-Go Package

The Secrets Manager GCP package are located in the Keeper Secrets Manager storage package which can be installed using 

> `go get github.com/keeper-security/secrets-manager-go/integrations/gcp`
Configure GCP Connection

configuration variables can be provided as 

```
import (
	"github.com/keeper-security/secrets-manager-go/core"
	gcpkv "github.com/keeper-security/secrets-manager-go/gcpkv"
)

cfg := gcpkv.NewGCPKeyVaultStorage(<config-file-path-with-its-name>, <key-arn>, &gcpkv.GCPConfig{
		CredentialsFileLocation: "<Location of credential file ending with .json>",
		KeyResourceName:         "<Key Resource Name>",
})

client_options := &core.ClientOptions{
	Token:  "[One Time Access Token]",
	Config: cfg,
}

fmt.Printf("Client ID Value: %s", cfg.Get(core.KEY_CLIENT_ID))

secrets_manager := core.NewSecretsManager(&client_options)
secrets, err := secrets_manager.GetSecrets([]string{})
if err != nil {
	// do something
} 

for _, record := range secrets {
	fmt.Printf("Records: %v\n", record)
}

isChanged, err := cfg.ChangeKey(&gcpkv.GCPConfig{
		KeyResourceName: "<Key Resource Name>",
})
if err != nil {
	// do something
} 

fmt.Printf("Key changed: %v\n", isChanged)
plainText, err := cfg.DecryptConfig(true)
if err != nil {
	// do something
}

fmt.Printf("Decrypted data: %v\n", plainText)

```
The storage will require an GCP credential file ended with .json, as well as Secrets Manager configuration which will be encrypted by GCP Cloud Key Management.

Provide `CredentialsFileLocation` and `KeyResourceName` variables.

KeyResourceName must be like this `projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME/cryptoKeyVersions/KEY_VERSION`

For more information about URL see the GCP Cloud Key Management Documentation 
https://cloud.google.com/kms/docs/getting-resource-ids

You're ready to use the KSM integration 👍

Using the GCP Cloud Key Management Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].
