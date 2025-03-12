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

> `go get github.com/keeper-security/secrets-manager-go/integrations/oracle`
2. Configure oracle Connection
```
package main

import (
	"encoding/json"
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	oraclekv "github.com/keeper-security/secrets-manager-go/integrations/oracle"
)

func main() {
    // Set true, if you want to decrypt the config
	decryptConfig := false
    // Set true if you want to change the key for encryption/decryption
	changeKey := false

	ksmConfigFile := ""
	oneTimeToken := "One Time Token"
	keyConfig := &oraclekv.KeyConfig{
		KeyID:        "",
		KeyVersionID: "",
	}

	oracleConfig := &oraclekv.OracleConfig{
		VaultManagementEndpoint: "",
		VaultCryptoEndpoint:     "",
		Profile:                 "",
		ProfileConfigPath:       "",
	}
	cfg := oraclekv.NewOracleKeyVaultStorage(ksmConfigFile, keyConfig, oracleConfig)
	secrets_manager := core.NewSecretsManager(
		&core.ClientOptions{
			Token:  oneTimeToken,
			Config: cfg,
		},
	)

    // Fetching secrets from Keeper security vault
	secrets, err := secrets_manager.GetSecrets([]string{})
	if err != nil {
		// do something
		fmt.Printf("Error: %s\n", err)
	} else {
		for _, secret := range secrets {
			fmt.Printf("Recieved secret: %s\n", secret.Title())
		}
	}

    // Changed the key for encryption/decryption
	if changeKey {
		updatedKeyConfig := &oraclekv.KeyConfig{}
        // Pass updatedOracleConfig as nil, if you don't want to change oracle config. 
		isChanged, err := cfg.ChangeKey(updatedKeyConfig, nil)
		if err != nil {
			// do something
			fmt.Printf("Key is not changed, got error: %s\n", err)
		} else {
			fmt.Printf("Key changed: %t\n", isChanged)
		}

        // If you want to change the config along with the update key.
		updatedOracleConfig := &oraclekv.OracleConfig{}
		isChanged, err = cfg.ChangeKey(updatedKeyConfig, updatedOracleConfig)
		if err != nil {
			// do something
			fmt.Printf("Key is not changed, got error: %s\n", err)
		} else {
			fmt.Printf("Key changed: %t\n", isChanged)
		}
	}

    // Decrypt the config 
	if decryptConfig {
		config := make(map[core.ConfigKey]interface{})
        // Pass true if you want to save decrypted config in ksm config file, else pass false
		decryptedConfig, err := cfg.DecryptConfig(false)
		if err != nil {
			// do something
			fmt.Printf("Error: %s\n", err)
		} else {
			if err := json.Unmarshal([]byte(decryptedConfig), &config); err != nil {
				// do something
				fmt.Printf("Error while Unmarshiling: %s\n", err)
			} else {
				fmt.Printf("Decrypted config: %s\n", config[core.KEY_CLIENT_ID])
			}
		}

	}
}
```
# Configuration 
The NewOracleKeyVaultStorage requires the following parameters to encrypt the KSM configuration using Oracle Vault:
* `ksmConfigFileName` : The file name of KSM configuration.
* `keyConfig` : Provide oracle key credentials `KeyID` and `KeyVersionID`.
* `oracleConfig` : Provide oracle credentials `VaultManagementEndpoint`, `VaultCryptoEndpoint`.
* By default, the oci-keymanagement library will use the **default OCI configuration file** (`~/.oci/config`).
* If you want to change the **default OCI configuration file** to **custom OCI configuration** then, update oracle credentials and add `Profile` and `ProfileConfigPath` to `oracleConfig`

Reference for OCI configuration [https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#Example_Configuration] 

See the (OCI documentation)[https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm] for more details.


You're ready to use the KSM integration 👍

Using the Oracle Vault Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].