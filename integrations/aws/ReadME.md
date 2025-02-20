**AWS Key Management**

Protect Secrets Manager connection details with AWS Key Management 

Keeper Secrets Manager integrates with  AWS Key Management in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.
Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with AWS Key Management 
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Go-Lang SDK functionality

Prerequisites

* Supports the Go-Lang Secrets Manager SDK.
* Requires AWS packages: aws, config, credentials, kms, kms-types
* Works with just AES/RSA key types with `Encrypt` and `Decrypt` permissions.

Setup
1. Install Secret-Manager-Go Package

The Secrets Manager AWS package are located in the Keeper Secrets Manager storage package which can be installed using 

> `go get github.com/keeper-security/secrets-manager-go/core`
Configure AWS Connection

configuration variables can be provided as 

```
    import awskv "github.com/keeper-security/secrets-manager-go/awskv"
    
    clientOptions := &ksm.ClientOptions{
		Token:  "[One Time Access Token]",
		Config: awskv.NewAWSKeyValueStorage(<config-file-path-with-its-name>, <key-arn>, &awskv.AWSConfig{
			ClientID:     "<Some Client ID>",
			ClientSecret: "<Some Client Secret>",
			Region:       "<Cloud Region>",
		}),
	}
```
The storage will require an AWS credentials if not present it will fetch from environment, as well Secrets Manager configuration which will be encrypted by AWS Key Management.

Provide `ClientID` , `ClientSecret` and `Region` variables.

KeyURL must be like this `arn:<partition>:kms:<region>:<account-id>:key/<key-id>`

For more information about URL see the AWS Key Management Documentation 
https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html

You're ready to use the KSM integration 👍

Using the AWS Key Management Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].