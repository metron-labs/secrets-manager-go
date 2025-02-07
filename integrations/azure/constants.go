package keyvault_azure

const (
	BLOB_HEADER                                     = "\xff\xff" // Encrypted BLOB Header: U+FFFF is a non character
	LATIN1_ENCODING                                 = "latin1"
	UTF_8_ENCODING                                  = "utf-8"
	AES_256_GCM                                     = "aes-256-gcm"
	RSA_OEAP                                        = "RSA-OAEP"
	DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE = "KSM_AZ_KEY_ID"
	MD5_HASH                                        = "md5"
	HEX_DIGEST                                      = "hex"
	DEFAULT_JSON_INDENT                             = 4
)
