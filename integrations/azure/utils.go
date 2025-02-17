package azurekv

import (
	"azurekv/logger"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

const (
	BLOB_HEADER = "\xff\xff"
	KEY_SIZE    = 256
	NONCE_SIZE  = 12
)

func encryptBuffer(azureKvStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, message []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, message, nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-gcm.Overhead()]
	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     key,
	}

	wrappedKeyResp, err := azureKvStorageCryptoClient.WrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		logger.Errorf("Failed to wrap key: %v", err)
		return nil, fmt.Errorf("azure crypto client failed to wrap key: %w", err)
	}

	wrappedKey := wrappedKeyResp.Result
	var blob []byte
	blob = append(blob, []byte(BLOB_HEADER)...)
	blob = append(blob, wrappedKey...)
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ciphertext...)

	return blob, nil

}

func decryptBuffer(azureKeyValueStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, cipherText []byte) ([]byte, error) {
	if len(cipherText) < len(BLOB_HEADER)+KEY_SIZE {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	if !bytes.HasPrefix(cipherText, []byte(BLOB_HEADER)) {
		return nil, fmt.Errorf("invalid BLOB_HEADER")
	}

	cipherText = cipherText[len(BLOB_HEADER):]
	encryptedKey := cipherText[:KEY_SIZE]

	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     encryptedKey,
	}

	decryptedKey, err := azureKeyValueStorageCryptoClient.UnwrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		logger.Errorf("Failed to unwrap key: %v", err)
		return nil, fmt.Errorf("azure crypto client failed to unwrap key: %w", err)
	}

	block, err := aes.NewCipher(decryptedKey.Result)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherText = cipherText[KEY_SIZE:]
	nonce, tag, ciphertext := cipherText[:NONCE_SIZE], cipherText[NONCE_SIZE:NONCE_SIZE+aesGCM.Overhead()], cipherText[NONCE_SIZE+aesGCM.Overhead():]

	ciphertext = append(ciphertext, tag...)
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func fetchKeyDetails(keyURL string) (string, string, string, error) {
	if keyURL == "" {
		return "", "", "", fmt.Errorf("key URL is empty")
	}

	parsedURL, err := url.Parse(keyURL)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse key URL: %v", err)
	}
	pathSegments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(pathSegments) < 3 {
		return "", "", "", fmt.Errorf("invalid key URL format")
	}
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	keyName := pathSegments[1]
	keyVersion := pathSegments[2]
	return baseURL, keyName, keyVersion, nil
}
