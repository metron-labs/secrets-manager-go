package azurekv

import (
	"azurekv/logger"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

const (
	BLOB_HEADER = "\xff\xff"
)

func encryptBuffer(azureKvStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, message string) ([]byte, error) {
	log := logger.NewDefaultLogger()
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

	ciphertext := gcm.Seal(nil, nonce, []byte(message), nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-gcm.Overhead()]
	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     key,
	}

	wrappedKeyResp, err := azureKvStorageCryptoClient.WrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		log.Error("Failed to wrap key: %v", err)
		return nil, fmt.Errorf("azure crypto client failed to wrap key: %w", err)
	}

	wrappedKey := wrappedKeyResp.Result
	blob, err := buildBlob(wrappedKey, nonce, tag, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to build blob: %w", err)
	}

	return blob, nil

}

func decryptBuffer(azureKeyValueStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, ciphertext []byte) (string, error) {
	log := logger.NewDefaultLogger()
	if !bytes.Equal(ciphertext[:len(BLOB_HEADER)], []byte(BLOB_HEADER)) {
		return "", fmt.Errorf("invalid header")
	}

	pos := len(BLOB_HEADER)
	var encryptedKey, nonce, tag, encryptedText []byte
	for i := 0; i < 4; i++ {
		if pos+2 > len(ciphertext) {
			return "", fmt.Errorf("missing part length")
		}
		partLength := binary.BigEndian.Uint16(ciphertext[pos : pos+2])
		pos += 2
		if pos+int(partLength) > len(ciphertext) {
			return "", fmt.Errorf("invalid ciphertext structure: part length mismatch")
		}
		part := ciphertext[pos : pos+int(partLength)]
		pos += int(partLength)

		switch i {
		case 0:
			encryptedKey = part
		case 1:
			nonce = part
		case 2:
			tag = part
		case 3:
			encryptedText = part
		}
	}

	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     encryptedKey,
	}

	key, err := azureKeyValueStorageCryptoClient.UnwrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		log.Error("Failed to unwrap key: %v", err)
		return "", fmt.Errorf("azure crypto client failed to unwrap key: %w", err)
	}

	block, err := aes.NewCipher(key.Result)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(tag) != aesGCM.Overhead() {
		return "", fmt.Errorf("invalid tag length")
	}

	decrypted, err := aesGCM.Open(nil, nonce, append(encryptedText, tag...), nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(decrypted), nil
}

func buildBlob(wrappedKey, nonce, tag, ciphertext []byte) ([]byte, error) {
	var buffers bytes.Buffer
	parts := [][]byte{wrappedKey, nonce, tag, ciphertext}
	header := []byte(BLOB_HEADER)
	buffers.Write(header)
	for _, part := range parts {
		partBuffer := part
		lengthBuffer := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuffer, uint16(len(partBuffer)))
		buffers.Write(lengthBuffer)
		buffers.Write(partBuffer)
	}
	return buffers.Bytes(), nil
}

func extractKeyDetails(keyURL string) (string, string, string, error) {
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
