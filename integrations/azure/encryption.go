package azure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func encryptBuffer(azureKvStorageCryptoClient *azkeys.Client, message string) ([]byte, error) {
	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Create AES-GCM cipher instance
	nonce := make([]byte, 16) // AES-GCM requires a 16-byte nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(message), nil)
	tag := aesGCM.Overhead()

	// Wrap the AES key using Azure Key Vault
	wrappedKey, err := azureKvStorageCryptoClient.WrapKey(RSA_OEAP, key)
	if err != nil {
		return nil, fmt.Errorf("Azure crypto client failed to wrap key: %w", err)
	}

	// Build the blob
	var buffers [][]byte
	buffers = append(buffers, []byte(BLOB_HEADER))
	parts := [][]byte{wrappedKey, nonce, tag, ciphertext}
	for _, part := range parts {
		lengthBuffer := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuffer, uint16(len(part)))
		buffers = append(buffers, lengthBuffer, part)
	}

	return bytes.Join(buffers, nil), nil
}

func decryptBuffer(azureKeyValueStorageCryptoClient CryptographyClient, ciphertext []byte) (string, error) {
	// Validate BLOB_HEADER
	if !bytes.Equal(ciphertext[:2], []byte(BLOB_HEADER)) {
		return "", errors.New("invalid header")
	}

	pos := 2
	var encryptedKey, nonce, tag, encryptedText []byte

	// Parse the ciphertext into its components
	for i := 0; i < 4; i++ {
		if pos+2 > len(ciphertext) {
			return "", errors.New("invalid ciphertext structure: insufficient length")
		}
		partLength := binary.BigEndian.Uint16(ciphertext[pos : pos+2])
		pos += 2
		if pos+int(partLength) > len(ciphertext) {
			return "", errors.New("invalid ciphertext structure: part length mismatch")
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

	// Unwrap the AES key using Azure Key Vault
	key, err := azureKeyValueStorageCryptoClient.UnwrapKey(RSA_OEAP, encryptedKey)
	if err != nil {
		return "", fmt.Errorf("Azure crypto client failed to unwrap key: %w", err)
	}

	// Decrypt the message using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(tag) != aesGCM.Overhead() {
		return "", errors.New("invalid tag length")
	}

	decrypted, err := aesGCM.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(decrypted), nil
}
