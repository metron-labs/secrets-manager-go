package keyvault_azure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"golang.org/x/text/encoding/charmap"
)

func encryptBuffer(azureKvStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, message string) ([]byte, error) {

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

	// Wrap the AES key using Azure Key Vault
	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     key,
	}

	wrappedKeyResp, err := azureKvStorageCryptoClient.WrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		return nil, fmt.Errorf("azure crypto client failed to wrap key: %w", err)
	}

	wrappedKey := wrappedKeyResp.Result
	blob, err := BuildBlob(wrappedKey, nonce, tag, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to build blob: %w", err)
	}

	return blob, nil

}

func decryptBuffer(azureKeyValueStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, ciphertext []byte) (string, error) {
	if !bytes.Equal(ciphertext[:len(BLOB_HEADER)], []byte(BLOB_HEADER)) {
		return "", errors.New("invalid header")
	}

	pos := len(BLOB_HEADER)
	var encryptedKey, nonce, tag, encryptedText []byte
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
	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     encryptedKey,
	}

	key, err := azureKeyValueStorageCryptoClient.UnwrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		return "", fmt.Errorf("azure crypto client failed to unwrap key: %w", err)
	}

	// Decrypt the message using AES-GCM
	block, err := aes.NewCipher(key.Result)
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

	decrypted, err := aesGCM.Open(nil, nonce, append(encryptedText, tag...), nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(decrypted), nil
}

func BuildBlob(wrappedKey, nonce, tag, ciphertext []byte) ([]byte, error) {
	parts := [][]byte{wrappedKey, nonce, tag, ciphertext}

	var buffers bytes.Buffer

	// Write the header
	encoder := charmap.ISO8859_1.NewEncoder()
	header, err := encoder.String(BLOB_HEADER)
	if err != nil {
		return nil, err
	}
	buffers.WriteString(header)

	for _, part := range parts {
		partBuffer := part

		// Write the length of the part
		lengthBuffer := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuffer, uint16(len(partBuffer)))
		buffers.Write(lengthBuffer)

		// Write the part itself
		buffers.Write(partBuffer)
	}

	return buffers.Bytes(), nil
}
