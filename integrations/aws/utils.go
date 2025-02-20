package awskv

import (
	"awskv/aws/logger"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	BLOB_HEADER = "\xff\xff"
	KEY_SIZE    = 384
	NONCE_SIZE  = 12
)

func encryptSymmetric(client *kms.Client, keyId string, message []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("message is empty")
	}

	cipherText, err := client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:               &keyId,
		Plaintext:           message,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	return cipherText.CiphertextBlob, nil
}

func decryptSymmetric(client *kms.Client, keyId string, cipherText []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	plainText, err := client.Decrypt(context.Background(), &kms.DecryptInput{
		KeyId:          &keyId,
		CiphertextBlob: cipherText,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return plainText.Plaintext, nil
}

func encryptAsymmetric(client *kms.Client, keyId string, message []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, message, nil)
	tag := ciphertext[len(ciphertext)-aesGCM.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()]

	asymmetricKey, err := client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:               &keyId,
		Plaintext:           key,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		logger.Errorf("Failed to encrypt asymmetric key: %v", err)
		return nil, fmt.Errorf("failed to encrypt asymmetric key: %w", err)
	}

	var blob []byte
	blob = append(blob, []byte(BLOB_HEADER)...)
	blob = append(blob, asymmetricKey.CiphertextBlob...)
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ciphertext...)

	return blob, nil
}

func decryptAsymmetric(client *kms.Client, keyId string, cipherText []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	if !bytes.HasPrefix(cipherText, []byte(BLOB_HEADER)) {
		return nil, fmt.Errorf("invalid BLOB_HEADER")
	}

	cipherText = cipherText[len(BLOB_HEADER):]
	key := cipherText[:KEY_SIZE]
	decryptedKey, err := client.Decrypt(context.Background(), &kms.DecryptInput{
		KeyId:               &keyId,
		CiphertextBlob:      key,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		logger.Errorf("Failed to decrypt asymmetric key: %v", err)
		return nil, fmt.Errorf("failed to decrypt asymmetric key: %w", err)
	}

	block, err := aes.NewCipher(decryptedKey.Plaintext)
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
		logger.Errorf("Data tampering detected or decryption failed: %v", err)
		return nil, err
	}

	return plaintext, nil
}
