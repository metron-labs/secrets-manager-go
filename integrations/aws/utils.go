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
	KEY_SIZE    = 32
	NONCE_SIZE  = 12
)

func GetKeyDetails(client *kms.Client, keyARN string, clientID string, clientSecret string, region string) (*string, *string, error) {
	result, err := client.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: &keyARN,
	})

	if err != nil {
		fmt.Println("Error describing key:", err)
		return nil, nil, fmt.Errorf("error fetching key details %v", err)
	}

	return (*string)(&result.KeyMetadata.KeySpec), (*string)(&result.KeyMetadata.KeyUsage), nil

}

func encryptSymmetric(client *kms.Client, keyId string, message []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is required")
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("message is required")
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
		return nil, fmt.Errorf("keyId is required")
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
		return nil, fmt.Errorf("keyId is required")
	}

	key := make([]byte, KEY_SIZE)
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
		logger.Error("Failed to encrypt asymmetric key: %v", err)
		return nil, fmt.Errorf("failed to encrypt asymmetric key: %v", err)
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
		return nil, fmt.Errorf("keyId is required")
	}
	if len(cipherText) < len(BLOB_HEADER)+KEY_SIZE {
		return nil, fmt.Errorf("invalid encrypted data")
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
		logger.Error("Failed to decrypt asymmetric key: %v", err)
		return nil, fmt.Errorf("failed to decrypt asymmetric key: %v", err)
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
		return nil, err
	}

	return plaintext, nil
}
