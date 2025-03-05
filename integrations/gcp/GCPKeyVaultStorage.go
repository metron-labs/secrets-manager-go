// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
// Keeper Secrets Manager
// Copyright 2025 Keeper Security Inc.
// Contact: sm@keepersecurity.com

package gcpkv

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"hash"
	"os"
	"path/filepath"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/secrets-manager-go/integrations/gcp/logger"
	"google.golang.org/api/option"
)

type googleCloudKeyVaultStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	keyResourceName     string
	gcpKMClient         *kms.KeyManagementClient
	gcpConfig           *GCPConfig
}

type GCPConfig struct {
	CredentialsFileLocation string
	KeyResourceName         string
}

var keyDetails = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]hash.Hash{
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256: sha256.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256: sha256.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256: sha256.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512: sha512.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1:   sha1.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1:   sha1.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:   sha1.New(),
}

// Creates a new instance of GoogleCloudKeyVaultStorage with the provided configuration.
func NewGCPKeyVaultStorage(configFileLocation string, gcpConfig *GCPConfig) *googleCloudKeyVaultStorage {
	ctx := context.Background()
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	gcpKeyManagementClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsFile(gcpConfig.CredentialsFileLocation))
	if err != nil {
		logger.Errorf("Failed to create GCP Key Management client: %v", err)
		return nil
	}
	defer gcpKeyManagementClient.Close()

	keyDetails, err := getKeyDetails(ctx, gcpKeyManagementClient, gcpConfig.KeyResourceName)
	if err != nil {
		return nil
	}

	if keyDetails.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT && keyDetails.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT {
		logger.Error("The specified key is not of type ENCRYPT_DECRYPT or ASYMMETRIC_DECRYPT")
		return nil
	}

	gcpStorage := &googleCloudKeyVaultStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		keyResourceName:     gcpConfig.KeyResourceName,
		gcpKMClient:         gcpKeyManagementClient,
		gcpConfig:           gcpConfig,
	}

	gcpStorage.loadConfig()
	return gcpStorage
}

// Loads the decrypted configuration from the config file if encrypted config is present, else encrypts the config.
func (g *googleCloudKeyVaultStorage) loadConfig() error {
	ctx := context.Background()
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool
	var decryptData []byte

	if err := g.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(g.configFileLocation)
	if err != nil {
		logger.Errorf("Failed to load config file %s: %s", g.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", g.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Errorf("Empty config file %s", g.configFileLocation)
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		g.config = config
		if err := g.saveConfig(config, false); err != nil {
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		g.lastSavedConfigHash = g.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		keydata, err := getKeyDetails(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName)
		if err != nil {
			return err
		}

		if keydata.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
			decryptData, err = decryptionSymmetric(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName, contents)
			if err != nil {
				decryptionError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
			}
		} else {
			decryptData, err = decryptAsymmetric(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName, contents)
			if err != nil {
				decryptionError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptionError = true
			logger.Errorf("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", g.configFileLocation)
		}

		g.config = config
		g.lastSavedConfigHash = g.createHash(decryptData)
	}

	if jsonError != nil && decryptionError {
		logger.Errorf("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", g.configFileLocation)
	}

	return nil
}

// Saves the encrypted updated configuration to the config file and updates the hash of the config.
func (g *googleCloudKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}, force bool) error {
	ctx := context.Background()
	configJson, err := json.Marshal(g.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configHash := g.createHash(configJson)
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := g.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			g.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				g.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if !force && configHash == g.lastSavedConfigHash {
		logger.Info("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := g.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := g.encryptConfig(ctx, configJson); err != nil {
		return err
	}

	g.lastSavedConfigHash = configHash
	return nil
}

// Creates a hash of the given configuration data.
func (g *googleCloudKeyVaultStorage) createHash(config []byte) string {
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

// Creates the config file if it does not already exist.
func (g *googleCloudKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(g.configFileLocation); !os.IsNotExist(err) {
		logger.Infof("Config file already exists at: %s", g.configFileLocation)
		return nil
	}

	dir := filepath.Dir(g.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := g.encryptConfig(context.Background(), []byte("{}")); err != nil {
		return err
	}

	logger.Infof("Config file created at: %s", g.configFileLocation)
	return nil
}

// Retrieves the details of the specified key from Google Cloud KMS.
func getKeyDetails(ctx context.Context, client *kms.KeyManagementClient, keyResourceName string) (*kmspb.CryptoKey, error) {
	// Remove the cryptoKeyVersions/<version> from the keyResourceName
	index := strings.Index(keyResourceName, "/cryptoKeyVersions/")
	if index != -1 {
		keyResourceName = keyResourceName[:index]
	}

	req := &kmspb.GetCryptoKeyRequest{
		Name: keyResourceName,
	}

	// Fetch the key details from GCP
	resp, err := client.GetCryptoKey(ctx, req)
	if err != nil {
		logger.Errorf("Failed to get key details: %v", err)
		return nil, fmt.Errorf("failed to get key details: %w", err)
	}

	return resp, nil
}

// Encrypts the configuration data and writes it to the config file.
func (g *googleCloudKeyVaultStorage) encryptConfig(ctx context.Context, config []byte) error {
	keyDetails, err := getKeyDetails(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName)
	if err != nil {
		return err
	}

	if keyDetails.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		ciphertext, err := encryptionSymmetric(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName, config)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	} else {
		ciphertext, err := encryptAsymmetric(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName, config)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	}

	return nil
}

func (g *googleCloudKeyVaultStorage) ChangeKey(updatedGcpConfig *GCPConfig) (bool, error) {
	oldKeyResourceName := g.keyResourceName
	oldGCPKMCClient := g.gcpKMClient
	if updatedGcpConfig.CredentialsFileLocation == "" {
		updatedGcpConfig.CredentialsFileLocation = g.gcpConfig.CredentialsFileLocation
	}

	newGCPKeyManagementClient, err := kms.NewKeyManagementClient(context.Background(), option.WithCredentialsFile(updatedGcpConfig.CredentialsFileLocation))
	if err != nil {
		logger.Errorf("Failed to create GCP Key Management client: %v", err)
		return false, fmt.Errorf("failed to create GCP Key Management client: %w", err)
	}
	defer newGCPKeyManagementClient.Close()

	g.gcpKMClient = newGCPKeyManagementClient
	g.keyResourceName = updatedGcpConfig.KeyResourceName
	if err := g.saveConfig(g.config, true); err != nil {
		g.gcpKMClient = oldGCPKMCClient
		g.keyResourceName = oldKeyResourceName
		logger.Errorf("Failed to change the key to '%s' for config '%s': %v", updatedGcpConfig.KeyResourceName, g.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", g.configFileLocation, err)
	}

	return true, nil
}

func (g *googleCloudKeyVaultStorage) DecryptConfig(autosave bool) (string, error) {
	var ciphertext []byte
	var plaintext []byte
	ctx := context.Background()

	ciphertext, err := os.ReadFile(g.configFileLocation)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	if len(ciphertext) == 0 {
		logger.Warnf("empty config file %s", g.configFileLocation)
		return "", nil
	}

	keydata, err := getKeyDetails(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName)
	if err != nil {
		return "", fmt.Errorf("failed to get key details: %w", err)
	}

	if keydata.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		plaintext, err = decryptionSymmetric(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName, ciphertext)
		if err != nil {
			logger.Errorf("Failed to decrypt config file: %s", err.Error())
			return "", fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
		}
	} else {
		plaintext, err = decryptAsymmetric(ctx, g.gcpKMClient, g.gcpConfig.KeyResourceName, ciphertext)
		if err != nil {
			logger.Errorf("Failed to decrypt config file: %s", err.Error())
			return "", fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
		}
	}

	if len(plaintext) == 0 {
		logger.Error("empty config file")
		return "", fmt.Errorf("empty config file")
	} else if autosave {
		if err := os.WriteFile(g.configFileLocation, plaintext, 0644); err != nil {
			logger.Error(fmt.Sprintf("failed to write decrypted config file %s: %v", g.configFileLocation, err))
			return "", fmt.Errorf("failed to write decrypted config file %s", g.configFileLocation)
		}
	}

	return string(plaintext), nil
}
