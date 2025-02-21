package gcpkv

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gcpkv/gcp/logger"
	"os"
	"path/filepath"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/keeper-security/secrets-manager-go/core"
	"google.golang.org/api/option"
)

type GoogleCloudKeyVaultStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	gcpKMCClient        *kms.KeyManagementClient
	gcpConfig           *GCPConfig
}

type GCPConfig struct {
	CredentialsFileLocation string
	KeyResourceName         string
}

func NewGCPKeyVaultStorage(configFileLocation string, gcpConfig *GCPConfig) *GoogleCloudKeyVaultStorage {
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

	gcpStorage := &GoogleCloudKeyVaultStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		gcpKMCClient:        gcpKeyManagementClient,
		gcpConfig:           gcpConfig,
	}

	gcpStorage.loadConfig()
	return gcpStorage
}

func (g *GoogleCloudKeyVaultStorage) loadConfig() error {
	ctx := context.Background()
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool
	var decryptData []byte
	var keySize int

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
		if err := g.saveConfig(config); err != nil {
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
		keydata, err := getKeyDetails(ctx, g.gcpKMCClient, g.gcpConfig.KeyResourceName)
		if err != nil {
			return err
		}

		keySize = getKeySize(keydata.VersionTemplate.Algorithm)
		if keydata.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
			decryptData, err = decryptionSymmetric(ctx, g.gcpKMCClient, g.gcpConfig.KeyResourceName, contents)
			if err != nil {
				decryptionError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
			}
		} else {
			decryptData, err = decryptAsymmetric(ctx, g.gcpKMCClient, g.gcpConfig.KeyResourceName, contents, keySize)
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

func (g *GoogleCloudKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}) error {
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

	if configHash == g.lastSavedConfigHash {
		fmt.Println("Skipped config JSON save. No changes detected.")
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

func (g *GoogleCloudKeyVaultStorage) createHash(config []byte) string {
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

func (g *GoogleCloudKeyVaultStorage) createConfigFileIfMissing() error {
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

func getKeyDetails(ctx context.Context, client *kms.KeyManagementClient, keyResourceName string) (*kmspb.CryptoKey, error) {
	index := strings.Index(keyResourceName, "/cryptoKeyVersions/")
	if index != -1 {
		keyResourceName = keyResourceName[:index]
	}

	req := &kmspb.GetCryptoKeyRequest{
		Name: keyResourceName,
	}

	resp, err := client.GetCryptoKey(ctx, req)
	if err != nil {
		logger.Errorf("Failed to get key details: %v", err)
		return nil, fmt.Errorf("failed to get key details: %w", err)
	}

	return resp, nil
}

func getKeySize(keyData kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) int {
	switch keyData {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256:
		return 256
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256:
		return 384
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
		return 512
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
		return 512
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1:
		return 256
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1:
		return 384
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:
		return 512
	default:
		return 0
	}
}

func (g *GoogleCloudKeyVaultStorage) encryptConfig(ctx context.Context, config []byte) error {
	keyDetails, err := getKeyDetails(ctx, g.gcpKMCClient, g.gcpConfig.KeyResourceName)
	if err != nil {
		return err
	}

	if keyDetails.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		ciphertext, err := encryptionSymmetric(ctx, g.gcpKMCClient, g.gcpConfig.KeyResourceName, config)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	} else {
		ciphertext, err := encryptAsymmetric(ctx, g.gcpKMCClient, g.gcpConfig.KeyResourceName, config)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	}

	return nil
}
