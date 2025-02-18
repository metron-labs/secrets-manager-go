package azurekv

import (
	"azurekv/logger"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/keeper-security/secrets-manager-go/core"
)

type AzureConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	KeyURL       string
}

type AzureKeyValueStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	cryptoClient        *azkeys.Client
	keyName             string
	keyVersion          string
	azureConfig         *AzureConfig
}

func NewAzureKeyValueStorage(configFileLocation string, azSessionConfig *AzureConfig) *AzureKeyValueStorage {
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	credential, err := fetchCredentials(azSessionConfig)
	if err != nil {
		return nil
	}

	baseURL, keyName, keyVersion, err := fetchKeyDetails(azSessionConfig.KeyURL)
	if err != nil {
		return nil
	}

	client, err := azkeys.NewClient(baseURL, credential, nil)
	if err != nil {
		logger.Errorf("Failed to create Azure Key Vault client: %v", err)
		return nil
	}

	azureDetails := &AzureKeyValueStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		cryptoClient:        client,
		keyName:             keyName,
		keyVersion:          keyVersion,
		azureConfig:         azSessionConfig,
	}

	err = azureDetails.loadConfig()
	if err != nil {
		return nil
	}

	return azureDetails
}

func (s *AzureKeyValueStorage) loadConfig() error {
	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(s.configFileLocation)
	if err != nil {
		logger.Errorf("Failed to load config file %s: %s", s.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", s.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Errorf("Empty config file %s", s.configFileLocation)
		contents = []byte("{}")
	}

	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool

	if err := json.Unmarshal(contents, &config); err == nil {
		s.config = config
		if err := s.saveConfig(config); err != nil {
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		s.lastSavedConfigHash = s.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		configJson, err := decryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, contents)
		if err != nil {
			decryptionError = true
			logger.Error("Failed to decrypt config file: %s", err.Error())
			return fmt.Errorf("failed to decrypt config file %s", s.configFileLocation)
		}

		if err := json.Unmarshal([]byte(configJson), &config); err != nil {
			decryptionError = true
			logger.Error("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", s.configFileLocation)
		}

		s.config = config

		configJsonBytes, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		s.lastSavedConfigHash = s.createHash(configJsonBytes)
	}

	if jsonError != nil && decryptionError {
		logger.Error("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", s.configFileLocation)
	}

	return nil
}

func (s *AzureKeyValueStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(s.configFileLocation); !os.IsNotExist(err) {
		logger.Infof("Config file already exists at: %s", s.configFileLocation)
		return nil
	}

	dir := filepath.Dir(s.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	blob, err := encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, []byte("{}"))
	if err != nil {
		return fmt.Errorf("failed to encrypt empty configuration: %w", err)
	}

	if err := os.WriteFile(s.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", s.configFileLocation, err)
	}

	logger.Infof("Config file created at: %s", s.configFileLocation)
	return nil
}

func (s *AzureKeyValueStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}) error {
	config := s.config
	if config == nil {
		config = make(map[core.ConfigKey]interface{})
	}

	configJson, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal current config: %w", err)
	}
	configHash := s.createHash(configJson)

	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.MarshalIndent(updatedConfig, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}
		updatedConfigHash := s.createHash(updatedConfigJson)

		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			s.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				s.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if configHash == s.lastSavedConfigHash {
		fmt.Println("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	blob, err := encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, configJson)
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}

	if err := os.WriteFile(s.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", s.configFileLocation, err)
	}

	s.lastSavedConfigHash = configHash
	return nil
}

func (s *AzureKeyValueStorage) createHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func (s *AzureKeyValueStorage) changeKey(newKeyURL string) (bool, error) {
	oldKeyURL := s.azureConfig.KeyURL
	oldCryptoClient := s.cryptoClient
	vaultURL, keyName, keyVersion, err := fetchKeyDetails(newKeyURL)
	if err != nil {
		logger.Errorf("Failed to extract key details from URL '%s': %v", newKeyURL, err)
		return false, fmt.Errorf("failed to extract key details from URL '%s': %w", newKeyURL, err)
	}

	s.azureConfig.KeyURL = newKeyURL
	s.keyName = keyName
	s.keyVersion = keyVersion
	cred, err := fetchCredentials(s.azureConfig)
	if err != nil {
		return false, err
	}

	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	s.cryptoClient = client
	if err := s.saveConfig(s.config); err != nil {
		oldBaseURL, oldKeyName, oldKeyVersion, err := fetchKeyDetails(oldKeyURL)
		s.azureConfig.KeyURL = oldBaseURL
		s.keyName = oldKeyName
		s.keyVersion = oldKeyVersion
		s.cryptoClient = oldCryptoClient
		logger.Errorf("Failed to change the key to '%s' for config '%s': %v", newKeyURL, s.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", s.configFileLocation, err)
	}

	return true, nil
}

func fetchCredentials(azSessionConfig *AzureConfig) (azcore.TokenCredential, error) {
	var secretCredentials azcore.TokenCredential
	var err error
	if azSessionConfig != nil && azSessionConfig.TenantID != "" && azSessionConfig.ClientID != "" && azSessionConfig.ClientSecret != "" {
		secretCredentials, err = azidentity.NewClientSecretCredential(azSessionConfig.TenantID, azSessionConfig.ClientID, azSessionConfig.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create client secret credential: %v", err)
		}
	} else {
		secretCredentials, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create default Azure credential: %v", err)
		}
	}
	return secretCredentials, nil
}
