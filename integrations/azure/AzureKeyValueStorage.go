package azurekv

import (
	"azurekv/logger"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	config              map[core.ConfigKey]string
	lastSavedConfigHash string
	cryptoClient        *azkeys.Client
	keyName             string
	keyVersion          string
}

func NewAzureKeyValueStorage(configFileLocation string, azSessionConfig *AzureConfig) *AzureKeyValueStorage {
	log := logger.NewDefaultLogger()
	if configFileLocation == "" {
		configFileLocation = os.Getenv("KSM_CONFIG_FILE")
		if configFileLocation == "" {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	var cred *azidentity.ClientSecretCredential
	if azSessionConfig != nil && azSessionConfig.TenantID != "" && azSessionConfig.ClientID != "" && azSessionConfig.ClientSecret != "" {
		var err error
		cred, err = azidentity.NewClientSecretCredential(azSessionConfig.TenantID, azSessionConfig.ClientID, azSessionConfig.ClientSecret, nil)
		if err != nil {
			log.Errorf("Failed to create client secret credential: %v", err)
			return nil
		}
	}

	baseURL, keyName, keyVersion, err := extractKeyDetails(azSessionConfig.KeyURL)
	if err != nil {
		return nil
	}

	client, err := azkeys.NewClient(baseURL, cred, nil)
	if err != nil {
		log.Error("Failed to create Azure Key Vault client: %v", err)
		return nil
	}

	azureDetails := &AzureKeyValueStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]string),
		lastSavedConfigHash: "",
		cryptoClient:        client,
		keyName:             keyName,
		keyVersion:          keyVersion,
	}

	err = azureDetails.loadConfig()
	if err != nil {
		return nil
	}

	return azureDetails
}

func (s *AzureKeyValueStorage) loadConfig() error {
	logger := logger.NewDefaultLogger()
	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(s.configFileLocation)
	if err != nil {
		logger.Error("Failed to load config file %s: %s", s.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", s.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Error("Empty config file %s", s.configFileLocation)
	}

	var config map[core.ConfigKey]string
	var jsonError error
	var decryptionError bool

	configData := string(contents)
	if err := json.Unmarshal([]byte(configData), &config); err == nil {
		s.config = config
		if err := s.saveConfig(config, false); err != nil {
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

		configJson = string(configJsonBytes)
		s.lastSavedConfigHash = s.createHash([]byte(configJson))
	}

	if jsonError != nil && decryptionError {
		logger.Error("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", s.configFileLocation)
	}

	return nil
}

func (s *AzureKeyValueStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(s.configFileLocation); os.IsNotExist(err) {
		dir := filepath.Dir(s.configFileLocation)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}

		blob, err := encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, "")
		if err != nil {
			return fmt.Errorf("failed to encrypt empty configuration: %w", err)
		}

		if err := os.WriteFile(s.configFileLocation, blob, 0644); err != nil {
			return fmt.Errorf("failed to write config file %s: %w", s.configFileLocation, err)
		}

		fmt.Println("Config file created at:", s.configFileLocation)
	} else {
		fmt.Println("Config file already exists at:", s.configFileLocation)
	}

	return nil
}

func (s *AzureKeyValueStorage) saveConfig(updatedConfig map[core.ConfigKey]string, force bool) error {
	config := s.config
	if config == nil {
		config = make(map[core.ConfigKey]string)
	}

	configJson, err := json.MarshalIndent(config, "", "    ")
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
			s.config = make(map[core.ConfigKey]string)
			for k, v := range updatedConfig {
				s.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if !force && configHash == s.lastSavedConfigHash {
		fmt.Println("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	blob, err := encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, string(configJson))
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
