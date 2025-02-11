package keyvault_azure

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	klog "keyvault_azure/logger"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type ConfigKey string

type AzureConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	VaultURL     string
}

type AzureKeyValueStorage struct {
	configFileLocation  string
	config              map[ConfigKey]string
	lastSavedConfigHash string
	cryptoClient        *azkeys.Client
	keyName             string
	keyVersion          string
}

func NewAzureKeyValueStorage(keyName, keyVersion, configFileLocation string, azSessionConfig *AzureConfig) (*AzureKeyValueStorage, error) {
	// Initialize config file location
	if configFileLocation == "" {
		configFileLocation = os.Getenv("KSM_CONFIG_FILE")
		if configFileLocation == "" {
			configFileLocation = "defaultConfigFileLocation" // Replace with your default config file location
		}
	}

	var cred *azidentity.ClientSecretCredential
	if azSessionConfig != nil && azSessionConfig.TenantID != "" && azSessionConfig.ClientID != "" && azSessionConfig.ClientSecret != "" {
		var err error
		cred, err = azidentity.NewClientSecretCredential(azSessionConfig.TenantID, azSessionConfig.ClientID, azSessionConfig.ClientSecret, nil)
		if err != nil {
			klog.Error("Failed to create client secret credential: %v", err)
			return nil, err
		}
	}

	// Initialize Azure Key Vault client
	client, err := azkeys.NewClient(azSessionConfig.VaultURL, cred, nil)
	if err != nil {
		klog.Error("Failed to create Azure Key Vault client: %v", err)
		return nil, err
	}

	azureDetails := &AzureKeyValueStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[ConfigKey]string),
		lastSavedConfigHash: "",
		cryptoClient:        client,
		keyName:             keyName,
		keyVersion:          keyVersion,
	}

	azureDetails.loadConfig()
	return azureDetails, nil
}

func (s *AzureKeyValueStorage) loadConfig() error {
	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	// Read the config file
	contents, err := os.ReadFile(s.configFileLocation)
	if err != nil {
		klog.Error("Failed to load config file %s: %s", s.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", s.configFileLocation)
	}

	if len(contents) == 0 {
		klog.Error("Empty config file %s", s.configFileLocation)
	}

	// Check if the content is plain JSON
	var config map[ConfigKey]string
	var jsonError error
	var decryptionError bool

	configData := string(contents)
	if err := json.Unmarshal([]byte(configData), &config); err == nil {
		// Encrypt and save the config if it's plain JSON
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
			klog.Error("Failed to decrypt config file: %s", err.Error())
			return fmt.Errorf("failed to decrypt config file %s", s.configFileLocation)
		}

		if err := json.Unmarshal([]byte(configJson), &config); err != nil {
			decryptionError = true
			klog.Error("Failed to parse decrypted config file: %s", err.Error())
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
		klog.Error("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", s.configFileLocation)
	}

	return nil
}

func (s *AzureKeyValueStorage) createConfigFileIfMissing() error {
	// Check if the config file already exists
	if _, err := os.Stat(s.configFileLocation); os.IsNotExist(err) {
		// Ensure the directory structure exists
		dir := filepath.Dir(s.configFileLocation)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}

		// Encrypt an empty configuration and write to the file
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

func (s *AzureKeyValueStorage) saveConfig(updatedConfig map[ConfigKey]string, force bool) error {
	config := s.config
	if config == nil {
		config = make(map[ConfigKey]string)
	}

	// Convert current config to JSON and calculate its hash
	configJson, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal current config: %w", err)
	}
	configHash := s.createHash(configJson)

	// Compare updatedConfig hash with current config hash
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.MarshalIndent(updatedConfig, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}
		updatedConfigHash := s.createHash(updatedConfigJson)

		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			s.config = make(map[ConfigKey]string)
			for k, v := range updatedConfig {
				s.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// Check if saving is necessary
	if !force && configHash == s.lastSavedConfigHash {
		fmt.Println("Skipped config JSON save. No changes detected.")
		return nil
	}

	// Ensure the config file exists
	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	// Encrypt the config JSON and write to the file
	blob, err := encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, string(configJson))
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}
	if err := os.WriteFile(s.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", s.configFileLocation, err)
	}

	// Update the last saved config hash
	s.lastSavedConfigHash = configHash

	return nil
}

func (s *AzureKeyValueStorage) createHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func (a *AzureKeyValueStorage) ReadStorage() map[string]interface{} {
	// To match what FileKeyValueStorage does, we need to return the enum values as keys
	// instead of the enum keys
	dictConfig := map[string]interface{}{}
	for key, value := range a.config {
		dictConfig[string(key)] = value
	}

	return dictConfig
}

func (a *AzureKeyValueStorage) SaveStorage(updatedConfig map[string]interface{}) {}

func (a *AzureKeyValueStorage) Get(key ConfigKey) string {
	if val, ok := a.config[key]; ok {
		return val
	}
	return ""
}

func (a *AzureKeyValueStorage) Set(key ConfigKey, value interface{}) map[string]interface{} {
	switch v := value.(type) {
	case string:
		a.config[key] = v
		return a.ReadStorage()
	default:
		klog.Error(fmt.Sprintf("Unknown value for ConfigKey: %s, Value: %v", string(key), v))
	}
	return nil
}

func (a *AzureKeyValueStorage) Delete(key ConfigKey) map[string]interface{} {
	if _, found := a.config[key]; found {
		delete(a.config, key)
		klog.Debug("Removed key: " + key)
	} else {
		klog.Warning(fmt.Sprintf("No key '%s' was found in config", string(key)))
	}
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) DeleteAll() map[string]interface{} {
	a.config = map[ConfigKey]string{}
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) Contains(key ConfigKey) bool {
	_, found := a.config[key]
	return found
}

func (a *AzureKeyValueStorage) IsEmpty() bool {
	return len(a.config) == 0
}
