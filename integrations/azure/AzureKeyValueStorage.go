package keyvault_azure

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"keyvault_azure/logger"
	klog "keyvault_azure/logger"
	"os"
	"path/filepath"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type AzureKeyValueStorage struct {
	configFileLocation  string
	config              map[string]string
	lastSavedConfigHash string
	cryptoClient        *azkeys.Client
	logger              *logger.Logger
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
		s.logger.Fatalf("Empty config file %s", s.configFileLocation)
	}

	// Check if the content is plain JSON
	var config map[string]string
	var jsonError error
	var decryptionError bool
	var keyName string
	var keyVersion string

	configData := string(contents)
	if err := json.Unmarshal([]byte(configData), &config); err == nil {
		// Encrypt and save the config if it's plain JSON
		s.config = config
		if err := s.saveConfig(config); err != nil {
			return err
		}

		s.lastSavedConfigHash = s.createHash(config)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		configJson, err := decryptBuffer(s.cryptoClient, keyName, keyVersion, contents)
		if err != nil {
			decryptionError = true
			klog.Error("Failed to decrypt config file: %s", err.Error())
			return fmt.Errorf("failed to decrypt config file %s", s.configFileLocation)
		}

		if err := json.Unmarshal([]byte(configJson), &config); err != nil {
			decryptionError = true
			s.logger.Fatalf("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", s.configFileLocation)
		}

		s.config = config
		s.lastSavedConfigHash = s.createHash(config)
	}

	if jsonError != nil && decryptionError {
		s.logger.Printf("Config file is not a valid JSON file: %s", jsonError.Error())
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
		blob, err := encryptBuffer(s.cryptoClient, "{}")
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

func (s *AzureKeyValueStorage) saveConfig(config map[string]string) error {
	// Retrieve current config
	config = s.config
	if config == nil {
		config = make(map[string]string)
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
		updatedConfigHash := createHash(updatedConfigJson)

		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			s.config = updatedConfig // Update the current config
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
	blob, err := encryptBuffer(s.cryptoClient, configJson)
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

func (s *AzureKeyValueStorage) createHash(config map[string]string) string {
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buffer bytes.Buffer
	for _, k := range keys {
		buffer.WriteString(fmt.Sprintf("%s:%s", k, config[k]))
	}

	hash := md5.Sum(buffer.Bytes())
	return hex.EncodeToString(hash[:])
}

func (m *AzureKeyValueStorage) ReadStorage() map[string]interface{} {
	// To match what FileKeyValueStorage does, we need to return the enum values as keys
	// instead of the enum keys
	dictConfig := map[string]interface{}{}
	for key, value := range m.Config {
		dictConfig[string(key)] = value
	}

	return dictConfig
}

func (m *AzureKeyValueStorage) SaveStorage(updatedConfig map[string]interface{}) {}

func (m *AzureKeyValueStorage) Get(key ConfigKey) string {
	if val, ok := m.Config[key]; ok {
		return val
	}
	return ""
}

func (m *AzureKeyValueStorage) Set(key ConfigKey, value interface{}) map[string]interface{} {
	switch v := value.(type) {
	case string:
		m.Config[key] = v
		return m.ReadStorage()
	default:
		klog.Error(fmt.Sprintf("Unknown value for ConfigKey: %s, Value: %v", string(key), v))
	}
	return nil
}

func (m *AzureKeyValueStorage) Delete(key ConfigKey) map[string]interface{} {
	if _, found := m.Config[key]; found {
		delete(m.Config, key)
		klog.Debug("Removed key: " + key)
	} else {
		klog.Warning(fmt.Sprintf("No key '%s' was found in config", string(key)))
	}
	return m.ReadStorage()
}

func (m *AzureKeyValueStorage) DeleteAll() map[string]interface{} {
	m.Config = map[ConfigKey]string{}
	return m.ReadStorage()
}

func (m *AzureKeyValueStorage) Contains(key ConfigKey) bool {
	_, found := m.Config[key]
	return found
}

func (m *AzureKeyValueStorage) IsEmpty() bool {
	return len(m.Config) == 0
}
