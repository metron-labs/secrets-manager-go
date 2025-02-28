package azurekv

import (
	"azurekv/logger"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/keeper-security/secrets-manager-go/core"
)

func (a *AzureKeyValueStorage) ReadStorage() map[string]interface{} {
	if err := a.loadConfig(); err != nil {
		logger.Errorf("Failed to load config: %v", err)
		return nil
	}
	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}
	return convertedConfig
}

func (a *AzureKeyValueStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := a.saveConfig(convertedConfig); err != nil {
		logger.Errorf("Failed to save config: %v", err)
	}
}

func (a *AzureKeyValueStorage) Get(key core.ConfigKey) string {
	if val, ok := a.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""

}

func (a *AzureKeyValueStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	a.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}
	a.SaveStorage(convertedConfig)
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := a.config[key]; found {
		delete(a.config, key)
		logger.Debugf("Removed key: %s", string(key))
		a.saveConfig(a.config)
	} else {
		logger.Warnf("No key '%s' was found in config", string(key))
	}
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]interface{}{}
	a.saveConfig(a.config)
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *AzureKeyValueStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}

// Changes the key used to encrypt/decrypt the configuration.
func (s *AzureKeyValueStorage) ChangeKey(newKeyURL string) (bool, error) {
	oldState := struct {
		vaultURL, keyName, keyVersion string
		cryptoClient                  *azkeys.Client
	}{
		s.azureConfig.KeyURL, s.keyName, s.keyVersion, s.cryptoClient,
	}

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
		s.azureConfig.KeyURL = oldState.vaultURL
		s.keyName = oldState.keyName
		s.keyVersion = oldState.keyVersion
		s.cryptoClient = oldState.cryptoClient
		logger.Errorf("Failed to change the key to '%s' for config '%s': %v", newKeyURL, s.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", s.configFileLocation, err)
	}

	return true, nil
}
