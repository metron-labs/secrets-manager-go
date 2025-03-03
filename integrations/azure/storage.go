package azurekv

import (
	"github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/secrets-manager-go/integrations/azure/logger"
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

	if err := a.saveConfig(convertedConfig, false); err != nil {
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
		a.saveConfig(a.config, false)
	} else {
		logger.Warnf("No key '%s' was found in config", string(key))
	}
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]interface{}{}
	a.saveConfig(a.config, false)
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *AzureKeyValueStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}
