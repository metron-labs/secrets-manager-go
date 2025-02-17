package awskv

import (
	"awskv/aws/logger"
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
)

func (a *AWSKeyVaultStorage) ReadStorage() map[string]interface{} {
	if err := a.loadConfig(); err != nil {
		logger.Errorf("%s", fmt.Sprintf("Failed to load config: %v", err))
		return nil
	}
	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}
	return convertedConfig
}

func (a *AWSKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := a.saveConfig(convertedConfig); err != nil {
		logger.Errorf("%s", fmt.Sprintf("Failed to save config: %v", err))
	}
}

func (a *AWSKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := a.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
		logger.Errorf("%s", fmt.Sprintf("Invalid type for key '%s': %v", key, val))
		return ""
	}
	return ""
}

func (a *AWSKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	switch v := value.(type) {
	case string:
		a.config[key] = v
		return a.ReadStorage()
	default:
		logger.Errorf("%s", fmt.Sprintf("Unknown value for ConfigKey: %s, Value: %v", string(key), v))
	}
	return nil
}

func (a *AWSKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := a.config[key]; found {
		delete(a.config, key)
		logger.Debugf("%s", "Removed key: "+string(key))
		a.saveConfig(a.config)
	} else {
		logger.Warn("%s", fmt.Sprintf("No key '%s' was found in config", string(key)))
	}
	return a.ReadStorage()
}

func (a *AWSKeyVaultStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]interface{}{}
	return a.ReadStorage()
}

func (a *AWSKeyVaultStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *AWSKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}
