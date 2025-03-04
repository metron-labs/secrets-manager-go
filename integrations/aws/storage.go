package awskv

import (
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/secrets-manager-go/integrations/aws/logger"
)

func (a *awsKeyVaultStorage) ReadStorage() map[string]interface{} {
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

func (a *awsKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := a.saveConfig(convertedConfig, false); err != nil {
		logger.Errorf("%s", fmt.Sprintf("Failed to save config: %v", err))
	}
}

func (a *awsKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := a.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
		logger.Errorf("%s", fmt.Sprintf("Invalid type for key '%s': %v", key, val))
		return ""
	}
	return ""
}

func (a *awsKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	switch v := value.(type) {
	case string:
		a.config[key] = v
		return a.ReadStorage()
	default:
		logger.Errorf("%s", fmt.Sprintf("Unknown value for ConfigKey: %s, Value: %v", string(key), v))
	}
	return nil
}

func (a *awsKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := a.config[key]; found {
		delete(a.config, key)
		logger.Debugf("Removed key: %s", string(key))
		a.saveConfig(a.config, false)
	} else {
		logger.Warnf("No key '%s' was found in config", string(key))
	}
	return a.ReadStorage()
}

func (a *awsKeyVaultStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]interface{}{}
	a.saveConfig(a.config, false)
	return a.ReadStorage()
}

func (a *awsKeyVaultStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *awsKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}
