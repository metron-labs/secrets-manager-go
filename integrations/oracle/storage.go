package oraclekv

import (
	"fmt"
	"oraclekv/oracle/logger"

	"github.com/keeper-security/secrets-manager-go/core"
)

func (o *OracleKeyVaultStorage) ReadStorage() map[string]interface{} {
	if err := o.loadConfig(); err != nil {
		logger.Errorf("Failed to load config: %v", err)
		return nil
	}
	convertedConfig := make(map[string]interface{})
	for k, v := range o.config {
		convertedConfig[string(k)] = v
	}
	return convertedConfig
}

func (o *OracleKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := o.saveConfig(convertedConfig, false); err != nil {
		logger.Errorf("Failed to save config: %v", err)
	}
}

func (o *OracleKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := o.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
		logger.Errorf("%s", fmt.Sprintf("Invalid type for key '%s': %v", key, val))
		return ""
	}
	return ""
}

func (o *OracleKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	o.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range o.config {
		convertedConfig[string(k)] = v
	}
	o.SaveStorage(convertedConfig)
	return o.ReadStorage()
}

func (o *OracleKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := o.config[key]; found {
		delete(o.config, key)
		logger.Debugf("%s", "Removed key: "+string(key))
		o.saveConfig(o.config, false)
	} else {
		logger.Warnf("No key '%s' was found in config", string(key))
	}
	return o.ReadStorage()
}

func (o *OracleKeyVaultStorage) DeleteAll() map[string]interface{} {
	o.config = map[core.ConfigKey]interface{}{}
	return o.ReadStorage()
}

func (o *OracleKeyVaultStorage) IsEmpty() bool {
	return len(o.config) == 0
}

func (o *OracleKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := o.config[key]
	return found
}
