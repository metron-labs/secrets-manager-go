package gcpkv

import (
	"fmt"
	"gcpkv/gcp/logger"

	"github.com/keeper-security/secrets-manager-go/core"
)

func (g *GoogleCloudKeyVaultStorage) ReadStorage() map[string]interface{} {
	if err := g.loadConfig(); err != nil {
		logger.Errorf("%s", fmt.Sprintf("Failed to load config: %v", err))
		return nil
	}
	convertedConfig := make(map[string]interface{})
	for k, v := range g.config {
		convertedConfig[string(k)] = v
	}
	return convertedConfig
}

func (g *GoogleCloudKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := g.saveConfig(convertedConfig); err != nil {
		logger.Errorf("%s", fmt.Sprintf("Failed to save config: %v", err))
	}
}

func (g *GoogleCloudKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := g.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
		logger.Errorf("%s", fmt.Sprintf("Invalid type for key '%s': %v", key, val))
		return ""
	}
	return ""
}

func (g *GoogleCloudKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	g.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range g.config {
		convertedConfig[string(k)] = v
	}
	g.SaveStorage(convertedConfig)
	return g.ReadStorage()
}

func (g *GoogleCloudKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := g.config[key]; found {
		delete(g.config, key)
		logger.Debugf("%s", "Removed key: "+string(key))
		g.saveConfig(g.config)
	} else {
		logger.Warn("%s", fmt.Sprintf("No key '%s' was found in config", string(key)))
	}
	return g.ReadStorage()
}

func (g *GoogleCloudKeyVaultStorage) DeleteAll() map[string]interface{} {
	g.config = map[core.ConfigKey]interface{}{}
	return g.ReadStorage()
}

func (g *GoogleCloudKeyVaultStorage) IsEmpty() bool {
	return len(g.config) == 0
}

func (g *GoogleCloudKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := g.config[key]
	return found
}
