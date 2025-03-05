package gcpkv

import (
	"github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/secrets-manager-go/integrations/gcp/logger"
)

func (g *googleCloudKeyVaultStorage) ReadStorage() map[string]interface{} {
	if err := g.loadConfig(); err != nil {
		logger.Errorf("Failed to load config: %v", err)
		return nil
	}

	convertedConfig := make(map[string]interface{})
	for k, v := range g.config {
		convertedConfig[string(k)] = v
	}

	return convertedConfig
}

func (g *googleCloudKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := g.saveConfig(convertedConfig, false); err != nil {
		logger.Errorf("Failed to save config: %v", err)
	}
}

func (g *googleCloudKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := g.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return ""

}

func (g *googleCloudKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	g.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range g.config {
		convertedConfig[string(k)] = v
	}

	g.SaveStorage(convertedConfig)
	return g.ReadStorage()
}

func (g *googleCloudKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := g.config[key]; found {
		delete(g.config, key)
		logger.Debugf("Removed key: %s", string(key))
		g.saveConfig(g.config, false)
	} else {
		logger.Warnf("No key '%s' was found in config", string(key))
	}

	return g.ReadStorage()
}

func (g *googleCloudKeyVaultStorage) DeleteAll() map[string]interface{} {
	g.config = map[core.ConfigKey]interface{}{}
	g.saveConfig(g.config, false)
	return g.ReadStorage()
}

func (g *googleCloudKeyVaultStorage) IsEmpty() bool {
	return len(g.config) == 0
}

func (g *googleCloudKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := g.config[key]
	return found
}
