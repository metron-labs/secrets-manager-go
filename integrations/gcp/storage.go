package gcpkv

import (
	"context"
	"fmt"
	"gcpkv/gcp/logger"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/keeper-security/secrets-manager-go/core"
	"google.golang.org/api/option"
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
		logger.Warnf("%s", fmt.Sprintf("No key '%s' was found in config", string(key)))
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

func (g *GoogleCloudKeyVaultStorage) changeKey(newKeyResourceName string) (bool, error) {
	oldKeyResourceName := g.keyResourceName
	oldGCPKMCClient := g.gcpKMCClient
	newGCPKeyManagementClient, err := kms.NewKeyManagementClient(context.Background(), option.WithCredentialsFile(g.gcpConfig.CredentialsFileLocation))
	if err != nil {
		logger.Errorf("Failed to create GCP Key Management client: %v", err)
		return false, fmt.Errorf("failed to create GCP Key Management client: %w", err)
	}
	defer newGCPKeyManagementClient.Close()

	g.gcpKMCClient = newGCPKeyManagementClient
	g.keyResourceName = newKeyResourceName
	if err := g.saveConfig(g.config); err != nil {
		g.gcpKMCClient = oldGCPKMCClient
		g.keyResourceName = oldKeyResourceName
		logger.Errorf("Failed to change the key to '%s' for config '%s': %v", newKeyResourceName, g.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", g.configFileLocation, err)
	}

	return true, nil
}
