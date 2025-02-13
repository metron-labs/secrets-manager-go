package azurekv

import (
	"azurekv/logger"
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
)

func (a *AzureKeyValueStorage) ReadStorage() map[string]interface{} {
	dictConfig := map[string]interface{}{}
	for key, value := range a.config {
		dictConfig[string(key)] = value
	}
	return dictConfig
}

func (a *AzureKeyValueStorage) SaveStorage(updatedConfig map[string]interface{}) {}

func (a *AzureKeyValueStorage) Get(key core.ConfigKey) string {
	if val, ok := a.config[key]; ok {
		return val
	}
	return ""
}

func (a *AzureKeyValueStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	logger := logger.NewDefaultLogger()
	switch v := value.(type) {
	case string:
		a.config[key] = v
		return a.ReadStorage()
	default:
		logger.Errorf("%s", fmt.Sprintf("Unknown value for ConfigKey: %s, Value: %v", string(key), v))
	}
	return nil
}

func (a *AzureKeyValueStorage) Delete(key core.ConfigKey) map[string]interface{} {
	logger := logger.NewDefaultLogger()
	if _, found := a.config[key]; found {
		delete(a.config, key)
		logger.Debugf("%s", "Removed key: "+string(key))
	} else {
		logger.Warn("%s", fmt.Sprintf("No key '%s' was found in config", string(key)))
	}
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]string{}
	return a.ReadStorage()
}

func (a *AzureKeyValueStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *AzureKeyValueStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}
