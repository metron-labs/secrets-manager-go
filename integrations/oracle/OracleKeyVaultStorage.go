// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
// Keeper Secrets Manager
// Copyright 2025 Keeper Security Inc.
// Contact: sm@keepersecurity.com

package oraclekv

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"oraclekv/oracle/logger"
	"os"
	"path/filepath"

	"github.com/keeper-security/secrets-manager-go/core"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

type KeyConfig struct {
	KeyId                   string
	KeyVersionID            string
	VaultManagementEndpoint string
	VaultCryptoEndpoint     string
	Profile                 string
	ProfileConfigPath       string
}

type OracleKeyVaultStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	keyResourceName     string
	oracleKMSClient     keymanagement.KmsCryptoClient
	keyConfig           *KeyConfig
}

// Creates a new OracleKeyVaultStorage instance.
func NewOracleKeyVaultStorage(configFileLocation string, keyConfig *KeyConfig) *OracleKeyVaultStorage {
	var client keymanagement.KmsCryptoClient
	var err error
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	if keyConfig.Profile == "" && keyConfig.ProfileConfigPath == "" {
		client, err = keymanagement.NewKmsCryptoClientWithConfigurationProvider(common.DefaultConfigProvider(), keyConfig.VaultCryptoEndpoint)
		if err != nil {
			logger.Errorf("Failed to create Oracle KMS crypto client: %v", err)
			return nil
		}
	} else {
		client, err = keymanagement.NewKmsCryptoClientWithConfigurationProvider(common.CustomProfileConfigProvider(keyConfig.ProfileConfigPath, keyConfig.Profile), keyConfig.VaultCryptoEndpoint)
		if err != nil {
			logger.Errorf("Failed to create Oracle KMS crypto client: %v", err)
			return nil
		}
	}

	keyDetails, err := getKeyDetails(keyConfig)
	if err != nil {
		logger.Errorf("Failed to get key details: %v", err)
		return nil
	}

	if keyDetails.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmAes && keyDetails.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmRsa {
		logger.Errorf("Unsupported key encryption algorithm: %v", keyDetails)
		return nil
	}

	oracleStorage := &OracleKeyVaultStorage{
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		configFileLocation:  configFileLocation,
		keyResourceName:     keyConfig.KeyId,
		oracleKMSClient:     client,
		keyConfig:           keyConfig,
	}

	oracleStorage.loadConfig()
	return oracleStorage
}

// Loads the decrypted configuration from the config file if encrypted config is present, else encrypts the config.
func (o *OracleKeyVaultStorage) loadConfig() error {
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptError bool
	var decryptData []byte

	if err := o.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(o.configFileLocation)
	if err != nil {
		logger.Errorf("Failed to load config file %s: %s", o.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", o.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Errorf("Empty config file %s", o.configFileLocation)
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		o.config = config
		if err := o.saveConfig(config); err != nil {
			logger.Errorf("Failed to save config: %v", err)
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		o.lastSavedConfigHash = o.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		keydata, err := getKeyDetails(o.keyConfig)
		if err != nil {
			return err
		}

		if keydata.KeyShape.Algorithm == keymanagement.KeyShapeAlgorithmAes {
			decryptData, err = decryptSymmetric(o.oracleKMSClient, *o.keyConfig, contents)
			if err != nil {
				decryptError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", o.configFileLocation)
			}

		} else {
			decryptData, err = decryptAsymmetric(o.oracleKMSClient, *o.keyConfig, contents)
			if err != nil {
				decryptError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", o.configFileLocation)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptError = true
			logger.Errorf("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", o.configFileLocation)
		}

		o.config = config
		o.lastSavedConfigHash = o.createHash(decryptData)
	}

	if jsonError != nil && decryptError {
		logger.Errorf("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", o.configFileLocation)
	}

	return nil
}

// Saves the encrypted updated configuration to the config file and updates the hash of the config.
func (o *OracleKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}) error {
	configJson, err := json.Marshal(o.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configHash := o.createHash(configJson)
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := o.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			o.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				o.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if configHash == o.lastSavedConfigHash {
		logger.Info("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := o.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := o.encryptConfig(configJson); err != nil {
		return err
	}

	o.lastSavedConfigHash = configHash
	return nil
}

// Creates the config file and encrypt if it is not already exist.
func (o *OracleKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(o.configFileLocation); !os.IsNotExist(err) {
		logger.Infof("Config file already exists at: %s", o.configFileLocation)
		return nil
	}

	dir := filepath.Dir(o.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := o.encryptConfig([]byte("{}")); err != nil {
		return err
	}

	logger.Infof("Config file created at: %s", o.configFileLocation)
	return nil
}

// Creates a hash of the given configuration data.
func (g *OracleKeyVaultStorage) createHash(config []byte) string {
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

// Encrypts the configuration data and writes it to the config file.
func (o *OracleKeyVaultStorage) encryptConfig(config []byte) error {
	keydata, err := getKeyDetails(o.keyConfig)
	if err != nil {
		return err
	}

	if keydata.KeyShape.Algorithm == keymanagement.KeyShapeAlgorithmAes {
		encryptedData, err := encryptSymmetric(o.oracleKMSClient, *o.keyConfig, config)
		if err != nil {
			logger.Errorf("Failed to encrypt config: %v", err)
			return err
		}
		if err := os.WriteFile(o.configFileLocation, encryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	} else {
		encryptedData, err := encryptAsymmetric(o.oracleKMSClient, *o.keyConfig, config)
		if err != nil {
			logger.Errorf("Failed to encrypt config: %v", err)
			return err
		}
		if err := os.WriteFile(o.configFileLocation, encryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	}

	return nil
}

// Update and save the config according to new Key.
func (o *OracleKeyVaultStorage) ChangeKey(updatedKeyConfig *KeyConfig) (bool, error) {
	oldKeyConfig := o.keyConfig
	oldOracleKMSClient := o.oracleKMSClient
	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(common.DefaultConfigProvider(), updatedKeyConfig.VaultManagementEndpoint)
	if err != nil {
		logger.Errorf("Failed to create Oracle KMS crypto client: %v", err)
		return false, nil
	}

	o.keyConfig = updatedKeyConfig
	o.oracleKMSClient = client
	if err := o.saveConfig(o.config); err != nil {
		o.keyConfig = oldKeyConfig
		o.oracleKMSClient = oldOracleKMSClient
		logger.Errorf("Failed to change the key to '%v' for config '%s': %v", updatedKeyConfig, o.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", o.configFileLocation, err)
	}

	return true, nil
}
