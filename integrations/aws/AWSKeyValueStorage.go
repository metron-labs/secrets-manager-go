package awskv

import (
	"awskv/aws/logger"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/keeper-security/secrets-manager-go/core"
)

type AWSConfig struct {
	ClientID     string
	ClientSecret string
	Region       string
}

type AWSKeyVaultStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	kmsClient           *kms.Client
	keyARN              string
	awsConfig           *AWSConfig
}

func NewAWSKeyValueStorage(configFileLocation string, KeyARN string, awsSessionConfig *AWSConfig) *AWSKeyVaultStorage {
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	cfg, err := getConfig(awsSessionConfig)
	if err != nil {
		return nil
	}

	if KeyARN == "" {
		logger.Errorf("Failed to create client secret credential: %v", err)
		return nil
	}

	client := kms.NewFromConfig(*cfg)
	awsDetails := &AWSKeyVaultStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		kmsClient:           client,
		keyARN:              KeyARN,
		awsConfig:           awsSessionConfig,
	}

	keyData, err := awsDetails.getKeyDetails()
	if err != nil && keyData.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		logger.Errorf("Failed to create client secret credential: %v", err)
		return nil
	}

	err = awsDetails.loadConfig()
	if err != nil {
		return nil
	}
	return awsDetails
}

func (a *AWSKeyVaultStorage) loadConfig() error {
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool
	var decryptData []byte

	if err := a.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(a.configFileLocation)
	if err != nil {
		logger.Errorf("Failed to load config file %s: %s", a.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", a.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Errorf("Empty config file %s", a.configFileLocation)
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		a.config = config
		if err := a.saveConfig(config); err != nil {
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		a.lastSavedConfigHash = a.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		keydata, err := a.getKeyDetails()
		if err != nil {
		}

		if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
			decryptData, err = decryptSymmetric(a.kmsClient, a.keyARN, contents)
			if err != nil {
				decryptionError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
			}
		} else {
			decryptData, err = decryptAsymmetric(a.kmsClient, a.keyARN, contents)
			if err != nil {
				decryptionError = true
				logger.Errorf("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptionError = true
			logger.Errorf("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", a.configFileLocation)
		}

		a.config = config
		a.lastSavedConfigHash = a.createHash(decryptData)
	}

	if jsonError != nil && decryptionError {
		logger.Errorf("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", a.configFileLocation)
	}

	return nil
}

func (a *AWSKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}) error {
	configJson, err := json.Marshal(a.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configHash := a.createHash(configJson)
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := a.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			a.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				a.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if configHash == a.lastSavedConfigHash {
		fmt.Println("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := a.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := a.encryptConfig(configJson); err != nil {
		return err
	}

	a.lastSavedConfigHash = configHash
	return nil
}

func (a *AWSKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(a.configFileLocation); !os.IsNotExist(err) {
		logger.Infof("Config file already exists at: %s", a.configFileLocation)
		return nil
	}

	dir := filepath.Dir(a.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := a.encryptConfig([]byte("{}")); err != nil {
		return err
	}

	logger.Infof("Config file created at: %s", a.configFileLocation)
	return nil
}

func (a *AWSKeyVaultStorage) getKeyDetails() (*kms.DescribeKeyOutput, error) {
	keyDetails, err := a.kmsClient.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: &a.keyARN,
	})

	if err != nil {
		logger.Errorf("Failed to get key details: %v", err)
		return nil, fmt.Errorf("failed to get key details: %w", err)
	}

	return keyDetails, nil
}

func (a *AWSKeyVaultStorage) createHash(config []byte) string {
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

func getConfig(awsSessionConfig *AWSConfig) (*aws.Config, error) {
	if awsSessionConfig.ClientID != "" && awsSessionConfig.ClientSecret != "" && awsSessionConfig.Region != "" {
		return &aws.Config{
			Credentials: credentials.NewStaticCredentialsProvider(awsSessionConfig.ClientID, awsSessionConfig.ClientSecret, ""),
			Region:      awsSessionConfig.Region,
		}, nil
	} else {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to load default config: %w", err)
		}
		return &cfg, nil
	}
}

func (a *AWSKeyVaultStorage) encryptConfig(config []byte) error {
	keydata, err := a.getKeyDetails()
	if err != nil {
		return err
	}

	var blob []byte
	if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
		blob, err = encryptSymmetric(a.kmsClient, a.keyARN, config)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
	} else {
		blob, err = encryptAsymmetric(a.kmsClient, a.keyARN, config)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
	}

	if err := os.WriteFile(a.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", a.configFileLocation, err)
	}

	logger.Debug("Config file created at: ", a.configFileLocation)
	return nil
}

func (a *AWSKeyVaultStorage) changeKey(newKeyARN string) (bool, error) {
	oldKeyARN := a.keyARN
	oldKMSClient := a.kmsClient
	config, err := getConfig(a.awsConfig)
	if err != nil {
		return false, fmt.Errorf("failed to get config: %w", err)
	}

	client := kms.NewFromConfig(*config)
	a.kmsClient = client
	a.keyARN = newKeyARN
	if err := a.saveConfig(a.config); err != nil {
		a.kmsClient = oldKMSClient
		a.keyARN = oldKeyARN
		logger.Errorf("Failed to change the key to '%s' for config '%s': %v", newKeyARN, a.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", a.configFileLocation, err)
	}

	return true, nil
}
