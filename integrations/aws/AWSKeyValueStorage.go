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
}

func NewAWSKeyValueStorage(configFileLocation string, KeyARN string, awsSessionConfig *AWSConfig) *AWSKeyVaultStorage {
	if configFileLocation == "" {
		configFileLocation = os.Getenv("KSM_CONFIG_FILE")
		if configFileLocation == "" {
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
	}

	keyData, err := awsDetails.GetKeyDetails()
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

func getConfig(awsSessionConfig *AWSConfig) (*aws.Config, error) {
	if awsSessionConfig.ClientID != "" && awsSessionConfig.ClientSecret != "" && awsSessionConfig.Region != "" {
		return &aws.Config{
			Credentials: credentials.NewStaticCredentialsProvider(awsSessionConfig.ClientID, awsSessionConfig.ClientSecret, ""),
			Region:      awsSessionConfig.Region,
		}, nil
	}
	return nil, fmt.Errorf("AWS ClientID, ClientSecret or Region is missing")
}

func (a *AWSKeyVaultStorage) loadConfig() error {
	if err := a.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(a.configFileLocation)
	if err != nil {
		logger.Errorf("Failed to load config file %s: %s", a.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", a.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Error("Empty config file %s", a.configFileLocation)
		contents = []byte("{}")
	}

	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool
	var decryptData []byte

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
		keydata, err := a.GetKeyDetails()
		if err != nil {
		}

		if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
			decryptData, err = decryptSymmetric(a.kmsClient, a.keyARN, contents)
			if err != nil {
				decryptionError = true
				logger.Error("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
			}
		} else {
			decryptData, err = decryptAsymmetric(a.kmsClient, a.keyARN, contents)
			if err != nil {
				decryptionError = true
				logger.Error("Failed to decrypt config file: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptionError = true
			logger.Error("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", a.configFileLocation)
		}

		a.config = config
		a.lastSavedConfigHash = a.createHash(decryptData)
	}

	if jsonError != nil && decryptionError {
		logger.Error("Config file is not a valid JSON file: %s", jsonError.Error())
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

	keydata, err := a.GetKeyDetails()
	if err != nil {
		return err
	}

	var blob []byte
	if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
		blob, err = encryptSymmetric(a.kmsClient, a.keyARN, configJson)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
	} else if keydata.KeyMetadata.KeySpec == types.KeySpecRsa2048 || keydata.KeyMetadata.KeySpec == types.KeySpecRsa3072 || keydata.KeyMetadata.KeySpec == types.KeySpecRsa4096 {
		blob, err = encryptAsymmetric(a.kmsClient, a.keyARN, configJson)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
	}

	if err := os.WriteFile(a.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", a.configFileLocation, err)
	}

	a.lastSavedConfigHash = configHash
	return nil
}

func (a *AWSKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(a.configFileLocation); os.IsNotExist(err) {
		dir := filepath.Dir(a.configFileLocation)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}

		keydata, err := a.GetKeyDetails()
		if err != nil {
			return err
		}

		var blob []byte
		if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
			blob, err = encryptSymmetric(a.kmsClient, a.keyARN, []byte("{}"))
			if err != nil {
				return fmt.Errorf("failed to encrypt config: %w", err)
			}
		} else if keydata.KeyMetadata.KeySpec == types.KeySpecRsa2048 || keydata.KeyMetadata.KeySpec == types.KeySpecRsa3072 || keydata.KeyMetadata.KeySpec == types.KeySpecRsa4096 {
			blob, err = encryptAsymmetric(a.kmsClient, a.keyARN, []byte("{}"))
			if err != nil {
				return fmt.Errorf("failed to encrypt config: %w", err)
			}
		}

		if err := os.WriteFile(a.configFileLocation, blob, 0644); err != nil {
			return fmt.Errorf("failed to write config file %s: %w", a.configFileLocation, err)
		}

		fmt.Println("Config file created at:", a.configFileLocation)
	} else {
		fmt.Println("Config file already exists at:", a.configFileLocation)
	}

	return nil
}

func (a *AWSKeyVaultStorage) GetKeyDetails() (*kms.DescribeKeyOutput, error) {
	keyDetails, err := a.kmsClient.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: &a.keyARN,
	})
	if err != nil {
		logger.Error("Failed to get key details: %v", err)
		return nil, fmt.Errorf("failed to get key details: %v", err)
	}
	return keyDetails, nil
}

func (s *AWSKeyVaultStorage) createHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}
