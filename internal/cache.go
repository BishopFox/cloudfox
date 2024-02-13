package internal

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dominikbraun/graph"
	"github.com/patrickmn/go-cache"
)

var Cache = cache.New(120*time.Minute, 0)
var sharedLogger = TxtLogger()

func SaveCacheToFiles(directory string, accountID string) error {
	err := os.MkdirAll(directory, 0755)
	if err != nil {
		return err
	}

	for key, item := range Cache.Items() {
		// only if the key contains the accountID
		if accountID != "" && strings.Contains(key, accountID) {
			entry := cacheEntry{
				Value: item.Object,
				Exp:   item.Expiration,
			}

			jsonData, err := json.MarshalIndent(entry, "", "  ")
			if err != nil {
				return err
			}

			filename := filepath.Join(directory, key+".json")
			err = os.WriteFile(filename, jsonData, 0644)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func LoadCacheFromFiles(directory string) error {
	_, err := os.Stat(directory)
	if os.IsNotExist(err) {
		// Directory doesn't exist, skip loading cache
		return nil
	} else if err != nil {
		return err
	}

	files, err := os.ReadDir(directory)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := filepath.Join(directory, file.Name())
		jsonData, err := os.ReadFile(filename)
		if err != nil {
			return err
		}

		var entry cacheEntry
		err = json.Unmarshal(jsonData, &entry)
		if err != nil {
			return err
		}

		key := strings.TrimSuffix(file.Name(), ".json")
		Cache.Set(key, entry.Value, time.Duration(entry.Exp-time.Now().UnixNano()))
	}

	fmt.Println("Cache loaded from files.")
	return nil
}

type cacheEntry struct {
	Value interface{}
	Exp   int64
}

type CacheableAWSConfig struct {
	Region string
	//Credentials   aws.CredentialsProvider
	//ConfigSources []interface{}
}

func SaveCacheToGobFiles(directory string, accountID string) error {
	err := os.MkdirAll(directory, 0755)
	if err != nil {
		return err
	}

	for key, item := range Cache.Items() {
		// if accountID != "" && strings.Contains(key, accountID) ||
		// 	strings.Contains(key, "AWSConfigFileLoader") ||
		// 	strings.Contains(key, "GetEnabledRegions") ||
		// 	strings.Contains(key, "GetCallerIdentity") {
		// 	entry := cacheEntry{
		// 		Value: item.Object,
		// 		Exp:   item.Expiration,
		// 	}

		// only if the key contains the accountID
		if accountID != "" && strings.Contains(key, accountID) {
			entry := cacheEntry{
				Value: item.Object,
				Exp:   item.Expiration,
			}

			filename := filepath.Join(directory, key+".gob")
			file, err := os.Create(filename)
			if err != nil {
				return err
			}
			defer file.Close()

			// if config, ok := item.Object.(aws.Config); ok {
			// 	cacheableConfig := converAWSConfigToCacheableAWSConfig(config)
			// 	encoder := gob.NewEncoder(file)
			// 	err = encoder.Encode(cacheableConfig)
			// 	if err != nil {
			// 		sharedLogger.Errorf("Could not encode the following key: %s", key)
			// 		return err
			// 	}

			// } else {
			encoder := gob.NewEncoder(file)
			err = encoder.Encode(entry)
			if err != nil {
				sharedLogger.Errorf("Could not encode the following key: %s", key)
				return err
			}
			//	}
		}
	}
	return nil
}

// func converAWSConfigToCacheableAWSConfig(config aws.Config) CacheableAWSConfig {
// 	return CacheableAWSConfig{
// 		Region: config.Region,
// 		//Credentials:   config.Credentials,
// 		//ConfigSources: config.ConfigSources,
// 	}
// }

var ErrDirectoryDoesNotExist = errors.New("directory does not exist")

func LoadCacheFromGobFiles(directory string) error {
	_, err := os.Stat(directory)
	if os.IsNotExist(err) {
		// Directory doesn't exist, skip loading cache
		return ErrDirectoryDoesNotExist
	} else if err != nil {
		return err
	}

	files, err := os.ReadDir(directory)

	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// if the filetype is json, skip it
		if filepath.Ext(file.Name()) == ".json" {
			continue
		}

		filename := filepath.Join(directory, file.Name())
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		var entry cacheEntry
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(&entry)
		if err != nil {
			sharedLogger.Errorf("Could not decode the following file: %s", filename)
			continue
		}

		// the key should remove the directory and the .json suffix from the filename and also trim the first slash
		key := strings.TrimSuffix(strings.TrimPrefix(filename, directory), ".gob")[1:]

		Cache.Set(key, entry.Value, time.Duration(entry.Exp-time.Now().UnixNano()))
	}

	//fmt.Println("Cache loaded from files.")
	return nil
}

func SaveGraphToGob[K comparable, T any](directory string, name string, g *graph.Graph[K, T]) error {
	err := os.MkdirAll(directory, 0755)
	if err != nil {
		return err
	}

	filename := filepath.Join(directory, name+".gob")
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(g)
	if err != nil {
		sharedLogger.Errorf("Could not encode the following graph: %s", name)
		return err

	}
	return nil
}
