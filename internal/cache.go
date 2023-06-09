package internal

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

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
			err = ioutil.WriteFile(filename, jsonData, 0644)
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

	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := filepath.Join(directory, file.Name())
		jsonData, err := ioutil.ReadFile(filename)
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

func SaveCacheToGobFiles(directory string, accountID string) error {
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

			filename := filepath.Join(directory, key+".gob")
			file, err := os.Create(filename)
			if err != nil {
				return err
			}
			defer file.Close()

			encoder := gob.NewEncoder(file)
			err = encoder.Encode(entry)
			if err != nil {
				sharedLogger.Errorf("Could not encode the following key: %s", key)
				return err
			}
		}
	}
	return nil
}

var ErrDirectoryDoesNotExist = errors.New("directory does not exist")

func LoadCacheFromGobFiles(directory string) error {
	_, err := os.Stat(directory)
	if os.IsNotExist(err) {
		// Directory doesn't exist, skip loading cache
		return ErrDirectoryDoesNotExist
	} else if err != nil {
		return err
	}

	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
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
			return err
		}

		// the key should remove the directory and the .json suffix from the filename and also trim the first slash
		key := strings.TrimSuffix(strings.TrimPrefix(filename, directory), ".gob")[1:]

		Cache.Set(key, entry.Value, time.Duration(entry.Exp-time.Now().UnixNano()))
	}

	//fmt.Println("Cache loaded from files.")
	return nil
}
