package internal

import (
	"bufio"
	"os"
)

func LoadFileLinesIntoArray(input string) []string {
	file, err := os.Open(input)
	if err != nil {
		return []string{input}
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var text []string
	for scanner.Scan() {
		text = append(text, scanner.Text())
	}

	return text
}

// Checks if element is part of array.
func Contains(element string, array []string) bool {
	for _, v := range array {
		if v == element {
			return true
		}
	}
	return false
}

func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
