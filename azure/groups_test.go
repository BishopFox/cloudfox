package azure

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"testing"
)

func TestListSubscriptions(t *testing.T) {
	subs, err := ListSubscriptions()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Available Subscriptions:")
	for _, sub := range subs {
		log.Println(sub)
	}
	fmt.Println()
}

func TestListResourceGroups(t *testing.T) {
	subscription := "11111111-1111-1111-1111-11111111"
	rgs, err := ListResourceGroups(subscription)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Available RGs for Subscription %s:", subscription)
	for _, rg := range rgs {
		log.Println(rg)
	}
	fmt.Println()
}

func TestPrintAvailableScope(t *testing.T) {
	subtests := []struct {
		name               string
		ListSubscriptions  func() ([]string, error)
		ListResourceGroups func(subscription string) ([]string, error)
	}{
		{
			name: "SubTest: multiple subs, multiple resource groups",
			ListSubscriptions: func() ([]string, error) {
				return []string{
					"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
					"BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
					"CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
				}, nil
			},
			ListResourceGroups: func(s string) ([]string, error) {
				switch s {
				case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
					return []string{"A1", "A2", "A3"}, nil
				case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
					return []string{"B1", "B2", "B3"}, nil
				case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
					return []string{"C1", "C2", "C3"}, nil
				}
				return []string{}, fmt.Errorf("no resource groups found for subscription: %s", s)
			},
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			log.Println(subtest.name)
			ListSubscriptions = subtest.ListSubscriptions
			ListResourceGroups = subtest.ListResourceGroups
			menu, err := PrintAvailableScope()
			if err != nil {
				log.Println(err)
			}
			log.Println(menu)
			fmt.Println()
		})
	}
}

func TestScopeSelection(t *testing.T) {
	subtests := []struct {
		name               string
		ListSubscriptions  func() ([]string, error)
		ListResourceGroups func(subscription string) ([]string, error)
		userInput          string
		expectedResult     []string
	}{
		{
			name: "SubTest 1",
			ListSubscriptions: func() ([]string, error) {
				return []string{
					"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
					"BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
					"CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
				}, nil
			},
			ListResourceGroups: func(s string) ([]string, error) {
				switch s {
				case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
					return []string{"A1", "A2", "A3"}, nil
				case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
					return []string{"B4", "B5", "B6"}, nil
				case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
					return []string{"C7", "C8", "C9"}, nil
				}
				return []string{}, fmt.Errorf("no resource groups found for subscription: %s", s)
			},
			userInput:      "2,3,8",
			expectedResult: []string{"A2", "A3", "C8"},
		},
		{
			name: "SubTest 2",
			ListSubscriptions: func() ([]string, error) {
				return []string{
					"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
					"BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB",
					"CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC",
				}, nil
			},
			ListResourceGroups: func(s string) ([]string, error) {
				switch s {
				case "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA":
					return []string{"A1", "A2", "A3"}, nil
				case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
					return []string{"B4", "B5", "B6"}, nil
				case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
					return []string{"C7", "C8", "C9"}, nil
				}
				return []string{}, fmt.Errorf("no resource groups found for subscription: %s", s)
			},
			userInput:      "1",
			expectedResult: []string{"A1"},
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			log.Println(subtest.name)
			ListSubscriptions = subtest.ListSubscriptions
			ListResourceGroups = subtest.ListResourceGroups
			results, err := ScopeSelection(subtest.userInput)
			if err != nil {
				log.Println(err)
			}
			for i, r := range results {
				if r != subtest.expectedResult[i] {
					log.Fatalf(
						"Expected result: %s, got %s",
						strings.Join(subtest.expectedResult, ","),
						strings.Join(results, ","),
					)
				}
			}
			log.Printf("Mocked user input: %s", subtest.userInput)
			log.Printf("Matches expected result of: %s", strings.Join(results, ","))
			fmt.Println()
		})
	}
}

func ScopeSelection(userInput string) ([]string, error) {
	menu, err := PrintAvailableScope()
	if err != nil {
		log.Println(err)
	}
	var scope []string
	for _, input := range strings.Split(userInput, ",") {
		inputInt, err := strconv.Atoi(input)
		if err != nil {
			return scope, err
		}
		scope = append(scope, menu[int(inputInt)])
	}
	return scope, nil
}
