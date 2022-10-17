package azure

import (
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestListSubscriptions(t *testing.T) {
	t.Skip()
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
	t.Skip()
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

func TestGetAvailableScope(t *testing.T) {
	// t.Skip()
	subtests := []struct {
		name               string
		expectedMenu       map[int]string
		ListSubscriptions  func() ([]string, error)
		ListResourceGroups func(subscription string) ([]string, error)
	}{
		{
			name: "subtest 1",
			expectedMenu: map[int]string{
				1: "A1",
				2: "A2",
				3: "B3",
				4: "B4",
				5: "C5",
				6: "C6",
			},
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
					return []string{"A1", "A2"}, nil
				case "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBB":
					return []string{"B3", "B4"}, nil
				case "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCC":
					return []string{"C5", "C6"}, nil
				}
				return []string{}, fmt.Errorf("no resource groups found for subscription: %s", s)
			},
		},
	}
	fmt.Println()
	fmt.Println("[test case] getAvailableScope")
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			ListSubscriptions = subtest.ListSubscriptions
			ListResourceGroups = subtest.ListResourceGroups
			menu := getAvailableScope()
			for i, expected := range subtest.expectedMenu {
				if menu[i] != expected {
					log.Fatalf("[%s] expected result: %s, got %s", subtest.name, menu[i], expected)
				}
			}
		})
	}
	fmt.Println()
}

func TestScopeSelection(t *testing.T) {
	t.Skip()
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
	fmt.Println()
	fmt.Println("[test case] scopeSelection")
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			ListSubscriptions = subtest.ListSubscriptions
			ListResourceGroups = subtest.ListResourceGroups
			results := ScopeSelection(subtest.userInput)
			for i, r := range results {
				if r != subtest.expectedResult[i] {
					log.Fatalf(
						"[%s] expected result: %s, got %s",
						subtest.name,
						strings.Join(subtest.expectedResult, ","),
						strings.Join(results, ","),
					)
				}
			}
			log.Printf("[%s] mocked user input of %s matches expected selection\n", subtest.name, subtest.userInput)
		})
	}
}
