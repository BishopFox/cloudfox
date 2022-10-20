package azure

import (
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestScopeSelection(t *testing.T) {
	//t.Skip()
	subtests := []struct {
		name              string
		getAvailableScope func() map[int]string
		userInput         string
		expectedResult    []string
	}{
		{
			name: "subtest 1",
			getAvailableScope: func() map[int]string {
				return map[int]string{
					1: "A1",
					2: "A2",
					3: "B3",
					4: "B4",
					5: "C5",
					6: "C6",
				}
			},
			userInput:      "2,3,6",
			expectedResult: []string{"A2", "B3", "C6"},
		},
	}
	fmt.Println()
	fmt.Println("[test case] scopeSelection")
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			getAvailableScopeM = subtest.getAvailableScope
			scope := ScopeSelection(subtest.userInput)
			for i, selection := range scope {
				if selection != subtest.expectedResult[i] {
					log.Fatalf("[%s] expected %s, got %s", subtest.name, subtest.expectedResult[i], selection)
				}
			}
			log.Printf("[%s] simulated user input of %s matches expected selection of %s", subtest.name, subtest.userInput, strings.Join(subtest.expectedResult, ","))
		})
	}
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
