package azure

import (
	"fmt"
	"log"
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
		})
	}
	fmt.Println()
}
