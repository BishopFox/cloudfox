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
