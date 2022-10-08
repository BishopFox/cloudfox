package azure

import (
	"context"

	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/smithy-go/ptr"
)

func ListSubscriptions() ([]string, error) {
	var subs []string
	subsClient, err := utils.GetSubscriptionsClient()
	if err != nil {
		return subs, err
	}
	for page, err := subsClient.List(context.TODO()); page.NotDone(); err = page.Next() {
		if err != nil {
			return subs, err
		}
		for _, sub := range page.Values() {
			subs = append(subs, ptr.ToString(sub.SubscriptionID))
		}
	}
	return subs, nil
}

func ListResourceGroups(subscription string) ([]string, error) {
	var resourceGroups []string
	rgClient, err := utils.GetResourceGroupsClient(subscription)
	if err != nil {
		return resourceGroups, err
	}
	for page, err := rgClient.List(context.TODO(), "", nil); page.NotDone(); err = page.Next() {
		if err != nil {
			return resourceGroups, err
		}
		for _, rg := range page.Values() {
			if rg.Name != nil {
				resourceGroups = append(resourceGroups, ptr.ToString(rg.Name))
			}
		}
	}
	return resourceGroups, nil
}
