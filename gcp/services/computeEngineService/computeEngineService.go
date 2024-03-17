package computeengineservice

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/compute/v1"
)

type ComputeEngineService struct {
	// DataStoreService datastoreservice.DataStoreService
}

func New() *ComputeEngineService {
	return &ComputeEngineService{}
}

type ComputeEngineInfo struct {
	Name              string
	ID                string
	Zone              string
	State             string
	ExternalIP        string
	InternalIP        string
	ServiceAccounts   []*compute.ServiceAccount // Assuming role is derived from service accounts
	NetworkInterfaces []*compute.NetworkInterface
	Tags              *compute.Tags
	ProjectID         string
}

// Retrieves instances from all regions and zones for a project without using concurrency.
func (ces *ComputeEngineService) Instances(projectID string) ([]ComputeEngineInfo, error) {
	ctx := context.Background()
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}

	regions, err := computeService.Regions.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	var instanceInfos []ComputeEngineInfo
	for _, region := range regions.Items {
		for _, zoneURL := range region.Zones {
			zone := getZoneNameFromURL(zoneURL)
			instanceList, err := computeService.Instances.List(projectID, zone).Do()
			if err != nil {
				return nil, fmt.Errorf("error retrieving instances from zone %s: %v", zone, err)
			}
			for _, instance := range instanceList.Items {
				info := ComputeEngineInfo{
					Name:              instance.Name,
					ID:                fmt.Sprintf("%v", instance.Id),
					Zone:              zoneURL,
					State:             instance.Status,
					ExternalIP:        getExternalIP(instance),
					InternalIP:        getInternalIP(instance),
					ServiceAccounts:   instance.ServiceAccounts,
					NetworkInterfaces: instance.NetworkInterfaces,
					Tags:              instance.Tags,
					ProjectID:         projectID,
				}
				instanceInfos = append(instanceInfos, info)
			}
		}
	}
	return instanceInfos, nil
}

// Returns the zone from a GCP URL string with the zone in it
func getZoneNameFromURL(zoneURL string) string {
	splits := strings.Split(zoneURL, "/")
	return splits[len(splits)-1]
}

// getExternalIP extracts the external IP address from an instance if available.
func getExternalIP(instance *compute.Instance) string {
	for _, iface := range instance.NetworkInterfaces {
		for _, accessConfig := range iface.AccessConfigs {
			if accessConfig.NatIP != "" {
				return accessConfig.NatIP
			}
		}
	}
	return ""
}

// getInternalIP extracts the internal IP address from an instance.
func getInternalIP(instance *compute.Instance) string {
	if len(instance.NetworkInterfaces) > 0 {
		return instance.NetworkInterfaces[0].NetworkIP
	}
	return ""
}

// TODO consider just getting the emails of the service account and returning a []string
