package azure

import (
	"context"
	"fmt"
	"strings"

	armdns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
)

// DNSRecordRow represents a single row for the endpoints-dns table
type DNSRecordRow struct {
	SubscriptionID   string
	SubscriptionName string
	ResourceGroup    string
	ZoneName         string
	RecordType       string
	RecordName       string
	RecordValues     string
	Region           string
}

// ListDNSRecordsPerSubscription enumerates all DNS records in a subscription
//func ListDNSRecordsPerSubscription(ctx context.Context, subID, subName string, cred azcore.TokenCredential) ([]DNSRecordRow, error) {
//	var rows []DNSRecordRow
//	logger := internal.NewLogger()
//
//	dnsZonesClient, err := armdns.NewZonesClient(subID, cred, nil)
//	if err != nil {
//		return nil, fmt.Errorf("creating DNS zones client for %s: %w", subID, err)
//	}
//
//	pager := dnsZonesClient.NewListPager(nil)
//	for pager.More() {
//		page, err := pager.NextPage(ctx)
//		if err != nil {
//			return nil, fmt.Errorf("listing DNS zones: %w", err)
//		}
//
//		for _, zone := range page.Value {
//			if zone == nil || zone.Name == nil || zone.ID == nil {
//				continue
//			}
//
//			zoneName := *zone.Name
//			rgName := GetResourceGroupNameFromID(*zone.ID)
//
//			rsClient, err := armdns.NewRecordSetsClient(subID, cred, nil)
//			if err != nil {
//				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//					logger.ErrorM(fmt.Sprintf("[ERROR] creating record sets client: %v", err), globals.AZ_DNS_MODULE_NAME)
//				}
//				continue
//			}
//
//			rsPager := rsClient.NewListByDNSZonePager(rgName, zoneName, nil)
//			for rsPager.More() {
//				rsPage, err := rsPager.NextPage(ctx)
//				if err != nil {
//					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
//						logger.ErrorM(fmt.Sprintf("[ERROR] listing records in %s: %v", zoneName, err), globals.AZ_DNS_MODULE_NAME)
//					}
//					break
//				}
//
//				for _, record := range rsPage.Value {
//					if record == nil || record.Name == nil || record.Type == nil {
//						continue
//					}
//
//					recName := *record.Name
//					recType := string(*record.Type)
//					var recValues []string
//
//					if record.Properties != nil {
//						if record.Properties.ARecords != nil {
//							for _, a := range record.Properties.ARecords {
//								if a.IPv4Address != nil {
//									recValues = append(recValues, *a.IPv4Address)
//								}
//							}
//						}
//						if record.Properties.AaaaRecords != nil {
//							for _, aaaa := range record.Properties.AaaaRecords {
//								if aaaa.IPv6Address != nil {
//									recValues = append(recValues, *aaaa.IPv6Address)
//								}
//							}
//						}
//						if record.Properties.CnameRecord != nil && record.Properties.CnameRecord.Cname != nil {
//							recValues = append(recValues, *record.Properties.CnameRecord.Cname)
//						}
//						if record.Properties.TxtRecords != nil {
//							for _, txt := range record.Properties.TxtRecords {
//								var txtValues []string
//								for _, v := range txt.Value {
//									if v != nil {
//										txtValues = append(txtValues, *v)
//									}
//								}
//								recValues = append(recValues, strings.Join(txtValues, " "))
//							}
//						}
//
//						if record.Properties.MxRecords != nil {
//							for _, mx := range record.Properties.MxRecords {
//								recValues = append(recValues, fmt.Sprintf("%d %s", *mx.Preference, *mx.Exchange))
//							}
//						}
//					}
//
//					rows = append(rows, DNSRecordRow{
//						SubscriptionID:   subID,
//						SubscriptionName: subName,
//						ResourceGroup:    rgName,
//						ZoneName:         zoneName,
//						RecordType:       recType,
//						RecordName:       recName,
//						RecordValues:     strings.Join(recValues, ", "),
//					})
//				}
//			}
//		}
//	}
//
//	return rows, nil
//}

// ListDNSRecordsPerSubscription enumerates all DNS records in a resource group
func ListDNSRecordsPerResourceGroup(ctx context.Context, session *SafeSession, subID, subName, rgName string) ([]DNSRecordRow, error) {
	var rows []DNSRecordRow
	logger := internal.NewLogger()

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subID, err)
	}

	cred := &StaticTokenCredential{Token: token}
	dnsZonesClient, err := armdns.NewZonesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating DNS zones client for %s: %w", subID, err)
	}

	// List DNS zones only in the specified resource group
	pager := dnsZonesClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing DNS zones in RG %s: %w", rgName, err)
		}

		for _, zone := range page.Value {
			if zone == nil || zone.Name == nil {
				continue
			}

			zoneName := *zone.Name

			rsClient, err := armdns.NewRecordSetsClient(subID, cred, nil)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("[ERROR] creating record sets client: %v", err), globals.AZ_DNS_MODULE_NAME)
				}
				continue
			}

			rsPager := rsClient.NewListByDNSZonePager(rgName, zoneName, nil)
			for rsPager.More() {
				rsPage, err := rsPager.NextPage(ctx)
				if err != nil {
					if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
						logger.ErrorM(fmt.Sprintf("[ERROR] listing records in %s: %v", zoneName, err), globals.AZ_DNS_MODULE_NAME)
					}
					break
				}

				for _, record := range rsPage.Value {
					if record == nil || record.Name == nil || record.Type == nil {
						continue
					}

					recName := *record.Name
					recType := string(*record.Type)
					var recValues []string

					if record.Properties != nil {
						if record.Properties.ARecords != nil {
							for _, a := range record.Properties.ARecords {
								if a.IPv4Address != nil {
									recValues = append(recValues, *a.IPv4Address)
								}
							}
						}
						if record.Properties.AaaaRecords != nil {
							for _, aaaa := range record.Properties.AaaaRecords {
								if aaaa.IPv6Address != nil {
									recValues = append(recValues, *aaaa.IPv6Address)
								}
							}
						}
						if record.Properties.CnameRecord != nil && record.Properties.CnameRecord.Cname != nil {
							recValues = append(recValues, *record.Properties.CnameRecord.Cname)
						}
						if record.Properties.TxtRecords != nil {
							for _, txt := range record.Properties.TxtRecords {
								var txtValues []string
								for _, v := range txt.Value {
									if v != nil {
										txtValues = append(txtValues, *v)
									}
								}
								recValues = append(recValues, strings.Join(txtValues, " "))
							}
						}

						if record.Properties.MxRecords != nil {
							for _, mx := range record.Properties.MxRecords {
								recValues = append(recValues, fmt.Sprintf("%d %s", *mx.Preference, *mx.Exchange))
							}
						}
					}

					rows = append(rows, DNSRecordRow{
						SubscriptionID:   subID,
						SubscriptionName: subName,
						ResourceGroup:    rgName,
						ZoneName:         zoneName,
						RecordType:       recType,
						RecordName:       recName,
						RecordValues:     strings.Join(recValues, ", "),
						Region:           SafeStringPtr(zone.Location),
					})
				}
			}
		}
	}

	return rows, nil
}

// PrivateDNSZoneRow represents a single Private DNS Zone with its VNet links
type PrivateDNSZoneRow struct {
	SubscriptionID    string
	SubscriptionName  string
	ResourceGroup     string
	Region            string
	ZoneName          string
	RecordCount       string
	VNetLinks         string // Comma-separated list of linked VNets
	AutoRegistration  string // Enabled/Disabled
	ProvisioningState string
}

// ListPrivateDNSZonesPerResourceGroup enumerates all Private DNS zones and their VNet links in a resource group
func ListPrivateDNSZonesPerResourceGroup(ctx context.Context, session *SafeSession, subID, subName, rgName string) ([]PrivateDNSZoneRow, error) {
	var rows []PrivateDNSZoneRow
	logger := internal.NewLogger()

	token, err := session.GetTokenForResource(globals.CommonScopes[0]) // ARM scope
	if err != nil {
		return nil, fmt.Errorf("failed to get ARM token for subscription %s: %v", subID, err)
	}

	cred := &StaticTokenCredential{Token: token}
	privateDNSZonesClient, err := armprivatedns.NewPrivateZonesClient(subID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating Private DNS zones client for %s: %w", subID, err)
	}

	// List Private DNS zones only in the specified resource group
	pager := privateDNSZonesClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Private DNS zones in RG %s: %w", rgName, err)
		}

		for _, zone := range page.Value {
			if zone == nil || zone.Name == nil {
				continue
			}

			zoneName := *zone.Name
			region := SafeStringPtr(zone.Location)

			// Get record count from properties
			recordCount := "N/A"
			provisioningState := "N/A"
			if zone.Properties != nil {
				if zone.Properties.NumberOfRecordSets != nil {
					recordCount = fmt.Sprintf("%d", *zone.Properties.NumberOfRecordSets)
				}
				if zone.Properties.ProvisioningState != nil {
					provisioningState = string(*zone.Properties.ProvisioningState)
				}
			}

			// Get VNet links for this zone
			vnetLinks := []string{}
			autoReg := "Disabled"

			vnetLinkClient, err := armprivatedns.NewVirtualNetworkLinksClient(subID, cred, nil)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("[ERROR] creating VNet links client: %v", err), globals.AZ_ENDPOINTS_MODULE_NAME)
				}
			} else {
				linkPager := vnetLinkClient.NewListPager(rgName, zoneName, nil)
				for linkPager.More() {
					linkPage, err := linkPager.NextPage(ctx)
					if err != nil {
						if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
							logger.ErrorM(fmt.Sprintf("[ERROR] listing VNet links for zone %s: %v", zoneName, err), globals.AZ_ENDPOINTS_MODULE_NAME)
						}
						break
					}

					for _, link := range linkPage.Value {
						if link == nil || link.Name == nil {
							continue
						}

						linkName := *link.Name
						vnetID := "N/A"
						linkState := "N/A"

						if link.Properties != nil {
							if link.Properties.VirtualNetwork != nil && link.Properties.VirtualNetwork.ID != nil {
								vnetID = *link.Properties.VirtualNetwork.ID
								// Extract VNet name from ID
								parts := strings.Split(vnetID, "/")
								if len(parts) > 0 {
									vnetID = parts[len(parts)-1]
								}
							}

							if link.Properties.VirtualNetworkLinkState != nil {
								linkState = string(*link.Properties.VirtualNetworkLinkState)
							}

							// Check if auto-registration is enabled
							if link.Properties.RegistrationEnabled != nil && *link.Properties.RegistrationEnabled {
								autoReg = "Enabled"
							}
						}

						vnetLinks = append(vnetLinks, fmt.Sprintf("%s (%s, %s)", linkName, vnetID, linkState))
					}
				}
			}

			vnetLinksStr := "None"
			if len(vnetLinks) > 0 {
				vnetLinksStr = strings.Join(vnetLinks, "; ")
			}

			rows = append(rows, PrivateDNSZoneRow{
				SubscriptionID:    subID,
				SubscriptionName:  subName,
				ResourceGroup:     rgName,
				Region:            region,
				ZoneName:          zoneName,
				RecordCount:       recordCount,
				VNetLinks:         vnetLinksStr,
				AutoRegistration:  autoReg,
				ProvisioningState: provisioningState,
			})
		}
	}

	return rows, nil
}
