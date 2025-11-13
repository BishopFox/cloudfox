package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzLoadBalancersCommand = &cobra.Command{
	Use:     "load-balancers",
	Aliases: []string{"lbs", "loadbalancers"},
	Short:   "Enumerate Azure Load Balancers",
	Long: `
Enumerate Azure Load Balancers for a specific tenant:
./cloudfox az load-balancers --tenant TENANT_ID

Enumerate Azure Load Balancers for a specific subscription:
./cloudfox az load-balancers --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

This module analyzes Azure Load Balancers to identify:
- Public vs Private load balancers
- Frontend IP configurations (public exposure)
- Backend pool resources (target VMs/services)
- Load balancing rules (protocol/port mappings)
- NAT rules (port forwarding that could expose internal services)
- Health probe configurations
- DDoS protection status (Standard SKU only)`,
	Run: ListLoadBalancers,
}

// ------------------------------
// Module struct
// ------------------------------
type LoadBalancersModule struct {
	azinternal.BaseAzureModule

	Subscriptions     []string
	LoadBalancerRows  [][]string
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type LoadBalancersOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LoadBalancersOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LoadBalancersOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListLoadBalancers(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_LOAD_BALANCERS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &LoadBalancersModule{
		BaseAzureModule:  azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:    cmdCtx.Subscriptions,
		LoadBalancerRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"load-balancer-commands":      {Name: "load-balancer-commands", Contents: ""},
			"load-balancer-nat-rules":     {Name: "load-balancer-nat-rules", Contents: "# Azure Load Balancer NAT Rules (Port Forwarding)\n\n"},
			"load-balancer-public-ips":    {Name: "load-balancer-public-ips", Contents: "# Public-Facing Load Balancers\n\n"},
			"load-balancer-target-scans":  {Name: "load-balancer-target-scans", Contents: "# Targeted Scanning Commands for Load Balancer Services\n\n"},
		},
	}

	module.PrintLoadBalancers(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *LoadBalancersModule) PrintLoadBalancers(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_LOAD_BALANCERS_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			// Save current tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Set tenant context for this iteration
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_LOAD_BALANCERS_MODULE_NAME, m.processSubscription)

			// Restore original tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_LOAD_BALANCERS_MODULE_NAME, m.processSubscription)
	}

	// Generate loot files
	m.generateTargetedScanningLoot()

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *LoadBalancersModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *LoadBalancersModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	// Get load balancers
	lbs, err := azinternal.ListLoadBalancers(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, lb := range lbs {
		m.processLoadBalancer(ctx, lb, subID, subName, rgName, region)
	}
}

// ------------------------------
// Process individual load balancer
// ------------------------------
func (m *LoadBalancersModule) processLoadBalancer(ctx context.Context, lb *armnetwork.LoadBalancer, subID, subName, rgName, region string) {
	if lb == nil || lb.Name == nil {
		return
	}

	lbName := *lb.Name

	// Extract SKU
	sku := "Basic"
	if lb.SKU != nil && lb.SKU.Name != nil {
		sku = string(*lb.SKU.Name)
	}

	// Extract Tags
	tags := "N/A"
	if lb.Tags != nil && len(lb.Tags) > 0 {
		var tagPairs []string
		for k, v := range lb.Tags {
			if v != nil {
				tagPairs = append(tagPairs, fmt.Sprintf("%s:%s", k, *v))
			} else {
				tagPairs = append(tagPairs, k)
			}
		}
		if len(tagPairs) > 0 {
			tags = strings.Join(tagPairs, ", ")
		}
	}

	// Determine if public or private based on frontend IP configurations
	frontendIPs := []string{}
	isPublic := false
	publicIPIDs := []string{}

	if lb.Properties != nil && lb.Properties.FrontendIPConfigurations != nil {
		for _, frontend := range lb.Properties.FrontendIPConfigurations {
			if frontend.Properties != nil {
				// Check for public IP
				if frontend.Properties.PublicIPAddress != nil && frontend.Properties.PublicIPAddress.ID != nil {
					isPublic = true
					publicIPIDs = append(publicIPIDs, *frontend.Properties.PublicIPAddress.ID)

					// Resolve public IP address
					publicIP := azinternal.GetPublicIPAddressByID(ctx, m.Session, subID, *frontend.Properties.PublicIPAddress.ID)
					if publicIP != "" {
						frontendIPs = append(frontendIPs, publicIP)
					}
				}

				// Check for private IP
				if frontend.Properties.PrivateIPAddress != nil {
					frontendIPs = append(frontendIPs, *frontend.Properties.PrivateIPAddress)
				}
			}
		}
	}

	frontendIPsStr := "None"
	if len(frontendIPs) > 0 {
		frontendIPsStr = strings.Join(frontendIPs, ", ")
	}

	exposureType := "Private"
	if isPublic {
		exposureType = "⚠ Public (Internet-Facing)"
	}

	// Extract backend pools
	backendPools := []string{}
	backendPoolCount := 0
	if lb.Properties != nil && lb.Properties.BackendAddressPools != nil {
		backendPoolCount = len(lb.Properties.BackendAddressPools)
		for _, pool := range lb.Properties.BackendAddressPools {
			if pool.Name != nil {
				backendPools = append(backendPools, *pool.Name)
			}
		}
	}
	backendPoolsStr := fmt.Sprintf("%d pool(s)", backendPoolCount)
	if len(backendPools) > 0 {
		backendPoolsStr = fmt.Sprintf("%d: %s", backendPoolCount, strings.Join(backendPools, ", "))
	}

	// Extract load balancing rules
	lbRules := []string{}
	if lb.Properties != nil && lb.Properties.LoadBalancingRules != nil {
		for _, rule := range lb.Properties.LoadBalancingRules {
			if rule.Properties != nil && rule.Name != nil {
				protocol := "N/A"
				if rule.Properties.Protocol != nil {
					protocol = string(*rule.Properties.Protocol)
				}

				frontendPort := "N/A"
				if rule.Properties.FrontendPort != nil {
					frontendPort = fmt.Sprintf("%d", *rule.Properties.FrontendPort)
				}

				backendPort := "N/A"
				if rule.Properties.BackendPort != nil {
					backendPort = fmt.Sprintf("%d", *rule.Properties.BackendPort)
				}

				lbRules = append(lbRules, fmt.Sprintf("%s: %s %s→%s", *rule.Name, protocol, frontendPort, backendPort))
			}
		}
	}
	lbRulesStr := "None"
	if len(lbRules) > 0 {
		lbRulesStr = strings.Join(lbRules, "; ")
	}

	// Extract NAT rules (inbound NAT rules expose internal services)
	natRules := []string{}
	hasRiskyNAT := false
	if lb.Properties != nil && lb.Properties.InboundNatRules != nil {
		for _, natRule := range lb.Properties.InboundNatRules {
			if natRule.Properties != nil && natRule.Name != nil {
				protocol := "N/A"
				if natRule.Properties.Protocol != nil {
					protocol = string(*natRule.Properties.Protocol)
				}

				frontendPort := "N/A"
				if natRule.Properties.FrontendPort != nil {
					frontendPort = fmt.Sprintf("%d", *natRule.Properties.FrontendPort)
				}

				backendPort := "N/A"
				if natRule.Properties.BackendPort != nil {
					backendPort = fmt.Sprintf("%d", *natRule.Properties.BackendPort)
				}

				natRules = append(natRules, fmt.Sprintf("%s: %s %s→%s", *natRule.Name, protocol, frontendPort, backendPort))

				// Flag risky ports (SSH, RDP, etc.)
				if natRule.Properties.BackendPort != nil {
					port := *natRule.Properties.BackendPort
					if port == 22 || port == 3389 || port == 445 || port == 3306 || port == 5432 || port == 1433 {
						hasRiskyNAT = true
					}
				}
			}
		}
	}
	natRulesStr := "None"
	natRiskIndicator := "✓ No NAT"
	if len(natRules) > 0 {
		natRulesStr = strings.Join(natRules, "; ")
		if hasRiskyNAT {
			natRiskIndicator = "⚠ RISKY (SSH/RDP/DB exposed)"
		} else {
			natRiskIndicator = "⚠ NAT Rules Present"
		}
	}

	// Extract health probes
	healthProbes := []string{}
	if lb.Properties != nil && lb.Properties.Probes != nil {
		for _, probe := range lb.Properties.Probes {
			if probe.Properties != nil && probe.Name != nil {
				protocol := "N/A"
				if probe.Properties.Protocol != nil {
					protocol = string(*probe.Properties.Protocol)
				}

				port := "N/A"
				if probe.Properties.Port != nil {
					port = fmt.Sprintf("%d", *probe.Properties.Port)
				}

				interval := "N/A"
				if probe.Properties.IntervalInSeconds != nil {
					interval = fmt.Sprintf("%ds", *probe.Properties.IntervalInSeconds)
				}

				healthProbes = append(healthProbes, fmt.Sprintf("%s: %s port %s (interval: %s)", *probe.Name, protocol, port, interval))
			}
		}
	}
	healthProbesStr := "None"
	if len(healthProbes) > 0 {
		healthProbesStr = strings.Join(healthProbes, "; ")
	}

	// DDoS protection (only available for Standard SKU with public IPs)
	ddosProtection := "N/A"
	if sku == "Standard" && isPublic {
		// DDoS Standard protection would be configured on the VNet or Public IP
		// For now, indicate that it's possible
		ddosProtection = "Available (check VNet/Public IP)"
	} else if isPublic {
		ddosProtection = "⚠ Not Available (Basic SKU)"
	}

	// Zone redundancy
	zones := "N/A"
	// Note: Zones field not available in current SDK version
	// TODO: Add zone detection when SDK supports it

	// Build loot entries for public load balancers with NAT rules
	if isPublic && len(natRules) > 0 {
		m.mu.Lock()
		m.LootMap["load-balancer-nat-rules"].Contents += fmt.Sprintf(
			"## Load Balancer: %s (Subscription: %s, Resource Group: %s)\n"+
				"Frontend IPs: %s\n"+
				"NAT Rules:\n%s\n\n",
			lbName, subName, rgName, frontendIPsStr,
			strings.ReplaceAll(natRulesStr, "; ", "\n"),
		)
		m.mu.Unlock()
	}

	// Build loot entry for public IPs
	if isPublic {
		m.mu.Lock()
		m.LootMap["load-balancer-public-ips"].Contents += fmt.Sprintf(
			"%s | %s | %s | %s\n",
			lbName, subName, rgName, frontendIPsStr,
		)
		m.mu.Unlock()
	}

	// Thread-safe append
	m.mu.Lock()
	m.LoadBalancerRows = append(m.LoadBalancerRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		lbName,
		sku,
		exposureType,
		frontendIPsStr,
		backendPoolsStr,
		lbRulesStr,
		natRulesStr,
		natRiskIndicator,
		healthProbesStr,
		ddosProtection,
		zones,
		tags,
	})
	m.mu.Unlock()
}

// ------------------------------
// Generate targeted scanning loot
// ------------------------------
func (m *LoadBalancersModule) generateTargetedScanningLoot() {
	// Generate scanning commands for public load balancers
	publicLBs := make(map[string][]string) // map[frontendIP][]services

	for _, row := range m.LoadBalancerRows {
		if len(row) < 14 {
			continue
		}

		exposureType := row[8]
		frontendIPs := row[9]
		lbRules := row[11]
		natRules := row[12]

		// Only process public load balancers
		if !strings.Contains(exposureType, "Public") {
			continue
		}

		// Parse frontend IPs
		ips := strings.Split(frontendIPs, ", ")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip == "" || ip == "None" {
				continue
			}

			// Extract ports from LB rules and NAT rules
			services := []string{}

			// Parse LB rules for ports
			if lbRules != "None" {
				rules := strings.Split(lbRules, "; ")
				for _, rule := range rules {
					// Format: "RuleName: Protocol Port→Port"
					if strings.Contains(rule, "→") {
						parts := strings.Split(rule, " ")
						for _, part := range parts {
							if strings.Contains(part, "→") {
								portParts := strings.Split(part, "→")
								if len(portParts) > 0 {
									services = append(services, portParts[0])
								}
							}
						}
					}
				}
			}

			// Parse NAT rules for ports
			if natRules != "None" {
				rules := strings.Split(natRules, "; ")
				for _, rule := range rules {
					if strings.Contains(rule, "→") {
						parts := strings.Split(rule, " ")
						for _, part := range parts {
							if strings.Contains(part, "→") {
								portParts := strings.Split(part, "→")
								if len(portParts) > 0 {
									services = append(services, portParts[0])
								}
							}
						}
					}
				}
			}

			if len(services) > 0 {
				publicLBs[ip] = services
			}
		}
	}

	if len(publicLBs) == 0 {
		return
	}

	lf := m.LootMap["load-balancer-target-scans"]
	lf.Contents += "# Public Load Balancer Scanning Commands\n"
	lf.Contents += "# These commands target services exposed through Azure Load Balancers\n\n"

	for ip, services := range publicLBs {
		lf.Contents += fmt.Sprintf("## Load Balancer Frontend IP: %s\n", ip)
		lf.Contents += fmt.Sprintf("# Exposed ports: %s\n", strings.Join(services, ", "))
		lf.Contents += fmt.Sprintf("# Quick port scan\n")
		lf.Contents += fmt.Sprintf("nmap -Pn -sV -p %s %s\n\n", strings.Join(services, ","), ip)
		lf.Contents += fmt.Sprintf("# Full service enumeration\n")
		lf.Contents += fmt.Sprintf("nmap -Pn -sV -sC -p %s %s -oA lb_%s_scan\n\n", strings.Join(services, ","), ip, strings.ReplaceAll(ip, ".", "_"))
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *LoadBalancersModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.LoadBalancerRows) == 0 {
		logger.InfoM("No load balancers found", globals.AZ_LOAD_BALANCERS_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Load Balancer Name",
		"SKU",
		"Exposure Type",
		"Frontend IPs",
		"Backend Pools",
		"Load Balancing Rules",
		"NAT Rules",
		"NAT Risk Level",
		"Health Probes",
		"DDoS Protection",
		"Availability Zones",
		"Tags",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.LoadBalancerRows,
			headers,
			"load-balancers",
			globals.AZ_LOAD_BALANCERS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.LoadBalancerRows, headers,
			"load-balancers", globals.AZ_LOAD_BALANCERS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := LoadBalancersOutput{
		Table: []internal.TableFile{{
			Name:   "load-balancers",
			Header: headers,
			Body:   m.LoadBalancerRows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output
	if err := internal.HandleOutputSmart(
		"Azure",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.UserUPN,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_LOAD_BALANCERS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	// Count public vs private
	publicCount := 0
	privateCount := 0
	natRuleCount := 0

	for _, row := range m.LoadBalancerRows {
		if len(row) > 8 && strings.Contains(row[8], "Public") {
			publicCount++
		} else {
			privateCount++
		}

		if len(row) > 12 && row[12] != "None" {
			natRuleCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d load balancer(s) across %d subscription(s) (Public: %d, Private: %d, With NAT Rules: %d)",
		len(m.LoadBalancerRows), len(m.Subscriptions), publicCount, privateCount, natRuleCount), globals.AZ_LOAD_BALANCERS_MODULE_NAME)
}
