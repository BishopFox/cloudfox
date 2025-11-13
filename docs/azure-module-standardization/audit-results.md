# Azure Module Compliance Audit
Date: 2025-11-13

| Module | InitCtx | BaseModule | RunSubEnum | SplitTenant | SplitSub | HandleOut | Score | Status |
|--------|---------|------------|------------|-------------|----------|-----------|-------|--------|
| accesskeys | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| acr | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| aks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| api-management | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| app-configuration | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| appgw | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| arc | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| automation | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| backup-inventory | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | 6/10 | ⚠️ PARTIAL |
| bastion | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 8/10 | ⚠️ PARTIAL |
| batch | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| cdn | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 8/10 | ⚠️ PARTIAL |
| compliance-dashboard | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | 8/10 | ⚠️ PARTIAL |
| conditional-access | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 4/10 | ❌ NON-COMPLIANT |
| consent-grants | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 4/10 | ❌ NON-COMPLIANT |
| container-apps | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| cost-security | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | 8/10 | ⚠️ PARTIAL |
| data-exfiltration | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| databases | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| databricks | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| datafactory | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| deployments | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| devops-agents | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | 2/10 | ❌ NON-COMPLIANT |
| devops-artifacts | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 0/10 | ❌ NON-COMPLIANT |
| devops-pipelines | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 0/10 | ❌ NON-COMPLIANT |
| devops-projects | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 0/10 | ❌ NON-COMPLIANT |
| devops-repos | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 0/10 | ❌ NON-COMPLIANT |
| devops-security | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 0/10 | ❌ NON-COMPLIANT |
| disks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| endpoints | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| enterprise-apps | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| expressroute | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| federated-credentials | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 4/10 | ❌ NON-COMPLIANT |
| filesystems | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| firewall | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| frontdoor | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 8/10 | ⚠️ PARTIAL |
| functions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| hdinsight | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| inventory | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| iothub | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| keyvaults | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| kusto | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| lateral-movement | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| lighthouse | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | 8/10 | ⚠️ PARTIAL |
| load-balancers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| load-testing | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| logicapps | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| machine-learning | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| monitor | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | 6/10 | ⚠️ PARTIAL |
| network-exposure | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| network-interfaces | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| network-topology | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 8/10 | ⚠️ PARTIAL |
| nsg | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| permissions | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | 8/10 | ⚠️ PARTIAL |
| policy | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| principals | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | 8/10 | ⚠️ PARTIAL |
| privatelink | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| rbac | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| redis | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| resource-graph | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | 6/10 | ⚠️ PARTIAL |
| routes | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| sentinel | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 4/10 | ❌ NON-COMPLIANT |
| servicefabric | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| signalr | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| springapps | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| storage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| streamanalytics | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| synapse | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | 9/10 | ✅ COMPLIANT |
| vms | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| vnets | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| webapps | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 10/10 | ✅ COMPLIANT |
| whoami | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | 6/10 | ⚠️ PARTIAL |

## Legend
- **InitCtx**: InitializeCommandContext
- **BaseModule**: azinternal.BaseAzureModule embedding
- **RunSubEnum**: RunSubscriptionEnumeration
- **SplitTenant**: ShouldSplitByTenant
- **SplitSub**: ShouldSplitBySubscription
- **HandleOut**: HandleOutputSmart

## Status Categories
- ✅ **COMPLIANT** (9-10/10): Fully follows gold standard
- ⚠️ **PARTIAL** (5-8/10): Has some patterns, needs updates
- ❌ **NON-COMPLIANT** (0-4/10): Missing most patterns, major refactor needed
