# Azure CloudFox Security Module Analysis - SESSION 2
## Compute & Container Resources Security Analysis

**Document Version:** 1.0
**Last Updated:** 2025-01-12
**Analysis Session:** 2 of Multiple
**Focus Area:** Compute & Container Resources

---

## SESSION 2 OVERVIEW: Compute & Container Modules

This session analyzes Azure compute and container-related modules to identify security gaps, missing features, and enhancement opportunities that would benefit offensive security assessments.

### Modules Analyzed in This Session:
1. **VMs** - Virtual Machines
2. **AKS** - Azure Kubernetes Service
3. **Functions** - Azure Functions
4. **WebApps** - App Service / Web Apps
5. **Container-Apps** - Container Instances & Container Apps
6. **Logic Apps** - Workflow automation
7. **Batch** - Batch computing

---

## 1. VMS Module (`vms.go`)

**Current Capabilities:**
- Comprehensive VM enumeration with extensive details
- OS disk and data disk enumeration
- Network interface and IP address details
- Managed identity enumeration (system and user-assigned)
- VM extension discovery
- Boot diagnostics configuration
- Public key authentication detection
- VM size and licensing info
- Tags and resource metadata
- Generates extensive loot files:
  - VM access commands (SSH/RDP with various techniques)
  - RunCommand execution templates
  - VM extension enumeration
  - Serial console access commands
  - Boot diagnostics log access
  - Disk mounting and snapshot commands
  - Password reset commands

**Security Gaps Identified:**
1. ❌ **No VM Agent Status** - Whether VM agent is running (affects extension execution)
2. ❌ **No Guest OS Security Baseline** - No Windows security baseline or Linux hardening checks
3. ❌ **No Anti-malware Extension Detection** - Microsoft Antimalware or Defender status
4. ❌ **No JIT (Just-In-Time) Access Status** - Security Center JIT VM access configuration
5. ❌ **No NSG Analysis per NIC** - Network Security Groups applied to VM NICs not analyzed
6. ❌ **No VM Update Management Status** - Patch compliance, missing updates
7. ❌ **No Azure Backup Status** - Whether VM is backed up
8. ❌ **No Disk Encryption Status** - ADE (Azure Disk Encryption) enablement
9. ❌ **No Boot Integrity Monitoring** - Trusted Launch, Secure Boot, vTPM status
10. ❌ **No VM Vulnerability Assessment** - Qualys/Rapid7 VA extension status
11. ❌ **No Custom Script Extension Analysis** - Scripts executed via CSE could contain secrets
12. ❌ **No VM Snapshot Enumeration** - Existing VM snapshots (data exfiltration opportunity)
13. ❌ **No Azure Monitor Agent Status** - Logging and monitoring configuration
14. ❌ **No VM Proximity Placement Groups** - VMs in same data center (lateral movement)
15. ❌ **No Ephemeral OS Disk Detection** - Persistence considerations

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add NSG analysis per VM NIC (inbound/outbound rules, open ports)
- [ ] Add disk encryption status (ADE enabled/disabled)
- [ ] Add JIT access status (whether JIT is configured, allowed source IPs)
- [ ] Add VM backup status (Recovery Services Vault association)
- [ ] Add boot diagnostics log content analysis (errors, crash dumps)
- [ ] Add VM snapshot enumeration (snapshot IDs, creation dates, sizes)

HIGH PRIORITY:
- [ ] Add VM agent status (running/stopped/not installed)
- [ ] Add anti-malware extension status (real-time protection, scan schedule)
- [ ] Add update management status (last assessment, pending updates, compliance)
- [ ] Add vulnerability assessment extension status (last scan date, findings count)
- [ ] Add custom script extension content extraction (potential secrets)
- [ ] Add Azure Monitor agent configuration (log analytics workspace)
- [ ] Add boot integrity status (Secure Boot, vTPM, measured boot)
- [ ] Add public IP protection (DDoS Standard vs Basic)

MEDIUM PRIORITY:
- [ ] Add proximity placement group membership (co-located VMs)
- [ ] Add availability set/zone configuration (HA considerations)
- [ ] Add VM lifecycle state (deallocated, stopped, running)
- [ ] Add VM diagnostics extension logs
- [ ] Add ephemeral OS disk detection
- [ ] Add Azure Policy compliance status per VM
- [ ] Add VM reserved instance details
- [ ] Add spot instance pricing (eviction policy)
- [ ] Add automatic OS upgrades status
- [ ] Add maintenance configuration assignments
```

**Attack Surface Considerations:**
- VMs without disk encryption = data at rest exposure
- VMs without JIT access = always-on RDP/SSH exposure
- VMs with public IPs + no NSG = direct internet exposure
- VMs without antimalware = easier persistence
- VM extensions = code execution vectors
- Boot diagnostics logs = potential information disclosure
- VM snapshots = data exfiltration opportunity
- Managed identities on VMs = cloud privilege escalation
- Custom script extensions = secret exposure in scripts

---

## 2. AKS Module (`aks.go`)

**Current Capabilities:**
- AKS cluster enumeration with comprehensive details
- Control plane and node pool configuration
- Network profile (CNI, network policy, DNS, service CIDR)
- Addon profiles (monitoring, policy, HTTP app routing)
- AAD integration and Azure RBAC configuration
- Private cluster detection
- Managed identity configuration (system and user-assigned)
- API server access profiles (authorized IP ranges)
- Auto-scaler configuration
- Linux profile and SSH keys
- Generates extensive loot files:
  - kubectl access commands with kubeconfig generation
  - Pod execution commands for privilege escalation
  - Secret dumping commands (K8s secrets, service account tokens)
  - Registry credential extraction
  - Container escape techniques
  - Network policy analysis
  - RBAC permission analysis

**Security Gaps Identified:**
1. ❌ **No Kubernetes Version CVE Analysis** - Known vulnerabilities in K8s version
2. ❌ **No Pod Security Standards** - PSS/PSP (Pod Security Policy) enforcement status
3. ❌ **No Admission Controller Configuration** - OPA Gatekeeper policies not enumerated
4. ❌ **No Network Policy Effectiveness** - Whether network policies actually exist
5. ❌ **No Secret Encryption at Rest** - KMS key encryption for etcd secrets
6. ❌ **No Image Vulnerability Scanning** - Defender for Containers / ACR scanning status
7. ❌ **No Runtime Security Monitoring** - Defender for Containers runtime protection
8. ❌ **No Privileged Container Detection** - Containers running with privileged: true
9. ❌ **No hostPath Volume Usage** - Containers mounting host filesystem
10. ❌ **No LoadBalancer Service Exposure** - Public LoadBalancer services enumeration
11. ❌ **No Ingress Controller Configuration** - NGINX/App Gateway ingress details
12. ❌ **No Certificate Management** - cert-manager, certificate expiration
13. ❌ **No Service Mesh Configuration** - Istio/Linkerd security policies
14. ❌ **No RBAC Overpermissions** - cluster-admin bindings, wildcard permissions
15. ❌ **No Windows Node Pool Analysis** - Windows containers security considerations

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add Kubernetes version CVE database lookup (known exploits)
- [ ] Add Pod Security Standards enforcement status (restricted/baseline/privileged)
- [ ] Add privileged container detection (enumerate pods with securityContext.privileged=true)
- [ ] Add hostPath volume usage detection (containers mounting /var/run/docker.sock, /etc, /proc)
- [ ] Add public LoadBalancer service enumeration (external IPs, open ports)
- [ ] Add API server public exposure analysis (bypass private cluster detection)
- [ ] Add image vulnerability scan results (Defender for Containers findings)
- [ ] Add secret encryption at rest status (KMS/BYOK configuration)

HIGH PRIORITY:
- [ ] Add admission controller policy enumeration (Gatekeeper constraints)
- [ ] Add network policy effectiveness analysis (default deny, egress restrictions)
- [ ] Add runtime security monitoring status (Defender for Containers)
- [ ] Add ingress controller configuration (TLS certificates, exposed paths)
- [ ] Add service mesh configuration (Istio AuthorizationPolicies, mTLS)
- [ ] Add RBAC overpermission analysis (cluster-admin bindings, wildcard verbs)
- [ ] Add certificate expiration tracking (ingress certs, webhook certs)
- [ ] Add node identity permissions (kubelet, node managed identity roles)
- [ ] Add Azure Monitor for Containers configuration (log retention)
- [ ] Add Windows node pool specific security (gmsa, host process containers)

MEDIUM PRIORITY:
- [ ] Add cluster autoscaler aggressive scale-down detection
- [ ] Add Azure Policy for Kubernetes assignment status
- [ ] Add diagnostic settings and audit log configuration
- [ ] Add node OS patching configuration (kured, node image upgrade)
- [ ] Add Azure Key Vault provider for Secrets Store CSI driver
- [ ] Add egress lockdown configuration (Azure Firewall, NAT Gateway)
- [ ] Add pod identity webhook configuration
```

**Attack Surface Considerations:**
- Public API servers = direct cluster compromise
- No network policies = pod-to-pod unrestricted communication
- Privileged containers = container escape to node
- hostPath volumes = node filesystem access
- Public LoadBalancers = exposed services
- Weak RBAC = privilege escalation within cluster
- Outdated K8s versions = known CVE exploitation
- No runtime protection = undetected malicious activity
- Managed identities on nodes = Azure privilege escalation
- Service account tokens = K8s API access

---

## 3. FUNCTIONS Module (`functions.go`)

**Current Capabilities:**
- Function App enumeration
- App Service Plan details
- Runtime stack detection (Node, Python, .NET, Java)
- HTTPS-only and TLS version configuration
- EntraID centralized authentication status (Easy Auth)
- Network configuration (VNet integration, private IPs)
- Managed identity enumeration
- Generates loot files:
  - Function settings and connection strings extraction
  - Function code download commands
  - Function keys extraction (master, host, function-level)
  - Publishing profile credentials
  - Function invocation examples with keys

**Security Gaps Identified:**
1. ❌ **No Function Authorization Level Analysis** - Anonymous vs Function vs Admin keys
2. ❌ **No CORS Configuration** - Allowed origins for cross-origin requests
3. ❌ **No API Management Integration** - APIM policies and rate limiting
4. ❌ **No Always-On Status** - Function app warm-up configuration
5. ❌ **No Remote Debugging Status** - Remote debugging enabled (security risk)
6. ❌ **No SCM (Kudu) Basic Auth Status** - Publishing credentials enabled
7. ❌ **No Deployment Slot Configuration** - Blue/green deployments
8. ❌ **No Application Insights Configuration** - Logging and monitoring
9. ❌ **No Function Triggers Enumeration** - HTTP, Timer, Queue, Blob triggers
10. ❌ **No Function Dependencies Analysis** - NuGet packages, npm modules (vulnerable deps)
11. ❌ **No Webhook URLs** - Exposed webhook endpoints
12. ❌ **No Function Timeout Configuration** - Execution time limits
13. ❌ **No Function Storage Account Analysis** - Backend storage account permissions
14. ❌ **No Durable Functions Orchestration** - Durable function instance enumeration
15. ❌ **No VNET Integration Details** - Subnet, route tables, NSG

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add function authorization level per function (anonymous functions = critical finding)
- [ ] Add function trigger types (HTTP triggers with anonymous auth = exposed endpoints)
- [ ] Add CORS configuration (wildcard origins = security issue)
- [ ] Add remote debugging status (if enabled = backdoor opportunity)
- [ ] Add SCM basic auth status (if disabled, can't use Kudu)
- [ ] Add webhook URL enumeration (Event Grid, GitHub webhooks)
- [ ] Add function bindings enumeration (input/output bindings = data access)

HIGH PRIORITY:
- [ ] Add API Management integration (gateway policies, authentication)
- [ ] Add function timeout limits (max execution time)
- [ ] Add function storage account role assignments (storage access)
- [ ] Add application insights instrumentation key
- [ ] Add deployment slot configuration (staging slots)
- [ ] Add function execution history (run history API)
- [ ] Add function code integrity (published package hash)
- [ ] Add function app scale-out configuration (max instances)
- [ ] Add function host keys rotation status (last rotated)

MEDIUM PRIORITY:
- [ ] Add dependency vulnerability scanning (outdated packages)
- [ ] Add durable functions orchestration enumeration
- [ ] Add function app always-on status (cold start considerations)
- [ ] Add function app health check endpoints
- [ ] Add function app deployment history
- [ ] Add function app container image (if containerized)
- [ ] Add Azure Storage firewall rules (backend storage)
```

**Attack Surface Considerations:**
- Anonymous HTTP triggers = unauthenticated function execution
- Exposed master keys = full function app control
- CORS misconfiguration = XSS and CSRF attacks
- Remote debugging enabled = code execution backdoor
- Function code extraction = source code disclosure
- Managed identities = Azure privilege escalation
- Storage account access = data exfiltration via bindings
- Webhook secrets = event injection attacks

---

## 4. WEBAPPS Module (`webapps.go`)

**Current Capabilities:**
- Comprehensive Web App / App Service enumeration
- App Service Plan details
- Runtime stack detection (Node, Python, .NET, PHP, Java)
- HTTPS-only and TLS version configuration
- EntraID centralized authentication status (Easy Auth)
- Network configuration (VNet integration, private/public IPs)
- Managed identity enumeration
- Publishing credentials extraction
- Generates extensive loot files:
  - Web app configuration and connection strings
  - Kudu API access commands (file browsing, command execution)
  - Backup access commands (backup enumeration, download, restore)
  - Easy Auth token extraction and decryption
  - Easy Auth service principal credentials
  - Deployment profile credentials

**Security Gaps Identified:**
1. ❌ **No Client Certificate Authentication** - Mutual TLS configuration
2. ❌ **No IP Restrictions** - Allowed/denied IP addresses for access
3. ❌ **No Deployment Slot Swap History** - Slot swap audit trail
4. ❌ **No SCM IP Restrictions** - Kudu endpoint IP restrictions
5. ❌ **No Always-On Status** - App warm-up configuration
6. ❌ **No Auto-Heal Rules** - Automatic recovery configuration
7. ❌ **No Health Check Endpoint** - Health probe configuration
8. ❌ **No Custom Domain SSL Bindings** - TLS certificate management
9. ❌ **No Deployment Source** - GitHub, Azure DevOps, local Git
10. ❌ **No Application Stack Vulnerabilities** - Outdated runtimes
11. ❌ **No Web Application Firewall** - WAF integration (App Gateway, Front Door)
12. ❌ **No CORS Configuration** - Cross-origin resource sharing rules
13. ❌ **No Authentication Provider Configuration** - AAD/Facebook/Google auth details
14. ❌ **No Site Extension Enumeration** - Installed site extensions
15. ❌ **No WebJobs Enumeration** - Background jobs and schedules

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add IP restriction analysis (apps without IP restrictions = open access)
- [ ] Add SCM IP restrictions (Kudu without IP restrictions = code access)
- [ ] Add client certificate authentication status (mutual TLS enforcement)
- [ ] Add deployment source detection (external repos = supply chain risk)
- [ ] Add application stack CVE analysis (outdated PHP, Node.js, Python versions)
- [ ] Add WAF integration status (no WAF = no web attack protection)
- [ ] Add authentication provider token validation (token lifetime, refresh tokens)
- [ ] Add backup encryption status (backups contain secrets)

HIGH PRIORITY:
- [ ] Add custom domain SSL certificate expiration dates
- [ ] Add CORS configuration (wildcard origins = security issue)
- [ ] Add deployment slot configuration and swap history
- [ ] Add always-on status (cold start = DoS opportunity)
- [ ] Add auto-heal rules (recovery triggers, actions)
- [ ] Add health check endpoint configuration
- [ ] Add site extension enumeration (extensions = attack surface)
- [ ] Add WebJobs enumeration (background processing, credentials)
- [ ] Add hybrid connection configuration (on-prem connectivity)
- [ ] Add diagnostic logging configuration (failed request tracing, detailed errors)

MEDIUM PRIORITY:
- [ ] Add deployment slot auto-swap configuration
- [ ] Add application initialization configuration
- [ ] Add connection string type classification (SQL, Redis, Storage, Custom)
- [ ] Add app setting source (Key Vault references)
- [ ] Add deployment center configuration
- [ ] Add scale-out configuration (auto-scale rules)
- [ ] Add regional VNet integration details
```

**Attack Surface Considerations:**
- No IP restrictions = global accessibility
- SCM site exposed = source code and config access
- Easy Auth tokens = session hijacking opportunity
- Publishing credentials = deployment access
- Kudu API = command execution capabilities
- Backups = historical data and config exposure
- Managed identities = Azure privilege escalation
- Connection strings in config = database access
- WebJobs = background execution context
- Deployment slots = testing environments with production data

---

## 5. CONTAINER-APPS Module (`container-apps.go`)

**Current Capabilities:**
- Azure Container Instances (ACI) enumeration
- Container Apps Jobs enumeration
- Network configuration (public/private IPs, FQDNs, ports)
- Managed identity enumeration (system and user-assigned)
- Container environment association
- Generates loot files:
  - Container instance access commands (logs, exec, export)
  - Container Apps job commands
  - Network connectivity testing
  - Template export commands

**Security Gaps Identified:**
1. ❌ **No Container Image Analysis** - Image registry, tags, vulnerabilities
2. ❌ **No Environment Variables** - Environment variables may contain secrets
3. ❌ **No Volume Mounts** - Azure Files, secrets, ConfigMaps mounted
4. ❌ **No Resource Limits** - CPU and memory limits (DoS potential)
5. ❌ **No Restart Policy** - Always/OnFailure/Never restart behavior
6. ❌ **No Container Registry Credentials** - How container pulls images
7. ❌ **No GPU Configuration** - GPU-enabled containers
8. ❌ **No DNS Configuration** - Custom DNS servers
9. ❌ **No Container Apps Environment Details** - Dapr, VNet, Log Analytics
10. ❌ **No Container Apps Revision History** - Previous container versions
11. ❌ **No Container Apps Ingress Configuration** - External vs internal, TLS
12. ❌ **No Container Apps Secrets** - Application secrets stored in Container Apps
13. ❌ **No Init Containers** - Container startup dependencies
14. ❌ **No Liveness/Readiness Probes** - Health check configuration
15. ❌ **No Azure Files SMB Share Mounts** - Shared storage access

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add container image analysis (registry, image digest, scan results)
- [ ] Add environment variable enumeration (may contain secrets, API keys)
- [ ] Add volume mount analysis (Azure Files shares, secrets, emptyDir)
- [ ] Add container registry credential extraction (ACR, Docker Hub tokens)
- [ ] Add Container Apps secrets enumeration (secret store)
- [ ] Add Container Apps ingress configuration (exposed endpoints, TLS certs)
- [ ] Add Azure Files SMB share mounts (potential data access)

HIGH PRIORITY:
- [ ] Add resource limits per container (CPU, memory quotas)
- [ ] Add restart policy configuration (automatic recovery)
- [ ] Add Container Apps environment configuration (VNet, Dapr, Log Analytics)
- [ ] Add Container Apps revision history (previous deployments)
- [ ] Add container startup commands (ENTRYPOINT, CMD overrides)
- [ ] Add liveness and readiness probes (health check endpoints)
- [ ] Add init container configuration (startup dependencies)
- [ ] Add container registry image vulnerability scan results
- [ ] Add DNS configuration (custom DNS, DNS suffix)

MEDIUM PRIORITY:
- [ ] Add GPU configuration (GPU SKU, driver version)
- [ ] Add container group subnet delegation (VNet injection)
- [ ] Add container log analytics workspace association
- [ ] Add container network profile details (network policies)
- [ ] Add Container Apps Dapr configuration (service-to-service calls)
- [ ] Add Container Apps scale rules (HTTP, queue-based scaling)
- [ ] Add Container Apps authentication configuration (Easy Auth)
```

**Attack Surface Considerations:**
- Public container endpoints = exposed services
- Environment variables = secret exposure
- Managed identities = Azure privilege escalation
- Volume mounts = data access and exfiltration
- Container exec capability = command execution
- Registry credentials = image tampering opportunity
- Azure Files mounts = shared storage access
- Container logs = information disclosure
- No resource limits = resource exhaustion attacks

---

## 6. LOGICAPPS Module (`logicapps.go`)

**Current Capabilities:**
- Logic App workflow enumeration
- Workflow state (Enabled/Disabled)
- Trigger type detection
- Action count
- Parameter detection
- Managed identity enumeration
- Generates loot files:
  - Workflow definitions (full JSON)
  - Workflow parameters
  - Potential secrets flagging
  - Logic App access commands

**Security Gaps Identified:**
1. ❌ **No Connector Authentication Analysis** - API connection credentials
2. ❌ **No Trigger URL Enumeration** - Webhook URLs with secrets
3. ❌ **No Run History Analysis** - Execution history with inputs/outputs
4. ❌ **No Access Control Configuration** - Allowed caller IPs, caller actions
5. ❌ **No Content Security** - Secure inputs/outputs obfuscation
6. ❌ **No Integration Account Usage** - B2B scenarios, EDI, AS2
7. ❌ **No Connector Enumeration** - Which connectors are used (O365, SQL, etc.)
8. ❌ **No Workflow Trigger History** - When workflow was triggered
9. ❌ **No Workflow Throttling Limits** - Rate limiting configuration
10. ❌ **No Diagnostic Settings** - Log Analytics configuration
11. ❌ **No State Configuration** - Stateful vs stateless workflows
12. ❌ **No Workflow Version History** - Previous workflow versions
13. ❌ **No Custom Connector Usage** - Custom API connectors
14. ❌ **No On-Premises Data Gateway** - Hybrid connectivity configuration
15. ❌ **No Workflow Performance Metrics** - Execution duration, failures

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add connector authentication analysis (API connections, OAuth tokens, keys)
- [ ] Add HTTP trigger URL enumeration (webhook URLs with SAS tokens)
- [ ] Add run history with input/output analysis (execution data contains secrets)
- [ ] Add access control policy (allowed caller IPs, required actions)
- [ ] Add secure parameter detection (parameters marked as secure)
- [ ] Add content security settings (secure inputs/outputs configuration)
- [ ] Add API connection enumeration (connection strings, credentials)

HIGH PRIORITY:
- [ ] Add connector usage analysis (which connectors: O365, SQL, SharePoint)
- [ ] Add workflow trigger history (last execution, trigger source)
- [ ] Add integration account association (B2B partner configurations)
- [ ] Add custom connector enumeration (external API endpoints)
- [ ] Add on-premises data gateway configuration (hybrid connectivity)
- [ ] Add diagnostic settings (Log Analytics workspace, retention)
- [ ] Add workflow throttling limits (concurrency, rate limits)
- [ ] Add stateful vs stateless detection (state storage configuration)

MEDIUM PRIORITY:
- [ ] Add workflow version history (previous definitions)
- [ ] Add workflow performance metrics (avg duration, failure rate)
- [ ] Add workflow dependencies (nested workflows, called APIs)
- [ ] Add workflow tags and metadata
- [ ] Add workflow schedule configuration (recurrence triggers)
- [ ] Add workflow retry policies (retry count, intervals)
```

**Attack Surface Considerations:**
- HTTP trigger URLs = unauthenticated workflow execution
- API connections = credential exposure
- Run history = sensitive data in inputs/outputs
- Connectors to O365/SQL = data exfiltration paths
- Managed identities = Azure privilege escalation
- Webhook secrets = event injection
- Integration accounts = B2B partner data access
- Custom connectors = external API exposure
- Workflow definitions = business logic disclosure

---

## 7. BATCH Module (`batch.go`)

**Current Capabilities:**
- Batch account enumeration
- Pool configuration (quota, count)
- Application enumeration
- Provisioning state
- Account endpoint
- Public network access status
- Managed identity enumeration
- Generates loot files:
  - Batch account access commands
  - Account key enumeration

**Security Gaps Identified:**
1. ❌ **No Batch Pool Details** - VM size, node count, OS configuration
2. ❌ **No Batch Pool Auto-Scale Formula** - Dynamic scaling configuration
3. ❌ **No Batch Task Enumeration** - Running and completed tasks
4. ❌ **No Batch Job Enumeration** - Active and completed jobs
5. ❌ **No Batch Pool Network Configuration** - VNet, NSG, public IPs
6. ❌ **No Batch Application Packages** - Application versions and storage
7. ❌ **No Batch Pool Certificates** - Installed certificates on nodes
8. ❌ **No Batch Pool Start Task** - Node startup script (may contain secrets)
9. ❌ **No Batch User Accounts** - Admin and non-admin users on nodes
10. ❌ **No Batch Job Schedule** - Recurring job schedules
11. ❌ **No Batch Pool VM Configuration** - OS disk, data disks
12. ❌ **No Batch Pool SSH Public Keys** - Linux node SSH keys
13. ❌ **No Batch Authentication Mode** - SharedKey vs AAD auth
14. ❌ **No Batch Diagnostic Settings** - Logging configuration
15. ❌ **No Batch Encryption Configuration** - Customer-managed keys

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add batch pool detailed enumeration (VM size, node count, OS)
- [ ] Add batch pool start task analysis (startup scripts contain secrets)
- [ ] Add batch pool network configuration (VNet, subnet, public IPs, NSGs)
- [ ] Add batch pool user accounts (admin users on compute nodes)
- [ ] Add batch task enumeration (running tasks, command lines, environment variables)
- [ ] Add batch pool certificates (TLS certs, code signing certs on nodes)
- [ ] Add batch account authentication mode (shared key vs AAD)

HIGH PRIORITY:
- [ ] Add batch pool auto-scale formula analysis (scaling logic)
- [ ] Add batch job enumeration (job details, task counts, priority)
- [ ] Add batch job schedule enumeration (recurring jobs, cron expressions)
- [ ] Add batch application package details (version, storage location)
- [ ] Add batch pool SSH public keys (Linux node access)
- [ ] Add batch pool VM configuration (OS disk, temp disk, data disks)
- [ ] Add batch pool node communication mode (classic vs simplified)
- [ ] Add batch account encryption configuration (CMK, BYOK)
- [ ] Add batch diagnostic settings (Log Analytics, Storage Account)

MEDIUM PRIORITY:
- [ ] Add batch pool inter-node communication status
- [ ] Add batch pool task scheduling policy
- [ ] Add batch pool resize timeout configuration
- [ ] Add batch pool application licenses
- [ ] Add batch node agent SKU
- [ ] Add batch account storage account association
- [ ] Add batch pool metadata and labels
```

**Attack Surface Considerations:**
- Batch account keys = full compute access
- Start tasks = startup script secrets
- Pool certificates = credential extraction
- User accounts on nodes = RDP/SSH access
- Task command lines = secrets in arguments
- Application packages = code tampering
- VNet integration = lateral movement
- Managed identities = Azure privilege escalation
- Public IP nodes = direct internet access
- Batch jobs = arbitrary code execution

---

## SESSION 2 SUMMARY: Compute Module Gaps

### Critical Gaps Across Compute Modules

1. **Encryption at Rest** - Missing across VMs (ADE), AKS (etcd), Batch (CMK)
2. **Network Security Analysis** - NSGs, IP restrictions, private endpoints not fully analyzed
3. **Vulnerability Management** - No runtime vulnerability scanning or CVE analysis
4. **Secret Management** - Secrets in environment variables, connection strings, scripts not extracted
5. **Runtime Security** - No runtime monitoring or threat detection status
6. **Authentication Mechanisms** - Anonymous access, weak auth not flagged
7. **Code Execution Vectors** - Extensions, webhooks, triggers not fully analyzed
8. **Backup and Recovery** - Backup encryption, snapshot management gaps
9. **Identity and Access** - Managed identity permissions not traced end-to-end
10. **Compliance Posture** - Security policies, baselines, standards not checked

### Recommended New Compute Modules

```markdown
NEW MODULE SUGGESTIONS:

1. **VM-SECURITY Module**
   - Consolidated VM security posture assessment
   - Disk encryption, JIT access, NSG analysis, patch compliance
   - Anti-malware status, vulnerability assessment
   - Boot diagnostics analysis
   - Extension security analysis

2. **AKS-SECURITY Module**
   - Kubernetes security posture assessment
   - Pod security standards, admission controllers
   - Network policies, service mesh configuration
   - RBAC overpermissions, privileged containers
   - Image vulnerability scanning results
   - Runtime security monitoring status

3. **APP-SERVICE-SECURITY Module**
   - Web App and Function App security consolidation
   - IP restrictions, CORS, authentication analysis
   - Deployment source and supply chain risk
   - WAF integration and protection status
   - SSL/TLS certificate management
   - Runtime stack vulnerability assessment

4. **CONTAINER-SECURITY Module**
   - Container image vulnerability scanning
   - Registry credential extraction
   - Container runtime security analysis
   - Volume mount and secret analysis
   - Network exposure and ingress configuration

5. **COMPUTE-IDENTITY-PATHS Module**
   - End-to-end managed identity permission tracing
   - VM/AKS/Function/WebApp identity -> RBAC roles -> permissions
   - Privilege escalation path detection
   - Identity-based attack surface analysis
```

---

## COMPUTE ATTACK SURFACE MATRIX

| Resource Type | Critical Vectors | Data Exfiltration | Privilege Escalation | Code Execution |
|---------------|-----------------|-------------------|---------------------|----------------|
| VMs | Public IPs, No JIT, Unencrypted disks | Disk snapshots, Boot diagnostics | Managed identity + RBAC | VM extensions, RunCommand |
| AKS | Public API, No NetworkPolicy | LoadBalancer services, Volume mounts | Managed identity, RBAC | Privileged pods, exec |
| Functions | Anonymous HTTP triggers, Master keys | Storage bindings, Logs | Managed identity + RBAC | Function code injection |
| WebApps | No IP restrictions, SCM exposed | Kudu API, Backups | Managed identity + RBAC | Kudu command API |
| Container Apps/ACI | Public endpoints, No ingress auth | Volume mounts, Logs | Managed identity + RBAC | Container exec |
| Logic Apps | HTTP trigger URLs, API connections | Run history, Connectors | Managed identity + RBAC | Workflow injection |
| Batch | Account keys, Public node IPs | Start tasks, Jobs | Managed identity + RBAC | Task execution |

---

## NEXT SESSIONS PLAN

**Session 3:** Storage & Data Modules (Storage Accounts, Key Vaults, Disks, Filesystems)
**Session 4:** Networking Modules (NSG, VNets, Firewalls, App Gateway, Load Balancers)
**Session 5:** Database Modules (SQL, MySQL, PostgreSQL, CosmosDB, Redis)
**Session 6:** Platform Services (Data Factory, Synapse, Databricks, etc.)
**Session 7:** DevOps & Management Modules (DevOps, Automation, Policy)
**Session 8:** Missing Azure Services & Final Recommendations

---

**END OF SESSION 2**

*Next session will analyze Storage and Data modules (Storage Accounts, Key Vaults, Disks)*
