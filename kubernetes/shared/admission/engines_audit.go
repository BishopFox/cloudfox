package admission

// registerAuditEngines registers all audit/runtime security engines
func (r *EngineRegistry) registerAuditEngines() {
	// Falco
	r.register(&Engine{
		ID:       "falco",
		Name:     "Falco",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"docker.io/falcosecurity/",
			"falcosecurity/",
		},
		ImagePatterns: []string{
			"falcosecurity/falco",
			"falco-no-driver",
			"falco",
		},
		DeploymentPatterns: []string{"falco"},
		ExpectedNamespaces: []string{"falco", "falco-system", "security", "kube-system"},
		CRDGroups:          []string{"falco.org"},
		LabelSelectors:     []string{"app=falco", "app.kubernetes.io/name=falco"},
		RequireImageVerification: true,
	})

	// Tetragon
	r.register(&Engine{
		ID:       "tetragon",
		Name:     "Tetragon",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"quay.io/cilium/",
			"docker.io/cilium/",
		},
		ImagePatterns: []string{
			"cilium/tetragon",
			"tetragon",
		},
		DeploymentPatterns: []string{"tetragon"},
		ExpectedNamespaces: []string{"kube-system", "tetragon", "cilium"},
		CRDGroups:          []string{"cilium.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=tetragon"},
		RequireImageVerification: true,
	})

	// KubeArmor
	r.register(&Engine{
		ID:       "kubearmor",
		Name:     "KubeArmor",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"kubearmor/",
			"docker.io/kubearmor/",
		},
		ImagePatterns: []string{
			"kubearmor/kubearmor",
			"kubearmor",
		},
		DeploymentPatterns: []string{"kubearmor"},
		ExpectedNamespaces: []string{"kubearmor", "kube-system"},
		CRDGroups:          []string{"security.kubearmor.com"},
		LabelSelectors:     []string{"kubearmor-app=kubearmor"},
		RequireImageVerification: true,
	})

	// Tracee (Aqua)
	r.register(&Engine{
		ID:       "tracee",
		Name:     "Tracee",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"docker.io/aquasec/",
			"aquasec/",
		},
		ImagePatterns: []string{
			"aquasec/tracee",
			"tracee",
		},
		DeploymentPatterns: []string{"tracee"},
		ExpectedNamespaces: []string{"tracee", "tracee-system", "aqua", "kube-system"},
		LabelSelectors:     []string{"app=tracee", "app.kubernetes.io/name=tracee"},
		RequireImageVerification: true,
	})

	// Sysdig Agent
	r.register(&Engine{
		ID:       "sysdig",
		Name:     "Sysdig Secure",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"sysdig/",
			"quay.io/sysdig/",
		},
		ImagePatterns: []string{
			"sysdig/agent",
			"sysdig-agent",
		},
		DeploymentPatterns: []string{"sysdig-agent"},
		ExpectedNamespaces: []string{"sysdig-agent", "sysdig", "kube-system"},
		LabelSelectors:     []string{"app=sysdig-agent", "app.kubernetes.io/name=sysdig"},
		RequireImageVerification: true,
	})

	// Prisma Cloud (Twistlock)
	r.register(&Engine{
		ID:       "prisma",
		Name:     "Prisma Cloud",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"registry.twistlock.com/",
			"twistlock/",
		},
		ImagePatterns: []string{
			"twistlock/defender",
			"twistlock/console",
			"prismacloud/defender",
		},
		DeploymentPatterns: []string{"twistlock-defender", "twistlock-console"},
		ExpectedNamespaces: []string{"twistlock", "prisma-cloud"},
		WebhookPatterns:    []string{"twistlock"},
		LabelSelectors:     []string{"app=twistlock-defender", "name=twistlock-defender-ds"},
		RequireImageVerification: true,
	})

	// Aqua Security
	r.register(&Engine{
		ID:       "aqua",
		Name:     "Aqua Security",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"registry.aquasec.com/",
			"aquasec/",
		},
		ImagePatterns: []string{
			"aquasec/enforcer",
			"aqua-enforcer",
			"aquasec/gateway",
			"aquasec/server",
		},
		DeploymentPatterns: []string{"aqua-gateway", "aqua-web"},
		ExpectedNamespaces: []string{"aqua", "aqua-security"},
		WebhookPatterns:    []string{"aqua-webhook"},
		LabelSelectors:     []string{"app=aqua-enforcer", "app=aqua-gateway"},
		RequireImageVerification: true,
	})

	// StackRox (Red Hat ACS)
	r.register(&Engine{
		ID:       "stackrox",
		Name:     "StackRox",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"stackrox/",
			"quay.io/stackrox-io/",
			"registry.redhat.io/advanced-cluster-security/",
		},
		ImagePatterns: []string{
			"stackrox/main",
			"stackrox/central",
			"stackrox/sensor",
			"stackrox/collector",
		},
		DeploymentPatterns: []string{"central", "sensor", "admission-control"},
		ExpectedNamespaces: []string{"stackrox", "rhacs-operator"},
		WebhookPatterns:    []string{"stackrox-admission-control"},
		CRDGroups:          []string{"platform.stackrox.io"},
		LabelSelectors:     []string{"app=central", "app=sensor"},
		RequireImageVerification: true,
	})

	// NeuVector
	r.register(&Engine{
		ID:       "neuvector",
		Name:     "NeuVector",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"neuvector/",
			"docker.io/neuvector/",
		},
		ImagePatterns: []string{
			"neuvector/controller",
			"neuvector/enforcer",
			"neuvector/manager",
			"neuvector/scanner",
		},
		DeploymentPatterns: []string{"neuvector-controller", "neuvector-manager"},
		ExpectedNamespaces: []string{"neuvector", "cattle-neuvector-system"},
		WebhookPatterns:    []string{"neuvector-validating", "neuvector-mutating"},
		CRDGroups:          []string{"neuvector.com"},
		LabelSelectors:     []string{"app=neuvector-controller-pod", "app=neuvector-enforcer-pod"},
		RequireImageVerification: true,
	})

	// CrowdStrike Falcon
	r.register(&Engine{
		ID:       "crowdstrike",
		Name:     "CrowdStrike Falcon",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"registry.crowdstrike.com/",
		},
		ImagePatterns: []string{
			"falcon-sensor",
			"falcon-container",
			"falcon-node-sensor",
		},
		DeploymentPatterns: []string{"falcon-sensor"},
		ExpectedNamespaces: []string{"falcon-system", "crowdstrike"},
		CRDGroups:          []string{"falcon.crowdstrike.com"},
		LabelSelectors:     []string{"app.kubernetes.io/name=falcon-sensor"},
		RequireImageVerification: true,
	})

	// Deepfence ThreatMapper
	r.register(&Engine{
		ID:       "deepfence",
		Name:     "Deepfence ThreatMapper",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"quay.io/deepfenceio/",
			"deepfenceio/",
		},
		ImagePatterns: []string{
			"deepfenceio/deepfence_agent",
			"deepfence-agent",
		},
		DeploymentPatterns: []string{"deepfence-agent"},
		ExpectedNamespaces: []string{"deepfence", "kube-system"},
		LabelSelectors:     []string{"app=deepfence-agent"},
		RequireImageVerification: true,
	})

	// Wiz Runtime Sensor
	r.register(&Engine{
		ID:       "wiz-runtime",
		Name:     "Wiz Runtime Sensor",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"wizio/",
			"wiziopublic/",
		},
		ImagePatterns: []string{
			"wiz-sensor",
			"wiz-kubernetes-connector",
		},
		DeploymentPatterns: []string{"wiz-sensor"},
		ExpectedNamespaces: []string{"wiz"},
		LabelSelectors:     []string{"app.kubernetes.io/name=wiz-sensor"},
		RequireImageVerification: true,
	})

	// Lacework
	r.register(&Engine{
		ID:       "lacework",
		Name:     "Lacework",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"lacework/",
		},
		ImagePatterns: []string{
			"lacework/datacollector",
			"lacework/k8s-collector",
		},
		DeploymentPatterns: []string{"lacework-agent"},
		ExpectedNamespaces: []string{"lacework"},
		LabelSelectors:     []string{"app=lacework-agent"},
		RequireImageVerification: true,
	})

	// Security Profiles Operator
	r.register(&Engine{
		ID:       "spo",
		Name:     "Security Profiles Operator",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"registry.k8s.io/",
			"k8s.gcr.io/",
			"gcr.io/k8s-staging-sp-operator/",
		},
		ImagePatterns: []string{
			"security-profiles-operator",
			"seccomp-operator",
		},
		DeploymentPatterns: []string{"security-profiles-operator", "seccomp-operator"},
		ExpectedNamespaces: []string{"security-profiles-operator", "kube-system"},
		CRDGroups:          []string{"security-profiles-operator.x-k8s.io"},
		LabelSelectors:     []string{"app=security-profiles-operator"},
		RequireImageVerification: true,
	})

	// Kubescape
	r.register(&Engine{
		ID:       "kubescape-runtime",
		Name:     "Kubescape",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"quay.io/kubescape/",
		},
		ImagePatterns: []string{
			"kubescape/kubescape",
			"kubescape/operator",
			"kubescape/node-agent",
		},
		DeploymentPatterns: []string{"kubescape", "kubescape-operator"},
		ExpectedNamespaces: []string{"kubescape", "armo-system"},
		CRDGroups:          []string{"spdx.softwarecomposition.kubescape.io"},
		LabelSelectors:     []string{"app=kubescape"},
		RequireImageVerification: true,
	})

	// AWS CloudWatch Agent / Fluent Bit for CloudWatch
	r.register(&Engine{
		ID:       "aws-cloudwatch",
		Name:     "AWS CloudWatch Agent",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"amazon/",
			"public.ecr.aws/",
		},
		ImagePatterns: []string{
			"cloudwatch-agent",
			"amazon/cloudwatch-agent",
			"aws-for-fluent-bit",
			"fluent-bit",
		},
		DeploymentPatterns: []string{"cloudwatch-agent", "fluent-bit"},
		ExpectedNamespaces: []string{"amazon-cloudwatch", "kube-system", "logging"},
		LabelSelectors:     []string{"app.kubernetes.io/name=cloudwatch-agent", "k8s-app=fluent-bit"},
		RequireImageVerification: true,
	})

	// AWS GuardDuty EKS Runtime Monitoring
	r.register(&Engine{
		ID:       "aws-guardduty",
		Name:     "AWS GuardDuty EKS",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"amazon/",
			"public.ecr.aws/",
		},
		ImagePatterns: []string{
			"guardduty-agent",
			"eks-guardduty",
		},
		DeploymentPatterns: []string{"guardduty-agent"},
		ExpectedNamespaces: []string{"amazon-guardduty", "kube-system"},
		LabelSelectors:     []string{"app.kubernetes.io/name=guardduty-agent"},
		RequireImageVerification: true,
	})

	// GCP Cloud Logging Agent (Stackdriver)
	r.register(&Engine{
		ID:       "gcp-cloud-logging",
		Name:     "GCP Cloud Logging",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"gcr.io/",
			"gke.gcr.io/",
		},
		ImagePatterns: []string{
			"stackdriver-logging-agent",
			"fluentd-gcp",
			"fluent-bit-gke-exporter",
			"gke-logging-agent",
		},
		DeploymentPatterns: []string{"fluentd-gcp", "stackdriver-log-aggregator"},
		ExpectedNamespaces: []string{"kube-system", "gke-system"},
		LabelSelectors:     []string{"k8s-app=fluentd-gcp", "component=fluentd-gcp"},
		RequireImageVerification: true,
	})

	// GCP Security Command Center
	r.register(&Engine{
		ID:       "gcp-scc",
		Name:     "GCP Security Command Center",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"gcr.io/",
		},
		ImagePatterns: []string{
			"scc-agent",
			"container-threat-detection",
		},
		ExpectedNamespaces: []string{"gke-system", "kube-system"},
		RequireImageVerification: true,
	})

	// Azure Monitor Container Insights
	r.register(&Engine{
		ID:       "azure-monitor",
		Name:     "Azure Monitor Container Insights",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azuremonitor/containerinsights",
			"oms-agent",
			"omsagent",
			"ama-logs",
			"azure-monitor-agent",
		},
		DeploymentPatterns: []string{"omsagent", "ama-logs"},
		ExpectedNamespaces: []string{"kube-system", "azure-monitor"},
		LabelSelectors:     []string{"component=oms-agent", "rsName=omsagent"},
		RequireImageVerification: true,
	})

	// Azure Defender for Kubernetes
	r.register(&Engine{
		ID:       "azure-defender",
		Name:     "Azure Defender for Kubernetes",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azuredefender/",
			"azure-defender",
			"microsoft-defender",
		},
		DeploymentPatterns: []string{"azure-defender", "defender-publisher"},
		ExpectedNamespaces: []string{"kube-system", "microsoft-defender"},
		LabelSelectors:     []string{"app=defender-publisher"},
		RequireImageVerification: true,
	})

	// Datadog Agent
	r.register(&Engine{
		ID:       "datadog",
		Name:     "Datadog Agent",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"datadog/",
			"gcr.io/datadoghq/",
		},
		ImagePatterns: []string{
			"datadog/agent",
			"datadog-agent",
			"datadog/cluster-agent",
		},
		DeploymentPatterns: []string{"datadog-agent", "datadog-cluster-agent"},
		ExpectedNamespaces: []string{"datadog", "kube-system"},
		CRDGroups:          []string{"datadoghq.com"},
		LabelSelectors:     []string{"app=datadog-agent", "app.kubernetes.io/name=datadog-agent-deployment"},
		RequireImageVerification: true,
	})

	// Splunk Connect for Kubernetes
	r.register(&Engine{
		ID:       "splunk",
		Name:     "Splunk Connect",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"docker.io/splunk/",
			"splunk/",
		},
		ImagePatterns: []string{
			"splunk/fluentd-hec",
			"splunk/splunk-otel-collector",
			"splunk-otel-collector-k8s",
		},
		DeploymentPatterns: []string{"splunk-otel-collector"},
		ExpectedNamespaces: []string{"splunk", "kube-system"},
		LabelSelectors:     []string{"app=splunk-otel-collector"},
		RequireImageVerification: true,
	})

	// Elastic Agent / Filebeat
	r.register(&Engine{
		ID:       "elastic",
		Name:     "Elastic Agent",
		Category: CategoryAudit,
		TrustedRegistries: []string{
			"docker.elastic.co/",
		},
		ImagePatterns: []string{
			"elastic-agent",
			"filebeat",
			"metricbeat",
		},
		DeploymentPatterns: []string{"elastic-agent", "filebeat"},
		ExpectedNamespaces: []string{"elastic-system", "kube-system"},
		CRDGroups:          []string{"agent.k8s.elastic.co"},
		LabelSelectors:     []string{"app=elastic-agent"},
		RequireImageVerification: true,
	})
}
