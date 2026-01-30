package admission

// registerRuntimeEngines registers all runtime security engines
func (r *EngineRegistry) registerRuntimeEngines() {
	// Falco
	r.register(&Engine{
		ID:       "falco",
		Name:     "Falco",
		Category: CategoryRuntime,
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
		LabelSelectors:     []string{"app=falco", "app.kubernetes.io/name=falco"},
		RequireImageVerification: true,
	})

	// Tetragon (Cilium)
	r.register(&Engine{
		ID:       "tetragon",
		Name:     "Tetragon",
		Category: CategoryRuntime,
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

	// Tracee (Aqua)
	r.register(&Engine{
		ID:       "tracee",
		Name:     "Tracee",
		Category: CategoryRuntime,
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

	// KubeArmor
	r.register(&Engine{
		ID:       "kubearmor",
		Name:     "KubeArmor",
		Category: CategoryRuntime,
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

	// Security Profiles Operator
	r.register(&Engine{
		ID:       "spo",
		Name:     "Security Profiles Operator",
		Category: CategoryRuntime,
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

	// Kubescape Runtime
	r.register(&Engine{
		ID:       "kubescape",
		Name:     "Kubescape",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"quay.io/kubescape/",
		},
		ImagePatterns: []string{
			"kubescape/kubescape",
			"kubescape/operator",
		},
		DeploymentPatterns: []string{"kubescape", "kubescape-operator"},
		ExpectedNamespaces: []string{"kubescape", "armo-system"},
		CRDGroups:          []string{"spdx.softwarecomposition.kubescape.io"},
		LabelSelectors:     []string{"app=kubescape"},
		RequireImageVerification: true,
	})

	// Deepfence ThreatMapper
	r.register(&Engine{
		ID:       "deepfence",
		Name:     "Deepfence ThreatMapper",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"quay.io/deepfenceio/",
			"deepfenceio/",
		},
		ImagePatterns: []string{
			"deepfenceio/deepfence_agent",
			"deepfence",
		},
		DeploymentPatterns: []string{"deepfence-agent"},
		ExpectedNamespaces: []string{"deepfence", "kube-system"},
		RequireImageVerification: true,
	})

	// CrowdStrike Falcon
	r.register(&Engine{
		ID:       "crowdstrike",
		Name:     "CrowdStrike Falcon",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"registry.crowdstrike.com/",
		},
		ImagePatterns: []string{
			"falcon-sensor",
			"falcon-container",
		},
		DeploymentPatterns: []string{"falcon-sensor"},
		ExpectedNamespaces: []string{"falcon-system", "crowdstrike"},
		CRDGroups:          []string{"falcon.crowdstrike.com"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// CNAPP Platforms with Runtime Security Capabilities
	// =============================================================================

	// Aqua Security - Runtime protection and enforcement
	r.register(&Engine{
		ID:       "aqua",
		Name:     "Aqua Security",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"aquasec/",
			"registry.aquasec.com/",
		},
		ImagePatterns: []string{
			"aquasec/enforcer",
			"aquasec/kube-enforcer",
			"aquasec/aqua-scanner",
		},
		DeploymentPatterns: []string{"aqua-enforcer", "aqua-kube-enforcer"},
		ExpectedNamespaces: []string{"aqua", "aqua-security"},
		LabelSelectors:     []string{"app=aqua-enforcer"},
		RequireImageVerification: true,
	})

	// Prisma Cloud - Runtime protection
	r.register(&Engine{
		ID:       "prisma",
		Name:     "Prisma Cloud",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"registry.twistlock.com/",
		},
		ImagePatterns: []string{
			"twistlock/defender",
			"twistlock/console",
		},
		DeploymentPatterns: []string{"twistlock-defender", "twistlock-console"},
		ExpectedNamespaces: []string{"twistlock", "prisma-cloud"},
		LabelSelectors:     []string{"app=twistlock-defender"},
		RequireImageVerification: true,
	})

	// Sysdig Secure - Runtime detection and response
	r.register(&Engine{
		ID:       "sysdig",
		Name:     "Sysdig Secure",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"quay.io/sysdig/",
			"sysdig/",
		},
		ImagePatterns: []string{
			"sysdig/agent",
			"sysdig/node-analyzer",
			"sysdig/workload-agent",
		},
		DeploymentPatterns: []string{"sysdig-agent"},
		ExpectedNamespaces: []string{"sysdig", "sysdig-agent"},
		LabelSelectors:     []string{"app=sysdig-agent", "app.kubernetes.io/name=sysdig"},
		RequireImageVerification: true,
	})

	// StackRox/RHACS - Runtime security
	r.register(&Engine{
		ID:       "stackrox",
		Name:     "StackRox/RHACS",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"quay.io/stackrox-io/",
			"registry.redhat.io/advanced-cluster-security/",
		},
		ImagePatterns: []string{
			"stackrox/main",
			"stackrox/collector",
			"rhacs/main",
			"rhacs/collector",
		},
		DeploymentPatterns: []string{"central", "sensor", "collector"},
		ExpectedNamespaces: []string{"stackrox", "rhacs-operator"},
		CRDGroups:          []string{"platform.stackrox.io"},
		LabelSelectors:     []string{"app=central", "app=sensor", "app=collector"},
		RequireImageVerification: true,
	})

	// NeuVector - Runtime protection
	r.register(&Engine{
		ID:       "neuvector",
		Name:     "NeuVector",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"neuvector/",
			"docker.io/neuvector/",
		},
		ImagePatterns: []string{
			"neuvector/enforcer",
			"neuvector/controller",
			"neuvector/scanner",
		},
		DeploymentPatterns: []string{"neuvector-controller-pod", "neuvector-enforcer-pod"},
		ExpectedNamespaces: []string{"neuvector", "cattle-neuvector-system"},
		CRDGroups:          []string{"neuvector.com"},
		LabelSelectors:     []string{"app=neuvector-controller-pod", "app=neuvector-enforcer-pod"},
		RequireImageVerification: true,
	})

	// Wiz Runtime Sensor
	r.register(&Engine{
		ID:       "wiz",
		Name:     "Wiz",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"wizio/",
			"wiziopublic.azurecr.io/",
		},
		ImagePatterns: []string{
			"wiz-sensor",
			"wiz-kubernetes-connector",
		},
		DeploymentPatterns: []string{"wiz-sensor", "wiz-kubernetes-connector"},
		ExpectedNamespaces: []string{"wiz", "kube-system"},
		LabelSelectors:     []string{"app=wiz-sensor"},
		RequireImageVerification: true,
	})

	// Lacework - Runtime anomaly detection
	r.register(&Engine{
		ID:       "lacework",
		Name:     "Lacework",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"lacework/",
		},
		ImagePatterns: []string{
			"lacework/datacollector",
			"lacework/k8s-controller",
		},
		DeploymentPatterns: []string{"lacework-agent"},
		ExpectedNamespaces: []string{"lacework", "kube-system"},
		LabelSelectors:     []string{"app.kubernetes.io/name=lacework-agent"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Cloud-Specific Runtime Environments
	// =============================================================================

	// AWS Bottlerocket
	r.register(&Engine{
		ID:       "aws-bottlerocket",
		Name:     "AWS Bottlerocket",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"public.ecr.aws/bottlerocket/",
		},
		ImagePatterns: []string{
			"bottlerocket-update-operator",
			"bottlerocket-control-container",
		},
		DeploymentPatterns: []string{"bottlerocket-update-operator"},
		ExpectedNamespaces: []string{"brupop-bottlerocket-aws", "kube-system"},
		CRDGroups:          []string{"brupop.bottlerocket.aws"},
		LabelSelectors:     []string{"app.kubernetes.io/name=brupop"},
		RequireImageVerification: true,
	})

	// AWS Firecracker (via RuntimeClass)
	r.register(&Engine{
		ID:       "aws-firecracker",
		Name:     "AWS Firecracker",
		Category: CategoryRuntime,
		ImagePatterns: []string{
			"firecracker-containerd",
			"aws-firecracker",
		},
		ExpectedNamespaces: []string{"kube-system"},
		RequireImageVerification: true,
	})

	// GKE Sandbox (gVisor)
	r.register(&Engine{
		ID:       "gke-sandbox",
		Name:     "GKE Sandbox (gVisor)",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"gke.gcr.io/",
			"gcr.io/gke-release/",
		},
		ImagePatterns: []string{
			"gvisor-runsc",
			"gke-sandbox",
			"gvisor",
		},
		ExpectedNamespaces: []string{"kube-system", "gke-system"},
		RequireImageVerification: true,
	})

	// Azure Kata Containers
	r.register(&Engine{
		ID:       "azure-kata",
		Name:     "Azure Kata Containers",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"kata-runtime",
			"kata-agent",
			"kata-containers",
		},
		ExpectedNamespaces: []string{"kube-system"},
		RequireImageVerification: true,
	})

	// Azure Confidential Containers
	r.register(&Engine{
		ID:       "azure-confidential",
		Name:     "Azure Confidential Containers",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"aci-cc",
			"confidential-containers",
			"cc-operator",
		},
		DeploymentPatterns: []string{"cc-operator-controller-manager"},
		ExpectedNamespaces: []string{"confidential-containers-system"},
		CRDGroups:          []string{"confidentialcontainers.org"},
		RequireImageVerification: true,
	})

	// Kata Containers (generic)
	r.register(&Engine{
		ID:       "kata-containers",
		Name:     "Kata Containers",
		Category: CategoryRuntime,
		TrustedRegistries: []string{
			"quay.io/kata-containers/",
		},
		ImagePatterns: []string{
			"kata-deploy",
			"kata-runtime",
		},
		DeploymentPatterns: []string{"kata-deploy"},
		ExpectedNamespaces: []string{"kube-system", "kata-system"},
		RequireImageVerification: true,
	})
}
