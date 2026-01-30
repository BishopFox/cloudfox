package admission

// registerMultitenancyEngines registers all multitenancy engines
func (r *EngineRegistry) registerMultitenancyEngines() {
	// Hierarchical Namespace Controller (HNC)
	r.register(&Engine{
		ID:       "hnc",
		Name:     "Hierarchical Namespace Controller",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"gcr.io/k8s-staging-multitenancy/",
			"registry.k8s.io/",
		},
		ImagePatterns: []string{
			"hnc-manager",
			"hierarchical-namespace-controller",
		},
		DeploymentPatterns: []string{"hnc-controller-manager"},
		ExpectedNamespaces: []string{"hnc-system", "kube-system"},
		WebhookPatterns:    []string{"hnc-validating", "hnc-mutating"},
		CRDGroups:          []string{"hnc.x-k8s.io"},
		LabelSelectors:     []string{"control-plane=controller-manager", "app=hnc-manager"},
		RequireImageVerification: true,
	})

	// Capsule
	r.register(&Engine{
		ID:       "capsule",
		Name:     "Capsule",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"quay.io/clastix/",
			"ghcr.io/clastix/",
		},
		ImagePatterns: []string{
			"clastix/capsule",
			"capsule",
		},
		DeploymentPatterns: []string{"capsule-controller-manager"},
		ExpectedNamespaces: []string{"capsule-system", "kube-system"},
		WebhookPatterns:    []string{"capsule-validating", "capsule-mutating"},
		CRDGroups:          []string{"capsule.clastix.io"},
		LabelSelectors:     []string{"control-plane=controller-manager", "app=capsule"},
		RequireImageVerification: true,
	})

	// vCluster
	r.register(&Engine{
		ID:       "vcluster",
		Name:     "vCluster",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"loftsh/",
			"ghcr.io/loft-sh/",
		},
		ImagePatterns: []string{
			"loftsh/vcluster",
			"vcluster",
			"vcluster-pro",
		},
		DeploymentPatterns: []string{"vcluster"},
		ExpectedNamespaces: []string{}, // Can be any namespace
		CRDGroups:          []string{"storage.loft.sh"},
		LabelSelectors:     []string{"app=vcluster", "release=vcluster"},
		RequireImageVerification: true,
	})

	// Loft
	r.register(&Engine{
		ID:       "loft",
		Name:     "Loft",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"loftsh/",
			"ghcr.io/loft-sh/",
		},
		ImagePatterns: []string{
			"loftsh/loft",
			"loft",
			"loft-agent",
		},
		DeploymentPatterns: []string{"loft", "loft-agent"},
		ExpectedNamespaces: []string{"loft", "loft-system"},
		WebhookPatterns:    []string{"loft-webhook"},
		CRDGroups:          []string{"management.loft.sh", "cluster.loft.sh", "storage.loft.sh"},
		LabelSelectors:     []string{"app=loft", "app.kubernetes.io/name=loft"},
		RequireImageVerification: true,
	})

	// Kiosk
	r.register(&Engine{
		ID:       "kiosk",
		Name:     "Kiosk",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"loftsh/",
			"ghcr.io/loft-sh/",
		},
		ImagePatterns: []string{
			"loftsh/kiosk",
			"kiosk",
		},
		DeploymentPatterns: []string{"kiosk"},
		ExpectedNamespaces: []string{"kiosk", "kube-system"},
		WebhookPatterns:    []string{"kiosk-webhook"},
		CRDGroups:          []string{"tenancy.kiosk.sh", "config.kiosk.sh"},
		LabelSelectors:     []string{"app=kiosk"},
		RequireImageVerification: true,
	})

	// Rancher
	r.register(&Engine{
		ID:       "rancher",
		Name:     "Rancher",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"rancher/",
			"docker.io/rancher/",
		},
		ImagePatterns: []string{
			"rancher/rancher",
			"rancher/rancher-agent",
		},
		DeploymentPatterns: []string{"rancher"},
		ExpectedNamespaces: []string{"cattle-system", "rancher"},
		WebhookPatterns:    []string{"rancher-webhook"},
		CRDGroups:          []string{"management.cattle.io", "project.cattle.io", "catalog.cattle.io"},
		LabelSelectors:     []string{"app=rancher"},
		RequireImageVerification: true,
	})

	// OpenShift Project (namespace isolation)
	r.register(&Engine{
		ID:       "openshift-project",
		Name:     "OpenShift Project",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"quay.io/openshift/",
			"registry.redhat.io/",
		},
		ImagePatterns: []string{
			"openshift/origin",
			"openshift-controller-manager",
		},
		DeploymentPatterns: []string{"openshift-controller-manager"},
		ExpectedNamespaces: []string{"openshift-controller-manager"},
		CRDGroups:          []string{"project.openshift.io"},
		RequireImageVerification: true,
	})

	// Kamaji
	r.register(&Engine{
		ID:       "kamaji",
		Name:     "Kamaji",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"quay.io/clastix/",
			"ghcr.io/clastix/",
		},
		ImagePatterns: []string{
			"clastix/kamaji",
			"kamaji",
		},
		DeploymentPatterns: []string{"kamaji-controller-manager"},
		ExpectedNamespaces: []string{"kamaji-system", "kube-system"},
		CRDGroups:          []string{"kamaji.clastix.io"},
		LabelSelectors:     []string{"control-plane=controller-manager", "app=kamaji"},
		RequireImageVerification: true,
	})

	// Karmada - multi-cluster management
	r.register(&Engine{
		ID:       "karmada",
		Name:     "Karmada",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"docker.io/karmada/",
			"karmada/",
		},
		ImagePatterns: []string{
			"karmada/karmada-controller-manager",
			"karmada/karmada-scheduler",
			"karmada/karmada-webhook",
			"karmada/karmada-agent",
		},
		DeploymentPatterns: []string{"karmada-controller-manager", "karmada-scheduler", "karmada-webhook"},
		ExpectedNamespaces: []string{"karmada-system", "kube-system"},
		WebhookPatterns:    []string{"karmada-webhook"},
		CRDGroups:          []string{"cluster.karmada.io", "policy.karmada.io", "work.karmada.io"},
		LabelSelectors:     []string{"app=karmada-controller-manager", "app.kubernetes.io/name=karmada"},
		RequireImageVerification: true,
	})

	// Admiralty - multi-cluster scheduling
	r.register(&Engine{
		ID:       "admiralty",
		Name:     "Admiralty",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"quay.io/admiralty/",
		},
		ImagePatterns: []string{
			"admiralty/multicluster-scheduler",
			"admiralty",
		},
		DeploymentPatterns: []string{"admiralty-multicluster-scheduler"},
		ExpectedNamespaces: []string{"admiralty", "kube-system"},
		WebhookPatterns:    []string{"admiralty"},
		CRDGroups:          []string{"multicluster.admiralty.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=multicluster-scheduler"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Policy Engines with Multitenancy Capabilities
	// =============================================================================

	// OPA Gatekeeper - Can enforce namespace isolation and tenant constraints
	r.register(&Engine{
		ID:       "gatekeeper",
		Name:     "OPA Gatekeeper",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"openpolicyagent/",
			"quay.io/gatekeeper/",
			"docker.io/openpolicyagent/",
		},
		ImagePatterns: []string{
			"openpolicyagent/gatekeeper",
			"gatekeeper",
		},
		DeploymentPatterns: []string{"gatekeeper-controller-manager", "gatekeeper-audit"},
		ExpectedNamespaces: []string{"gatekeeper-system", "kube-system"},
		WebhookPatterns:    []string{"gatekeeper-validating", "gatekeeper-mutating"},
		CRDGroups:          []string{"constraints.gatekeeper.sh", "templates.gatekeeper.sh"},
		LabelSelectors:     []string{"control-plane=controller-manager", "gatekeeper.sh/system=yes"},
		RequireImageVerification: true,
	})

	// Kyverno - Can enforce namespace policies and tenant isolation
	r.register(&Engine{
		ID:       "kyverno",
		Name:     "Kyverno",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"ghcr.io/kyverno/",
			"nirmata/",
			"docker.io/nirmata/",
		},
		ImagePatterns: []string{
			"kyverno/kyverno",
			"kyverno",
			"nirmata/kyverno",
		},
		DeploymentPatterns: []string{"kyverno", "kyverno-admission-controller"},
		ExpectedNamespaces: []string{"kyverno", "kube-system"},
		WebhookPatterns:    []string{"kyverno-resource-validating", "kyverno-resource-mutating"},
		CRDGroups:          []string{"kyverno.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=kyverno", "app=kyverno"},
		RequireImageVerification: true,
	})

	// Kubewarden - Can enforce multitenancy policies
	r.register(&Engine{
		ID:       "kubewarden",
		Name:     "Kubewarden",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"ghcr.io/kubewarden/",
		},
		ImagePatterns: []string{
			"kubewarden/policy-server",
			"kubewarden/kubewarden-controller",
		},
		DeploymentPatterns: []string{"kubewarden-controller", "policy-server"},
		ExpectedNamespaces: []string{"kubewarden", "kubewarden-system"},
		WebhookPatterns:    []string{"kubewarden"},
		CRDGroups:          []string{"policies.kubewarden.io"},
		LabelSelectors:     []string{"app=kubewarden-policy-server", "app.kubernetes.io/name=kubewarden-controller"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Cloud-Specific Resource Management
	// =============================================================================

	// AWS Controllers for Kubernetes (ACK)
	r.register(&Engine{
		ID:       "aws-ack",
		Name:     "AWS Controllers for Kubernetes",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"public.ecr.aws/aws-controllers-k8s/",
		},
		ImagePatterns: []string{
			"aws-controllers-k8s/",
			"ack-",
		},
		DeploymentPatterns: []string{"ack-", "-controller"},
		ExpectedNamespaces: []string{"ack-system", "kube-system"},
		CRDGroups:          []string{"services.k8s.aws"},
		LabelSelectors:     []string{"app.kubernetes.io/name=ack"},
		RequireImageVerification: true,
	})

	// GCP Config Connector
	r.register(&Engine{
		ID:       "gcp-config-connector",
		Name:     "GCP Config Connector",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"gcr.io/cnrm-eap/",
			"gcr.io/gke-release/",
		},
		ImagePatterns: []string{
			"cnrm-controller-manager",
			"cnrm-webhook-manager",
			"cnrm-deletiondefender",
			"cnrm-resource-stats-recorder",
		},
		DeploymentPatterns: []string{"cnrm-controller-manager", "cnrm-webhook-manager"},
		ExpectedNamespaces: []string{"cnrm-system", "configconnector-operator-system"},
		WebhookPatterns:    []string{"cnrm-validating", "cnrm-mutating"},
		CRDGroups:          []string{"core.cnrm.cloud.google.com", "iam.cnrm.cloud.google.com"},
		LabelSelectors:     []string{"cnrm.cloud.google.com/component=cnrm-controller-manager"},
		RequireImageVerification: true,
	})

	// Azure Service Operator
	r.register(&Engine{
		ID:       "azure-service-operator",
		Name:     "Azure Service Operator",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azure-service-operator",
			"aso-controller",
		},
		DeploymentPatterns: []string{"azureserviceoperator-controller-manager"},
		ExpectedNamespaces: []string{"azureserviceoperator-system", "kube-system"},
		WebhookPatterns:    []string{"azureserviceoperator-validating", "azureserviceoperator-mutating"},
		CRDGroups:          []string{"resources.azure.com", "containerservice.azure.com"},
		LabelSelectors:     []string{"control-plane=controller-manager"},
		RequireImageVerification: true,
	})

	// Crossplane (multi-cloud resource management)
	r.register(&Engine{
		ID:       "crossplane",
		Name:     "Crossplane",
		Category: CategoryMultitenancy,
		TrustedRegistries: []string{
			"crossplane/",
			"xpkg.upbound.io/",
		},
		ImagePatterns: []string{
			"crossplane/crossplane",
			"crossplane-runtime",
			"provider-",
		},
		DeploymentPatterns: []string{"crossplane", "crossplane-rbac-manager"},
		ExpectedNamespaces: []string{"crossplane-system", "upbound-system"},
		WebhookPatterns:    []string{"crossplane"},
		CRDGroups:          []string{"pkg.crossplane.io", "apiextensions.crossplane.io"},
		LabelSelectors:     []string{"app=crossplane", "app.kubernetes.io/name=crossplane"},
		RequireImageVerification: true,
	})
}
