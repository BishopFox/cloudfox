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
}
