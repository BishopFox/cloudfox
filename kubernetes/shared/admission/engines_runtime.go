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
}
