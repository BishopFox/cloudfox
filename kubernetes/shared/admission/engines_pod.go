package admission

// registerPodEngines registers all pod security/policy engines
func (r *EngineRegistry) registerPodEngines() {
	// OPA Gatekeeper
	r.register(&Engine{
		ID:       "gatekeeper",
		Name:     "OPA Gatekeeper",
		Category: CategoryPod,
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
		CRDGroups:          []string{"gatekeeper.sh", "constraints.gatekeeper.sh", "templates.gatekeeper.sh"},
		LabelSelectors:     []string{"control-plane=controller-manager", "gatekeeper.sh/system=yes"},
		RequireImageVerification: true,
	})

	// Kyverno
	r.register(&Engine{
		ID:       "kyverno",
		Name:     "Kyverno",
		Category: CategoryPod,
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

	// Pod Security Admission (built-in)
	r.register(&Engine{
		ID:       "psa",
		Name:     "Pod Security Admission",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"registry.k8s.io/",
			"k8s.gcr.io/",
		},
		ImagePatterns:            []string{}, // Built into API server
		DeploymentPatterns:       []string{},
		ExpectedNamespaces:       []string{"kube-system"},
		LabelSelectors:           []string{"pod-security.kubernetes.io/enforce"},
		RequireImageVerification: false, // Built-in feature
	})

	// Polaris
	r.register(&Engine{
		ID:       "polaris",
		Name:     "Polaris",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"quay.io/fairwinds/",
			"fairwinds/",
		},
		ImagePatterns: []string{
			"fairwinds/polaris",
			"polaris",
		},
		DeploymentPatterns: []string{"polaris"},
		ExpectedNamespaces: []string{"polaris", "kube-system"},
		WebhookPatterns:    []string{"polaris-webhook"},
		LabelSelectors:     []string{"app=polaris", "app.kubernetes.io/name=polaris"},
		RequireImageVerification: true,
	})

	// Datree
	r.register(&Engine{
		ID:       "datree",
		Name:     "Datree",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"datree/",
			"docker.io/datree/",
		},
		ImagePatterns: []string{
			"datree/admission-webhook",
			"datree/webhook-server",
		},
		DeploymentPatterns: []string{"datree-webhook"},
		ExpectedNamespaces: []string{"datree", "kube-system"},
		WebhookPatterns:    []string{"datree-webhook"},
		LabelSelectors:     []string{"app=datree-webhook"},
		RequireImageVerification: true,
	})

	// Kubewarden (also used for pod security)
	r.register(&Engine{
		ID:       "kubewarden-pod",
		Name:     "Kubewarden",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"ghcr.io/kubewarden/",
			"docker.io/kubewarden/",
		},
		ImagePatterns: []string{
			"kubewarden/policy-server",
			"kubewarden/kubewarden-controller",
		},
		DeploymentPatterns: []string{"kubewarden-controller", "policy-server"},
		ExpectedNamespaces: []string{"kubewarden", "kube-system"},
		WebhookPatterns:    []string{"kubewarden"},
		CRDGroups:          []string{"policies.kubewarden.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=kubewarden"},
		RequireImageVerification: true,
	})

	// Copper
	r.register(&Engine{
		ID:       "copper",
		Name:     "Copper",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"cloud66/",
		},
		ImagePatterns: []string{
			"copper-webhook",
		},
		DeploymentPatterns: []string{"copper"},
		ExpectedNamespaces: []string{"copper", "kube-system"},
		WebhookPatterns:    []string{"copper"},
		RequireImageVerification: true,
	})

	// K-Rail
	r.register(&Engine{
		ID:       "krail",
		Name:     "K-Rail",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"cruise/",
			"ghcr.io/cruise-automation/",
		},
		ImagePatterns: []string{
			"cruise-automation/k-rail",
			"k-rail",
		},
		DeploymentPatterns: []string{"k-rail"},
		ExpectedNamespaces: []string{"k-rail", "kube-system"},
		WebhookPatterns:    []string{"k-rail"},
		RequireImageVerification: true,
	})

	// jsPolicy
	r.register(&Engine{
		ID:       "jspolicy",
		Name:     "jsPolicy",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"loftsh/",
			"ghcr.io/loft-sh/",
		},
		ImagePatterns: []string{
			"loftsh/jspolicy",
			"loft-sh/jspolicy",
			"jspolicy",
		},
		DeploymentPatterns: []string{"jspolicy", "jspolicy-controller"},
		ExpectedNamespaces: []string{"jspolicy", "kube-system"},
		WebhookPatterns:    []string{"jspolicy"},
		CRDGroups:          []string{"policy.jspolicy.com"},
		LabelSelectors:     []string{"app=jspolicy", "app.kubernetes.io/name=jspolicy"},
		RequireImageVerification: true,
	})

	// Kube-LINTER (pod linting)
	r.register(&Engine{
		ID:       "kube-linter",
		Name:     "KubeLinter",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"stackrox/",
			"quay.io/stackrox/",
		},
		ImagePatterns: []string{
			"kube-linter",
			"stackrox/kube-linter",
		},
		DeploymentPatterns: []string{"kube-linter"},
		ExpectedNamespaces: []string{"kube-linter", "kube-system"},
		WebhookPatterns:    []string{"kube-linter"},
		RequireImageVerification: true,
	})

	// Conftest (OPA-based testing)
	r.register(&Engine{
		ID:       "conftest",
		Name:     "Conftest",
		Category: CategoryPod,
		TrustedRegistries: []string{
			"openpolicyagent/",
		},
		ImagePatterns: []string{
			"conftest",
			"openpolicyagent/conftest",
		},
		DeploymentPatterns: []string{"conftest"},
		ExpectedNamespaces: []string{"conftest", "kube-system"},
		WebhookPatterns:    []string{"conftest"},
		RequireImageVerification: true,
	})
}
