package admission

// registerImageEngines registers all image admission controller engines
func (r *EngineRegistry) registerImageEngines() {
	// Portieris - IBM image signature verification
	r.register(&Engine{
		ID:       "portieris",
		Name:     "Portieris",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"docker.io/",
			"icr.io/",
			"quay.io/",
		},
		ImagePatterns: []string{
			"ibmcom/portieris",
			"portieris",
		},
		DeploymentPatterns: []string{"portieris"},
		ExpectedNamespaces: []string{"portieris", "ibm-system", "kube-system"},
		WebhookPatterns:    []string{"portieris", "image-admission"},
		CRDGroups:          []string{"portieris.cloud.ibm.com"},
		LabelSelectors:     []string{"app=portieris", "app.kubernetes.io/name=portieris"},
		RequireImageVerification: true,
	})

	// Connaisseur - signature verification
	r.register(&Engine{
		ID:       "connaisseur",
		Name:     "Connaisseur",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"docker.io/",
			"ghcr.io/",
		},
		ImagePatterns: []string{
			"securesystemsengineering/connaisseur",
			"connaisseur",
		},
		DeploymentPatterns: []string{"connaisseur"},
		ExpectedNamespaces: []string{"connaisseur", "kube-system"},
		WebhookPatterns:    []string{"connaisseur"},
		LabelSelectors:     []string{"app=connaisseur", "app.kubernetes.io/name=connaisseur"},
		RequireImageVerification: true,
	})

	// Ratify - Microsoft artifact verification
	r.register(&Engine{
		ID:       "ratify",
		Name:     "Ratify",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/",
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"ratify-project/ratify",
			"deislabs/ratify",
			"ratify",
		},
		DeploymentPatterns: []string{"ratify"},
		ExpectedNamespaces: []string{"ratify", "gatekeeper-system", "kube-system"},
		WebhookPatterns:    []string{"ratify"},
		CRDGroups:          []string{"config.ratify.deislabs.io"},
		LabelSelectors:     []string{"app=ratify", "app.kubernetes.io/name=ratify"},
		RequireImageVerification: true,
	})

	// Kritis - Google attestation
	r.register(&Engine{
		ID:       "kritis",
		Name:     "Kritis",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"gcr.io/",
			"us-docker.pkg.dev/",
		},
		ImagePatterns: []string{
			"kritis-project/kritis-signer",
			"kritis-signer",
			"kritis",
		},
		DeploymentPatterns: []string{"kritis"},
		ExpectedNamespaces: []string{"kritis", "kube-system"},
		WebhookPatterns:    []string{"kritis"},
		CRDGroups:          []string{"kritis.grafeas.io"},
		RequireImageVerification: true,
	})

	// Sigstore Policy Controller
	r.register(&Engine{
		ID:       "sigstore",
		Name:     "Sigstore Policy Controller",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/",
			"gcr.io/",
		},
		ImagePatterns: []string{
			"sigstore/policy-controller",
			"policy-controller",
			"policy-webhook",
		},
		DeploymentPatterns: []string{"policy-controller", "policy-webhook"},
		ExpectedNamespaces: []string{"cosign-system", "sigstore-system", "kube-system"},
		WebhookPatterns:    []string{"policy.sigstore.dev", "cosign"},
		CRDGroups:          []string{"policy.sigstore.dev"},
		LabelSelectors:     []string{"app=policy-controller", "app.kubernetes.io/name=policy-controller"},
		RequireImageVerification: true,
	})

	// Notation / Notary v2
	r.register(&Engine{
		ID:       "notation",
		Name:     "Notation",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/",
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"notaryproject/notation",
			"notation",
		},
		DeploymentPatterns: []string{"notation"},
		ExpectedNamespaces: []string{"notation-system", "kube-system"},
		CRDGroups:          []string{"notation.cncf.io"},
		RequireImageVerification: true,
	})

	// GCP Binary Authorization
	r.register(&Engine{
		ID:       "gcp-binauth",
		Name:     "GCP Binary Authorization",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"gcr.io/",
			"us-docker.pkg.dev/",
		},
		ImagePatterns:      []string{}, // Uses ImagePolicyWebhook, no dedicated controller image
		DeploymentPatterns: []string{},
		ExpectedNamespaces: []string{"kube-system"},
		WebhookPatterns:    []string{"imagepolicywebhook.image-policy.k8s.io", "binaryauthorization"},
		RequireImageVerification: false, // Cloud-managed service
	})

	// AWS Signer
	r.register(&Engine{
		ID:       "aws-signer",
		Name:     "AWS Signer",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"public.ecr.aws/",
			"602401143452.dkr.ecr.", // AWS managed ECR
		},
		ImagePatterns:      []string{"aws-signer"},
		DeploymentPatterns: []string{"aws-signer"},
		ExpectedNamespaces: []string{"kube-system", "aws-signer"},
		CRDGroups:          []string{"signer.amazonaws.com"},
		RequireImageVerification: false, // AWS managed
	})

	// Aqua Security
	r.register(&Engine{
		ID:       "aqua",
		Name:     "Aqua Security",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"registry.aquasec.com/",
			"docker.io/aquasec/",
		},
		ImagePatterns: []string{
			"aquasec/kube-enforcer",
			"aquasec/aqua-enforcer",
			"aqua-enforcer",
			"kube-enforcer",
		},
		DeploymentPatterns: []string{"aqua-kube-enforcer", "aqua-enforcer"},
		ExpectedNamespaces: []string{"aqua", "aqua-security", "kube-system"},
		WebhookPatterns:    []string{"aqua", "kube-enforcer"},
		LabelSelectors:     []string{"app=aqua-kube-enforcer"},
		RequireImageVerification: true,
	})

	// Prisma Cloud / Twistlock
	r.register(&Engine{
		ID:       "prisma",
		Name:     "Prisma Cloud",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"registry.twistlock.com/",
			"registry-auth.twistlock.com/",
		},
		ImagePatterns: []string{
			"twistlock/defender",
			"prismacloud/defender",
			"twistlock-defender",
		},
		DeploymentPatterns: []string{"twistlock-defender", "prisma-defender"},
		ExpectedNamespaces: []string{"twistlock", "prisma-cloud", "kube-system"},
		WebhookPatterns:    []string{"twistlock", "prisma"},
		RequireImageVerification: true,
	})

	// Sysdig Secure
	r.register(&Engine{
		ID:       "sysdig",
		Name:     "Sysdig Secure",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"quay.io/sysdig/",
			"docker.io/sysdig/",
		},
		ImagePatterns: []string{
			"sysdig/admission-controller",
			"sysdig/agent",
		},
		DeploymentPatterns: []string{"sysdig-admission-controller"},
		ExpectedNamespaces: []string{"sysdig", "sysdig-agent", "kube-system"},
		WebhookPatterns:    []string{"sysdig"},
		RequireImageVerification: true,
	})

	// NeuVector
	r.register(&Engine{
		ID:       "neuvector",
		Name:     "NeuVector",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"docker.io/neuvector/",
			"neuvector/",
		},
		ImagePatterns: []string{
			"neuvector/controller",
			"neuvector/enforcer",
			"neuvector/manager",
		},
		DeploymentPatterns: []string{"neuvector-controller", "neuvector-enforcer"},
		ExpectedNamespaces: []string{"neuvector", "kube-system"},
		WebhookPatterns:    []string{"neuvector"},
		RequireImageVerification: true,
	})

	// StackRox / Red Hat ACS
	r.register(&Engine{
		ID:       "stackrox",
		Name:     "StackRox/RHACS",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"quay.io/stackrox-io/",
			"registry.redhat.io/",
		},
		ImagePatterns: []string{
			"stackrox-io/main",
			"stackrox-io/scanner",
			"advanced-cluster-security/rhacs",
		},
		DeploymentPatterns: []string{"central", "sensor", "scanner"},
		ExpectedNamespaces: []string{"stackrox", "rhacs-operator", "kube-system"},
		WebhookPatterns:    []string{"stackrox", "acs"},
		CRDGroups:          []string{"platform.stackrox.io"},
		RequireImageVerification: true,
	})

	// Snyk Container
	r.register(&Engine{
		ID:       "snyk",
		Name:     "Snyk Container",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"docker.io/snyk/",
			"snyk/",
		},
		ImagePatterns: []string{
			"snyk/kubernetes-monitor",
			"snyk/snyk",
		},
		DeploymentPatterns: []string{"snyk-monitor"},
		ExpectedNamespaces: []string{"snyk-monitor", "kube-system"},
		WebhookPatterns:    []string{"snyk"},
		RequireImageVerification: true,
	})

	// Anchore Enterprise
	r.register(&Engine{
		ID:       "anchore",
		Name:     "Anchore Enterprise",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"docker.io/anchore/",
		},
		ImagePatterns: []string{
			"anchore/anchore-engine",
			"anchore/enterprise",
			"anchore/kai",
		},
		DeploymentPatterns: []string{"anchore-engine", "anchore-enterprise"},
		ExpectedNamespaces: []string{"anchore", "anchore-enterprise", "kube-system"},
		WebhookPatterns:    []string{"anchore"},
		RequireImageVerification: true,
	})

	// Trivy Operator
	r.register(&Engine{
		ID:       "trivy",
		Name:     "Trivy Operator",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/aquasecurity/",
			"docker.io/aquasec/",
		},
		ImagePatterns: []string{
			"aquasecurity/trivy-operator",
			"aquasec/trivy",
			"trivy-operator",
		},
		DeploymentPatterns: []string{"trivy-operator"},
		ExpectedNamespaces: []string{"trivy-system", "trivy-operator", "kube-system"},
		CRDGroups:          []string{"aquasecurity.github.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=trivy-operator"},
		RequireImageVerification: true,
	})

	// Kubewarden
	r.register(&Engine{
		ID:       "kubewarden",
		Name:     "Kubewarden",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/kubewarden/",
		},
		ImagePatterns: []string{
			"kubewarden/policy-server",
			"kubewarden/kubewarden-controller",
		},
		DeploymentPatterns: []string{"kubewarden-controller", "policy-server"},
		ExpectedNamespaces: []string{"kubewarden", "kubewarden-system", "kube-system"},
		WebhookPatterns:    []string{"kubewarden"},
		CRDGroups:          []string{"policies.kubewarden.io"},
		RequireImageVerification: true,
	})

	// Harbor
	r.register(&Engine{
		ID:       "harbor",
		Name:     "Harbor",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"goharbor/",
			"docker.io/goharbor/",
		},
		ImagePatterns: []string{
			"goharbor/harbor-core",
			"goharbor/trivy-adapter",
		},
		DeploymentPatterns: []string{"harbor-core", "harbor-trivy"},
		ExpectedNamespaces: []string{"harbor", "harbor-system"},
		RequireImageVerification: true,
	})

	// Clair
	r.register(&Engine{
		ID:       "clair",
		Name:     "Clair",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"quay.io/",
		},
		ImagePatterns: []string{
			"projectquay/clair",
			"quay.io/projectquay/clair",
			"clair/clair",
		},
		DeploymentPatterns: []string{"clair"},
		ExpectedNamespaces: []string{"clair", "quay", "quay-enterprise"},
		WebhookPatterns:    []string{"clair", "quay-clair"},
		RequireImageVerification: true,
	})

	// Azure Policy for AKS
	r.register(&Engine{
		ID:       "azure-policy",
		Name:     "Azure Policy",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azure-policy/policy-kubernetes",
			"aks/azure-policy",
		},
		DeploymentPatterns: []string{"azure-policy"},
		ExpectedNamespaces: []string{"kube-system", "gatekeeper-system"},
		WebhookPatterns:    []string{"azure-policy"},
		RequireImageVerification: false, // Azure managed
	})

	// Kyverno (also used for pod admission)
	r.register(&Engine{
		ID:       "kyverno",
		Name:     "Kyverno",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/kyverno/",
			"docker.io/kyverno/",
		},
		ImagePatterns: []string{
			"kyverno/kyverno",
			"kyverno/kyvernopre",
		},
		DeploymentPatterns: []string{"kyverno", "kyverno-admission-controller"},
		ExpectedNamespaces: []string{"kyverno", "kube-system"},
		WebhookPatterns:    []string{"kyverno"},
		CRDGroups:          []string{"kyverno.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=kyverno"},
		RequireImageVerification: true,
	})

	// OPA Gatekeeper
	r.register(&Engine{
		ID:       "gatekeeper",
		Name:     "OPA Gatekeeper",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"openpolicyagent/",
			"docker.io/openpolicyagent/",
		},
		ImagePatterns: []string{
			"openpolicyagent/gatekeeper",
			"gatekeeper",
		},
		DeploymentPatterns: []string{"gatekeeper-controller-manager", "gatekeeper-audit"},
		ExpectedNamespaces: []string{"gatekeeper-system", "opa-system", "kube-system"},
		WebhookPatterns:    []string{"gatekeeper"},
		CRDGroups:          []string{"templates.gatekeeper.sh", "constraints.gatekeeper.sh"},
		LabelSelectors:     []string{"gatekeeper.sh/system=yes", "control-plane=controller-manager"},
		RequireImageVerification: true,
	})

	// NEW: Cosign standalone (not part of Sigstore policy controller)
	r.register(&Engine{
		ID:       "cosign",
		Name:     "Cosign",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/sigstore/",
			"gcr.io/",
		},
		ImagePatterns: []string{
			"sigstore/cosign",
			"cosign",
		},
		DeploymentPatterns: []string{"cosign"},
		ExpectedNamespaces: []string{"cosign-system", "sigstore-system"},
		RequireImageVerification: true,
	})

	// NEW: Flux Image Automation
	r.register(&Engine{
		ID:       "flux-image",
		Name:     "Flux Image Automation",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"ghcr.io/fluxcd/",
		},
		ImagePatterns: []string{
			"fluxcd/image-automation-controller",
			"fluxcd/image-reflector-controller",
		},
		DeploymentPatterns: []string{"image-automation-controller", "image-reflector-controller"},
		ExpectedNamespaces: []string{"flux-system"},
		CRDGroups:          []string{"image.toolkit.fluxcd.io"},
		RequireImageVerification: true,
	})

	// NEW: JFrog Xray
	r.register(&Engine{
		ID:       "jfrog-xray",
		Name:     "JFrog Xray",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"releases-docker.jfrog.io/",
		},
		ImagePatterns: []string{
			"jfrog/xray",
			"xray",
		},
		DeploymentPatterns: []string{"xray"},
		ExpectedNamespaces: []string{"jfrog", "artifactory"},
		RequireImageVerification: true,
	})

	// NEW: Wiz
	r.register(&Engine{
		ID:       "wiz",
		Name:     "Wiz",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"wizio.azurecr.io/",
		},
		ImagePatterns: []string{
			"wiz-sensor",
			"wiz-admission-controller",
		},
		DeploymentPatterns: []string{"wiz-sensor", "wiz-admission-controller"},
		ExpectedNamespaces: []string{"wiz"},
		WebhookPatterns:    []string{"wiz"},
		RequireImageVerification: true,
	})

	// NEW: Lacework
	r.register(&Engine{
		ID:       "lacework",
		Name:     "Lacework",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"lacework/",
		},
		ImagePatterns: []string{
			"lacework/datacollector",
			"lacework/k8s-admission-controller",
		},
		DeploymentPatterns: []string{"lacework-agent", "lacework-admission-controller"},
		ExpectedNamespaces: []string{"lacework"},
		WebhookPatterns:    []string{"lacework"},
		RequireImageVerification: true,
	})

	// NEW: Deepfence ThreatMapper
	r.register(&Engine{
		ID:       "deepfence",
		Name:     "Deepfence ThreatMapper",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"deepfenceio/",
			"quay.io/deepfenceio/",
		},
		ImagePatterns: []string{
			"deepfenceio/deepfence_agent",
			"deepfenceio/deepfence_console",
			"deepfenceio/deepfence_router",
			"deepfence-agent",
		},
		DeploymentPatterns: []string{"deepfence-agent", "deepfence-console", "deepfence-router"},
		ExpectedNamespaces: []string{"deepfence", "deepfence-console"},
		WebhookPatterns:    []string{"deepfence"},
		RequireImageVerification: true,
	})

	// NEW: Qualys Container Security
	r.register(&Engine{
		ID:       "qualys",
		Name:     "Qualys Container Security",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"qualys/",
		},
		ImagePatterns: []string{
			"qualys/qcs-sensor",
			"qualys/container-sensor",
			"qualys-sensor",
		},
		DeploymentPatterns: []string{"qualys-container-sensor", "qcs-sensor"},
		ExpectedNamespaces: []string{"qualys"},
		WebhookPatterns:    []string{"qualys"},
		RequireImageVerification: true,
	})

	// NEW: Docker Scout
	r.register(&Engine{
		ID:       "docker-scout",
		Name:     "Docker Scout",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"docker/",
			"docker.io/docker/",
		},
		ImagePatterns: []string{
			"docker/scout-cli",
			"docker/scout-sbom-indexer",
		},
		DeploymentPatterns: []string{"docker-scout"},
		ExpectedNamespaces: []string{"docker-scout", "docker"},
		WebhookPatterns:    []string{"docker-scout", "scout"},
		RequireImageVerification: true,
	})

	// NEW: Tenable Container Security
	r.register(&Engine{
		ID:       "tenable",
		Name:     "Tenable Container Security",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"registry.tenable.com/",
		},
		ImagePatterns: []string{
			"tenable/nessus-agent",
			"tenable/cs-scanner",
		},
		DeploymentPatterns: []string{"tenable-agent", "nessus-agent"},
		ExpectedNamespaces: []string{"tenable"},
		WebhookPatterns:    []string{"tenable"},
		RequireImageVerification: true,
	})

	// NEW: GitLab Container Scanning
	r.register(&Engine{
		ID:       "gitlab-container-scanning",
		Name:     "GitLab Container Scanning",
		Category: CategoryImage,
		TrustedRegistries: []string{
			"registry.gitlab.com/",
		},
		ImagePatterns: []string{
			"gitlab/container-scanning",
			"gitlab-org/security-products/analyzers/container-scanning",
		},
		DeploymentPatterns: []string{"gitlab-container-scanning"},
		ExpectedNamespaces: []string{"gitlab", "gitlab-runner"},
		WebhookPatterns:    []string{"gitlab"},
		RequireImageVerification: true,
	})
}
