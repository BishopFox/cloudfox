package admission

// registerSecretEngines registers all secret management engines
func (r *EngineRegistry) registerSecretEngines() {
	// HashiCorp Vault Agent Injector
	r.register(&Engine{
		ID:       "vault-injector",
		Name:     "Vault Agent Injector",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"hashicorp/",
			"docker.io/hashicorp/",
		},
		ImagePatterns: []string{
			"hashicorp/vault-k8s",
			"vault-k8s",
			"vault-agent-injector",
		},
		DeploymentPatterns: []string{"vault-agent-injector"},
		ExpectedNamespaces: []string{"vault", "hashicorp", "kube-system"},
		WebhookPatterns:    []string{"vault-agent-injector"},
		LabelSelectors:     []string{"app.kubernetes.io/name=vault-agent-injector", "component=webhook"},
		RequireImageVerification: true,
	})

	// HashiCorp Vault CSI Provider
	r.register(&Engine{
		ID:       "vault-csi",
		Name:     "Vault CSI Provider",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"hashicorp/",
			"docker.io/hashicorp/",
		},
		ImagePatterns: []string{
			"hashicorp/vault-csi-provider",
			"vault-csi-provider",
		},
		DeploymentPatterns: []string{"vault-csi-provider"},
		ExpectedNamespaces: []string{"vault", "hashicorp", "kube-system"},
		LabelSelectors:     []string{"app.kubernetes.io/name=vault-csi-provider"},
		RequireImageVerification: true,
	})

	// HashiCorp Vault Operator (Bank-Vaults)
	r.register(&Engine{
		ID:       "vault-operator",
		Name:     "Vault Operator",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"hashicorp/",
			"ghcr.io/bank-vaults/",
			"banzaicloud/",
		},
		ImagePatterns: []string{
			"hashicorp/vault",
			"bank-vaults/vault-operator",
			"banzaicloud/vault-operator",
			"vault-operator",
		},
		DeploymentPatterns: []string{"vault-operator", "vault"},
		ExpectedNamespaces: []string{"vault", "vault-system", "hashicorp", "kube-system"},
		CRDGroups:          []string{"vault.banzaicloud.com"},
		LabelSelectors:     []string{"app.kubernetes.io/name=vault-operator", "app=vault"},
		RequireImageVerification: true,
	})

	// External Secrets Operator
	r.register(&Engine{
		ID:       "external-secrets",
		Name:     "External Secrets Operator",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"ghcr.io/external-secrets/",
			"docker.io/external-secrets/",
		},
		ImagePatterns: []string{
			"external-secrets/external-secrets",
			"external-secrets",
		},
		DeploymentPatterns: []string{"external-secrets", "external-secrets-webhook", "external-secrets-cert-controller"},
		ExpectedNamespaces: []string{"external-secrets", "kube-system"},
		WebhookPatterns:    []string{"external-secrets-webhook"},
		CRDGroups:          []string{"external-secrets.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=external-secrets", "app=external-secrets"},
		RequireImageVerification: true,
	})

	// Sealed Secrets
	r.register(&Engine{
		ID:       "sealed-secrets",
		Name:     "Sealed Secrets",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"bitnami/",
			"docker.io/bitnami/",
			"quay.io/bitnami/",
		},
		ImagePatterns: []string{
			"bitnami/sealed-secrets-controller",
			"sealed-secrets-controller",
		},
		DeploymentPatterns: []string{"sealed-secrets-controller", "sealed-secrets"},
		ExpectedNamespaces: []string{"kube-system", "sealed-secrets"},
		CRDGroups:          []string{"bitnami.com"},
		LabelSelectors:     []string{"app.kubernetes.io/name=sealed-secrets", "name=sealed-secrets-controller"},
		RequireImageVerification: true,
	})

	// AWS Secrets Manager CSI Driver
	r.register(&Engine{
		ID:       "aws-secrets-csi",
		Name:     "AWS Secrets CSI Driver",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"public.ecr.aws/",
			"amazon/",
		},
		ImagePatterns: []string{
			"secrets-store-csi-driver-provider-aws",
			"aws-secrets-manager",
		},
		DeploymentPatterns: []string{"secrets-store-csi-driver-provider-aws"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"app=secrets-store-csi-driver-provider-aws"},
		RequireImageVerification: true,
	})

	// Azure Key Vault CSI Driver
	r.register(&Engine{
		ID:       "azure-keyvault-csi",
		Name:     "Azure Key Vault CSI Driver",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"aks/keyvault/",
			"azure-keyvault-secrets-provider",
			"csi-secrets-store-provider-azure",
		},
		DeploymentPatterns: []string{"csi-secrets-store-provider-azure"},
		ExpectedNamespaces: []string{"kube-system", "azure-keyvault-secrets-provider"},
		LabelSelectors:     []string{"app=csi-secrets-store-provider-azure"},
		RequireImageVerification: true,
	})

	// GCP Secret Manager CSI Driver
	r.register(&Engine{
		ID:       "gcp-secrets-csi",
		Name:     "GCP Secret Manager CSI Driver",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"gcr.io/",
			"us-docker.pkg.dev/",
		},
		ImagePatterns: []string{
			"secrets-store-csi-driver-provider-gcp",
			"gcp-secrets-store-csi-driver-provider",
		},
		DeploymentPatterns: []string{"secrets-store-csi-driver-provider-gcp"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"app=secrets-store-csi-driver-provider-gcp"},
		RequireImageVerification: true,
	})

	// Secrets Store CSI Driver (base)
	r.register(&Engine{
		ID:       "secrets-store-csi",
		Name:     "Secrets Store CSI Driver",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"registry.k8s.io/",
			"k8s.gcr.io/",
		},
		ImagePatterns: []string{
			"csi-secrets-store/driver",
			"secrets-store-csi-driver",
		},
		DeploymentPatterns: []string{"secrets-store-csi-driver"},
		ExpectedNamespaces: []string{"kube-system"},
		CRDGroups:          []string{"secrets-store.csi.x-k8s.io"},
		LabelSelectors:     []string{"app=secrets-store-csi-driver"},
		RequireImageVerification: true,
	})

	// Akeyless Secrets Injection
	r.register(&Engine{
		ID:       "akeyless",
		Name:     "Akeyless",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"akeyless/",
			"docker.io/akeyless/",
		},
		ImagePatterns: []string{
			"akeyless/k8s-secrets-injection",
			"akeyless-secrets-injection",
		},
		DeploymentPatterns: []string{"akeyless-secrets-injection"},
		ExpectedNamespaces: []string{"akeyless", "kube-system"},
		WebhookPatterns:    []string{"akeyless"},
		LabelSelectors:     []string{"app=akeyless-secrets-injection"},
		RequireImageVerification: true,
	})

	// CyberArk Conjur
	r.register(&Engine{
		ID:       "conjur",
		Name:     "CyberArk Conjur",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"cyberark/",
			"docker.io/cyberark/",
		},
		ImagePatterns: []string{
			"cyberark/secrets-provider-for-k8s",
			"conjur-authn-k8s-client",
			"secrets-provider-for-k8s",
		},
		DeploymentPatterns: []string{"conjur-follower"},
		ExpectedNamespaces: []string{"conjur", "cyberark", "kube-system"},
		LabelSelectors:     []string{"app=conjur-follower"},
		RequireImageVerification: true,
	})

	// SOPS
	r.register(&Engine{
		ID:       "sops",
		Name:     "SOPS",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"mozilla/",
			"ghcr.io/getsops/",
		},
		ImagePatterns: []string{
			"sops",
			"getsops/sops",
		},
		DeploymentPatterns: []string{"sops-secrets-operator"},
		ExpectedNamespaces: []string{"kube-system"},
		CRDGroups:          []string{"isindir.github.com"},
		RequireImageVerification: true,
	})

	// Infisical
	r.register(&Engine{
		ID:       "infisical",
		Name:     "Infisical",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"infisical/",
			"docker.io/infisical/",
		},
		ImagePatterns: []string{
			"infisical/kubernetes-operator",
			"infisical-secrets-operator",
		},
		DeploymentPatterns: []string{"infisical-secrets-operator"},
		ExpectedNamespaces: []string{"infisical", "kube-system"},
		CRDGroups:          []string{"secrets.infisical.com"},
		LabelSelectors:     []string{"app.kubernetes.io/name=infisical-secrets-operator"},
		RequireImageVerification: true,
	})

	// Doppler
	r.register(&Engine{
		ID:       "doppler",
		Name:     "Doppler",
		Category: CategorySecret,
		TrustedRegistries: []string{
			"dopplerhq/",
			"docker.io/dopplerhq/",
		},
		ImagePatterns: []string{
			"dopplerhq/kubernetes-operator",
			"doppler-kubernetes-operator",
		},
		DeploymentPatterns: []string{"doppler-operator"},
		ExpectedNamespaces: []string{"doppler-operator-system", "kube-system"},
		CRDGroups:          []string{"secrets.doppler.com"},
		LabelSelectors:     []string{"control-plane=doppler-operator"},
		RequireImageVerification: true,
	})
}
