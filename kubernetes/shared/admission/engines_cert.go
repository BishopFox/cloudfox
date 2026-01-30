package admission

// registerCertEngines registers all certificate management engines
func (r *EngineRegistry) registerCertEngines() {
	// cert-manager
	r.register(&Engine{
		ID:       "cert-manager",
		Name:     "cert-manager",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"quay.io/jetstack/",
			"docker.io/jetstack/",
			"gcr.io/jetstack-cert-manager-containers/",
		},
		ImagePatterns: []string{
			"jetstack/cert-manager",
			"cert-manager-controller",
			"cert-manager-webhook",
			"cert-manager-cainjector",
		},
		DeploymentPatterns: []string{"cert-manager", "cert-manager-webhook", "cert-manager-cainjector"},
		ExpectedNamespaces: []string{"cert-manager", "kube-system"},
		WebhookPatterns:    []string{"cert-manager-webhook"},
		CRDGroups:          []string{"cert-manager.io", "acme.cert-manager.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=cert-manager", "app=cert-manager"},
		RequireImageVerification: true,
	})

	// Venafi
	r.register(&Engine{
		ID:       "venafi",
		Name:     "Venafi",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"venafi/",
			"docker.io/venafi/",
		},
		ImagePatterns: []string{
			"venafi/cert-manager-venafi",
			"venafi/vcp",
			"venafi-enhanced-issuer",
			"venafi-kubernetes-agent",
		},
		DeploymentPatterns: []string{"venafi-enhanced-issuer", "venafi-kubernetes-agent"},
		ExpectedNamespaces: []string{"venafi", "cert-manager"},
		CRDGroups:          []string{"jetstack.io"},
		LabelSelectors:     []string{"app=venafi-enhanced-issuer"},
		RequireImageVerification: true,
	})

	// SPIFFE/SPIRE
	r.register(&Engine{
		ID:       "spiffe",
		Name:     "SPIFFE/SPIRE",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"ghcr.io/spiffe/",
			"gcr.io/spiffe-io/",
		},
		ImagePatterns: []string{
			"spiffe/spire",
			"spire-server",
			"spire-agent",
		},
		DeploymentPatterns: []string{"spire-server"},
		ExpectedNamespaces: []string{"spire", "spiffe"},
		CRDGroups:          []string{"spire.spiffe.io"},
		LabelSelectors:     []string{"app=spire-server", "app=spire-agent"},
		RequireImageVerification: true,
	})

	// AWS ACM Controller
	r.register(&Engine{
		ID:       "aws-acm",
		Name:     "AWS ACM Controller",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"amazon/",
			"public.ecr.aws/",
		},
		ImagePatterns: []string{
			"aws-controllers-k8s/acm-controller",
			"acm-controller",
		},
		DeploymentPatterns: []string{"acm-controller"},
		ExpectedNamespaces: []string{"ack-system", "kube-system"},
		CRDGroups:          []string{"acm.services.k8s.aws"},
		LabelSelectors:     []string{"app.kubernetes.io/name=acm-controller"},
		RequireImageVerification: true,
	})

	// AWS Private CA Issuer
	r.register(&Engine{
		ID:       "aws-pca",
		Name:     "AWS Private CA Issuer",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"amazon/",
			"public.ecr.aws/",
		},
		ImagePatterns: []string{
			"aws-privateca-issuer",
			"cert-manager-aws-privateca-issuer",
		},
		DeploymentPatterns: []string{"aws-privateca-issuer"},
		ExpectedNamespaces: []string{"cert-manager", "aws-pca-issuer-system"},
		CRDGroups:          []string{"awspca.cert-manager.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=aws-privateca-issuer"},
		RequireImageVerification: true,
	})

	// Google CAS Issuer
	r.register(&Engine{
		ID:       "google-cas",
		Name:     "Google CAS Issuer",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"gcr.io/",
			"us-docker.pkg.dev/",
		},
		ImagePatterns: []string{
			"google-cas-issuer",
			"cert-manager-google-cas-issuer",
		},
		DeploymentPatterns: []string{"google-cas-issuer"},
		ExpectedNamespaces: []string{"cert-manager", "google-cas-issuer-system"},
		CRDGroups:          []string{"cas-issuer.jetstack.io"},
		RequireImageVerification: true,
	})

	// step-certificates
	r.register(&Engine{
		ID:       "step-certificates",
		Name:     "step-certificates",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"smallstep/",
			"docker.io/smallstep/",
		},
		ImagePatterns: []string{
			"smallstep/step-ca",
			"step-ca",
			"step-certificates",
		},
		DeploymentPatterns: []string{"step-certificates"},
		ExpectedNamespaces: []string{"step", "smallstep"},
		CRDGroups:          []string{"certmanager.step.sm"},
		LabelSelectors:     []string{"app.kubernetes.io/name=step-certificates"},
		RequireImageVerification: true,
	})

	// trust-manager
	r.register(&Engine{
		ID:       "trust-manager",
		Name:     "trust-manager",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"quay.io/jetstack/",
		},
		ImagePatterns: []string{
			"jetstack/trust-manager",
			"trust-manager",
		},
		DeploymentPatterns: []string{"trust-manager"},
		ExpectedNamespaces: []string{"cert-manager"},
		CRDGroups:          []string{"trust.cert-manager.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=trust-manager"},
		RequireImageVerification: true,
	})

	// approver-policy
	r.register(&Engine{
		ID:       "approver-policy",
		Name:     "approver-policy",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"quay.io/jetstack/",
		},
		ImagePatterns: []string{
			"jetstack/cert-manager-approver-policy",
			"approver-policy",
		},
		DeploymentPatterns: []string{"cert-manager-approver-policy"},
		ExpectedNamespaces: []string{"cert-manager"},
		CRDGroups:          []string{"policy.cert-manager.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=approver-policy"},
		RequireImageVerification: true,
	})

	// csi-driver (cert-manager)
	r.register(&Engine{
		ID:       "cert-manager-csi",
		Name:     "cert-manager CSI Driver",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"quay.io/jetstack/",
		},
		ImagePatterns: []string{
			"jetstack/cert-manager-csi-driver",
			"cert-manager-csi-driver",
		},
		DeploymentPatterns: []string{"cert-manager-csi-driver"},
		ExpectedNamespaces: []string{"cert-manager"},
		LabelSelectors:     []string{"app.kubernetes.io/name=cert-manager-csi-driver"},
		RequireImageVerification: true,
	})

	// Azure Key Vault Certificate Issuer (via cert-manager)
	r.register(&Engine{
		ID:       "azure-keyvault-issuer",
		Name:     "Azure Key Vault Issuer",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azure-keyvault-controller",
			"keyvault-cert-controller",
			"akv2k8s",
		},
		DeploymentPatterns: []string{"akv2k8s-controller", "azure-keyvault-controller"},
		ExpectedNamespaces: []string{"akv2k8s", "azure-keyvault"},
		CRDGroups:          []string{"spv.no", "keyvault.azure.com"},
		LabelSelectors:     []string{"app=akv2k8s"},
		RequireImageVerification: true,
	})

	// DigiCert Certificate Issuer
	r.register(&Engine{
		ID:       "digicert-issuer",
		Name:     "DigiCert Issuer",
		Category: CategoryCert,
		TrustedRegistries: []string{
			"digicert/",
		},
		ImagePatterns: []string{
			"digicert/cert-manager-issuer",
			"digicert-issuer",
		},
		DeploymentPatterns: []string{"digicert-issuer"},
		ExpectedNamespaces: []string{"cert-manager", "digicert"},
		CRDGroups:          []string{"certmanager.digicert.com"},
		RequireImageVerification: true,
	})

	// Origin CA Issuer (Cloudflare)
	r.register(&Engine{
		ID:       "origin-ca-issuer",
		Name:     "Cloudflare Origin CA Issuer",
		Category: CategoryCert,
		ImagePatterns: []string{
			"origin-ca-issuer",
			"cloudflare-origin-ca-issuer",
		},
		DeploymentPatterns: []string{"origin-ca-issuer"},
		ExpectedNamespaces: []string{"cert-manager", "origin-ca-issuer"},
		CRDGroups:          []string{"cert-manager.io"},
		RequireImageVerification: true,
	})
}
