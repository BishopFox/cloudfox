package admission

// registerDNSEngines registers all DNS-related engines
func (r *EngineRegistry) registerDNSEngines() {
	// CoreDNS
	r.register(&Engine{
		ID:       "coredns",
		Name:     "CoreDNS",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"coredns/",
			"docker.io/coredns/",
			"registry.k8s.io/",
			"k8s.gcr.io/",
		},
		ImagePatterns: []string{
			"coredns/coredns",
			"coredns",
		},
		DeploymentPatterns: []string{"coredns"},
		ExpectedNamespaces: []string{"kube-system", "coredns"},
		LabelSelectors:     []string{"k8s-app=kube-dns", "kubernetes.io/name=CoreDNS"},
		RequireImageVerification: true,
	})

	// NodeLocalDNS
	r.register(&Engine{
		ID:       "nodelocaldns",
		Name:     "NodeLocalDNS",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"registry.k8s.io/",
			"k8s.gcr.io/",
		},
		ImagePatterns: []string{
			"k8s-dns-node-cache",
			"dns-node-cache",
			"node-local-dns",
			"nodelocaldns",
		},
		DeploymentPatterns: []string{"node-local-dns", "nodelocaldns"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"k8s-app=node-local-dns"},
		RequireImageVerification: true,
	})

	// external-dns
	r.register(&Engine{
		ID:       "external-dns",
		Name:     "external-dns",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"registry.k8s.io/",
			"k8s.gcr.io/",
			"bitnami/",
		},
		ImagePatterns: []string{
			"external-dns",
			"externaldns",
			"k8s-sigs/external-dns",
			"bitnami/external-dns",
		},
		DeploymentPatterns: []string{"external-dns"},
		ExpectedNamespaces: []string{"external-dns", "kube-system", "default"},
		LabelSelectors:     []string{"app.kubernetes.io/name=external-dns", "app=external-dns"},
		RequireImageVerification: true,
	})

	// PowerDNS
	r.register(&Engine{
		ID:       "powerdns",
		Name:     "PowerDNS",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"powerdns/",
			"docker.io/powerdns/",
		},
		ImagePatterns: []string{
			"powerdns/pdns",
			"powerdns-admin",
			"pdns",
		},
		DeploymentPatterns: []string{"powerdns"},
		ExpectedNamespaces: []string{"powerdns", "kube-system"},
		LabelSelectors:     []string{"app=powerdns"},
		RequireImageVerification: true,
	})

	// Unbound DNS
	r.register(&Engine{
		ID:       "unbound",
		Name:     "Unbound DNS",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"klutchell/",
			"mvance/",
		},
		ImagePatterns: []string{
			"unbound",
		},
		DeploymentPatterns: []string{"unbound"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"app=unbound"},
		RequireImageVerification: true,
	})

	// AWS Route53 Resolver
	r.register(&Engine{
		ID:       "route53-resolver",
		Name:     "Route53 Resolver",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"amazon/",
			"602401143452.dkr.ecr.",
		},
		ImagePatterns: []string{
			"route53-resolver",
			"amazon/cloud-map-controller",
		},
		DeploymentPatterns: []string{"route53-resolver"},
		ExpectedNamespaces: []string{"kube-system", "aws-controllers"},
		RequireImageVerification: true,
	})

	// GCP Cloud DNS
	r.register(&Engine{
		ID:       "gcp-cloud-dns",
		Name:     "GCP Cloud DNS",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"gcr.io/",
			"gke.gcr.io/",
		},
		ImagePatterns: []string{
			"cloud-dns",
			"k8s-dns",
		},
		DeploymentPatterns: []string{},
		ExpectedNamespaces: []string{"kube-system", "gke-system"},
		RequireImageVerification: true,
	})

	// Azure DNS
	r.register(&Engine{
		ID:       "azure-dns",
		Name:     "Azure DNS",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azure-dns",
			"azure/external-dns",
		},
		DeploymentPatterns: []string{},
		ExpectedNamespaces: []string{"kube-system", "azure-dns"},
		RequireImageVerification: true,
	})

	// Pi-hole
	r.register(&Engine{
		ID:       "pihole",
		Name:     "Pi-hole",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"pihole/",
			"docker.io/pihole/",
		},
		ImagePatterns: []string{
			"pihole/pihole",
			"pihole",
		},
		DeploymentPatterns: []string{"pihole"},
		ExpectedNamespaces: []string{"pihole", "kube-system"},
		LabelSelectors:     []string{"app=pihole"},
		RequireImageVerification: true,
	})

	// AdGuard Home
	r.register(&Engine{
		ID:       "adguard",
		Name:     "AdGuard Home",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"adguard/",
			"docker.io/adguard/",
		},
		ImagePatterns: []string{
			"adguard/adguardhome",
			"adguardhome",
		},
		DeploymentPatterns: []string{"adguard-home"},
		ExpectedNamespaces: []string{"adguard", "kube-system"},
		LabelSelectors:     []string{"app=adguard-home"},
		RequireImageVerification: true,
	})
}
