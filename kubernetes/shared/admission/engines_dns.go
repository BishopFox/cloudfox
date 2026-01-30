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

	// =============================================================================
	// Network Controllers with DNS Policy Capabilities
	// =============================================================================

	// Calico - GlobalNetworkPolicy supports FQDN-based egress rules
	r.register(&Engine{
		ID:       "calico",
		Name:     "Calico",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"calico/",
			"docker.io/calico/",
			"quay.io/calico/",
		},
		ImagePatterns: []string{
			"calico/kube-controllers",
			"calico/cni",
			"calico/node",
			"calico/typha",
		},
		DeploymentPatterns: []string{"calico-kube-controllers", "calico-typha"},
		ExpectedNamespaces: []string{"kube-system", "calico-system"},
		CRDGroups:          []string{"crd.projectcalico.org", "projectcalico.org"},
		LabelSelectors:     []string{"k8s-app=calico-node", "k8s-app=calico-kube-controllers"},
		RequireImageVerification: true,
	})

	// Cilium - CiliumNetworkPolicy has toFQDNs for DNS-aware policies
	r.register(&Engine{
		ID:       "cilium",
		Name:     "Cilium",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"cilium/",
			"quay.io/cilium/",
			"docker.io/cilium/",
		},
		ImagePatterns: []string{
			"cilium/cilium",
			"cilium/operator",
		},
		DeploymentPatterns: []string{"cilium-operator"},
		ExpectedNamespaces: []string{"kube-system", "cilium"},
		CRDGroups:          []string{"cilium.io"},
		LabelSelectors:     []string{"k8s-app=cilium", "app.kubernetes.io/name=cilium"},
		RequireImageVerification: true,
	})

	// Antrea - ClusterNetworkPolicy with FQDN support
	r.register(&Engine{
		ID:       "antrea",
		Name:     "Antrea",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"antrea/",
			"projects.registry.vmware.com/antrea/",
		},
		ImagePatterns: []string{
			"antrea/antrea-agent",
			"antrea/antrea-controller",
		},
		DeploymentPatterns: []string{"antrea-controller"},
		ExpectedNamespaces: []string{"kube-system", "antrea-system"},
		CRDGroups:          []string{"crd.antrea.io"},
		LabelSelectors:     []string{"app=antrea", "component=antrea-controller"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Service Mesh with DNS Capabilities
	// =============================================================================

	// Istio - ServiceEntry for DNS routing and external service resolution
	r.register(&Engine{
		ID:       "istio",
		Name:     "Istio",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"docker.io/istio/",
			"istio/",
			"gcr.io/istio-release/",
		},
		ImagePatterns: []string{
			"istio/proxyv2",
			"istio/pilot",
			"istio/istiod",
		},
		DeploymentPatterns: []string{"istiod"},
		ExpectedNamespaces: []string{"istio-system"},
		CRDGroups:          []string{"networking.istio.io"},
		LabelSelectors:     []string{"app=istiod", "istio=pilot"},
		RequireImageVerification: true,
	})

	// Consul - DNS forwarding and service mesh DNS
	r.register(&Engine{
		ID:       "consul",
		Name:     "Consul",
		Category: CategoryDNS,
		TrustedRegistries: []string{
			"hashicorp/",
			"docker.io/hashicorp/",
		},
		ImagePatterns: []string{
			"hashicorp/consul",
			"consul",
			"consul-k8s",
		},
		DeploymentPatterns: []string{"consul-server", "consul-connect-injector"},
		ExpectedNamespaces: []string{"consul", "hashicorp"},
		CRDGroups:          []string{"consul.hashicorp.com"},
		LabelSelectors:     []string{"app=consul", "component=server"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Policy Engines with DNS Policy Capabilities
	// =============================================================================

	// OPA Gatekeeper - Can enforce DNS policy constraints
	r.register(&Engine{
		ID:       "gatekeeper",
		Name:     "OPA Gatekeeper",
		Category: CategoryDNS,
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

	// Kyverno - Can validate/mutate DNS-related resources
	r.register(&Engine{
		ID:       "kyverno",
		Name:     "Kyverno",
		Category: CategoryDNS,
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

	// Kubewarden - Can enforce DNS-related policies
	r.register(&Engine{
		ID:       "kubewarden",
		Name:     "Kubewarden",
		Category: CategoryDNS,
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
}
