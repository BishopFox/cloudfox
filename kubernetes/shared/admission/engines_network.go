package admission

// registerNetworkEngines registers all network policy/CNI engines
func (r *EngineRegistry) registerNetworkEngines() {
	// Calico
	r.register(&Engine{
		ID:       "calico",
		Name:     "Calico",
		Category: CategoryNetwork,
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
			"calico/apiserver",
		},
		DeploymentPatterns: []string{"calico-kube-controllers", "calico-typha", "calico-apiserver"},
		ExpectedNamespaces: []string{"kube-system", "calico-system", "calico-apiserver"},
		CRDGroups:          []string{"crd.projectcalico.org", "projectcalico.org"},
		LabelSelectors:     []string{"k8s-app=calico-node", "k8s-app=calico-kube-controllers"},
		RequireImageVerification: true,
	})

	// Cilium
	r.register(&Engine{
		ID:       "cilium",
		Name:     "Cilium",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"cilium/",
			"quay.io/cilium/",
			"docker.io/cilium/",
		},
		ImagePatterns: []string{
			"cilium/cilium",
			"cilium/operator",
			"cilium/hubble",
		},
		DeploymentPatterns: []string{"cilium-operator", "hubble-relay", "hubble-ui"},
		ExpectedNamespaces: []string{"kube-system", "cilium"},
		CRDGroups:          []string{"cilium.io"},
		LabelSelectors:     []string{"k8s-app=cilium", "app.kubernetes.io/name=cilium"},
		RequireImageVerification: true,
	})

	// Weave Net
	r.register(&Engine{
		ID:       "weave",
		Name:     "Weave Net",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"weaveworks/",
			"docker.io/weaveworks/",
			"ghcr.io/weaveworks/",
		},
		ImagePatterns: []string{
			"weaveworks/weave-kube",
			"weaveworks/weave-npc",
			"weave-kube",
			"weave-npc",
		},
		DeploymentPatterns: []string{"weave-net"},
		ExpectedNamespaces: []string{"kube-system", "weave"},
		LabelSelectors:     []string{"name=weave-net", "weave-net"},
		RequireImageVerification: true,
	})

	// Flannel
	r.register(&Engine{
		ID:       "flannel",
		Name:     "Flannel",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"flannel/",
			"docker.io/flannel/",
			"quay.io/coreos/",
		},
		ImagePatterns: []string{
			"flannel/flannel",
			"coreos/flannel",
			"flannel-cni",
		},
		DeploymentPatterns: []string{"kube-flannel"},
		ExpectedNamespaces: []string{"kube-system", "kube-flannel"},
		LabelSelectors:     []string{"app=flannel", "k8s-app=flannel"},
		RequireImageVerification: true,
	})

	// Antrea
	r.register(&Engine{
		ID:       "antrea",
		Name:     "Antrea",
		Category: CategoryNetwork,
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
		CRDGroups:          []string{"crd.antrea.io", "controlplane.antrea.io"},
		LabelSelectors:     []string{"app=antrea", "component=antrea-controller"},
		RequireImageVerification: true,
	})

	// Kube-router
	r.register(&Engine{
		ID:       "kuberouter",
		Name:     "Kube-router",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"cloudnativelabs/",
			"docker.io/cloudnativelabs/",
		},
		ImagePatterns: []string{
			"kube-router",
			"cloudnativelabs/kube-router",
		},
		DeploymentPatterns: []string{"kube-router"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"k8s-app=kube-router"},
		RequireImageVerification: true,
	})

	// Canal (Calico + Flannel)
	r.register(&Engine{
		ID:       "canal",
		Name:     "Canal",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"calico/",
			"docker.io/calico/",
			"quay.io/calico/",
		},
		ImagePatterns: []string{
			"calico/cni",
			"flannel",
		},
		DeploymentPatterns: []string{"canal"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"k8s-app=canal"},
		RequireImageVerification: true,
	})

	// OVN-Kubernetes
	r.register(&Engine{
		ID:       "ovn",
		Name:     "OVN-Kubernetes",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"ghcr.io/ovn-org/",
			"quay.io/ovn-org/",
		},
		ImagePatterns: []string{
			"ovn-kubernetes",
			"ovnkube-node",
			"ovn-controller",
		},
		DeploymentPatterns: []string{"ovnkube-master", "ovnkube-db"},
		ExpectedNamespaces: []string{"ovn-kubernetes", "openshift-ovn-kubernetes"},
		LabelSelectors:     []string{"app=ovnkube-master", "app=ovnkube-node"},
		RequireImageVerification: true,
	})

	// AWS VPC CNI
	r.register(&Engine{
		ID:       "aws-vpc-cni",
		Name:     "AWS VPC CNI",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"602401143452.dkr.ecr.",
			"amazon/",
		},
		ImagePatterns: []string{
			"amazon-k8s-cni",
			"aws-vpc-cni",
		},
		DeploymentPatterns: []string{"aws-node"},
		ExpectedNamespaces: []string{"kube-system"},
		LabelSelectors:     []string{"k8s-app=aws-node"},
		RequireImageVerification: true,
	})

	// Azure CNI
	r.register(&Engine{
		ID:       "azure-cni",
		Name:     "Azure CNI",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
			"containernetworking/",
		},
		ImagePatterns: []string{
			"azure-cni",
			"azure-vnet",
		},
		DeploymentPatterns: []string{"azure-cni-networkmonitor"},
		ExpectedNamespaces: []string{"kube-system"},
		RequireImageVerification: true,
	})

	// GKE Network Policy
	r.register(&Engine{
		ID:       "gke-netpol",
		Name:     "GKE Network Policy",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"gke.gcr.io/",
			"gcr.io/gke-release/",
		},
		ImagePatterns: []string{
			"netd",
			"network-policy-controller",
		},
		DeploymentPatterns: []string{"calico-node", "calico-typha"},
		ExpectedNamespaces: []string{"kube-system"},
		RequireImageVerification: true,
	})

	// Multus CNI
	r.register(&Engine{
		ID:       "multus",
		Name:     "Multus CNI",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"ghcr.io/k8snetworkplumbingwg/",
			"nfvpe/",
		},
		ImagePatterns: []string{
			"multus-cni",
			"multus",
		},
		DeploymentPatterns: []string{"kube-multus"},
		ExpectedNamespaces: []string{"kube-system"},
		CRDGroups:          []string{"k8s.cni.cncf.io"},
		LabelSelectors:     []string{"app=multus", "name=multus"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Policy Engines with Network Policy Capabilities
	// =============================================================================

	// OPA Gatekeeper - Can enforce constraints on NetworkPolicy resources
	r.register(&Engine{
		ID:       "gatekeeper",
		Name:     "OPA Gatekeeper",
		Category: CategoryNetwork,
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

	// Kyverno - Can validate/mutate NetworkPolicy resources
	r.register(&Engine{
		ID:       "kyverno",
		Name:     "Kyverno",
		Category: CategoryNetwork,
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

	// Kubewarden - Can enforce policies on NetworkPolicy resources
	r.register(&Engine{
		ID:       "kubewarden",
		Name:     "Kubewarden",
		Category: CategoryNetwork,
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
	// Service Mesh with Network Policy Capabilities
	// =============================================================================

	// Istio - AuthorizationPolicy provides L7 network access control
	r.register(&Engine{
		ID:       "istio",
		Name:     "Istio",
		Category: CategoryNetwork,
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
		DeploymentPatterns: []string{"istiod", "istio-ingressgateway", "istio-egressgateway"},
		ExpectedNamespaces: []string{"istio-system"},
		CRDGroups:          []string{"security.istio.io", "networking.istio.io"},
		LabelSelectors:     []string{"app=istiod", "istio=pilot"},
		RequireImageVerification: true,
	})

	// Linkerd - Server/ServerAuthorization for L7 network policies
	r.register(&Engine{
		ID:       "linkerd",
		Name:     "Linkerd",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"cr.l5d.io/linkerd/",
			"ghcr.io/linkerd/",
		},
		ImagePatterns: []string{
			"linkerd/controller",
			"linkerd/proxy",
			"linkerd/policy-controller",
		},
		DeploymentPatterns: []string{"linkerd-destination", "linkerd-identity", "linkerd-proxy-injector"},
		ExpectedNamespaces: []string{"linkerd"},
		CRDGroups:          []string{"policy.linkerd.io"},
		LabelSelectors:     []string{"linkerd.io/control-plane-component"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// CNAPP Platforms with Network Capabilities
	// =============================================================================

	// Aqua - Network micro-segmentation
	r.register(&Engine{
		ID:       "aqua",
		Name:     "Aqua Security",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"aquasec/",
			"registry.aquasec.com/",
		},
		ImagePatterns: []string{
			"aquasec/enforcer",
			"aquasec/kube-enforcer",
		},
		DeploymentPatterns: []string{"aqua-enforcer", "aqua-kube-enforcer"},
		ExpectedNamespaces: []string{"aqua", "aqua-security"},
		LabelSelectors:     []string{"app=aqua-enforcer"},
		RequireImageVerification: true,
	})

	// Prisma Cloud - Network segmentation
	r.register(&Engine{
		ID:       "prisma",
		Name:     "Prisma Cloud",
		Category: CategoryNetwork,
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

	// Sysdig - Network security policies
	r.register(&Engine{
		ID:       "sysdig",
		Name:     "Sysdig Secure",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"quay.io/sysdig/",
			"sysdig/",
		},
		ImagePatterns: []string{
			"sysdig/agent",
			"sysdig/node-analyzer",
		},
		DeploymentPatterns: []string{"sysdig-agent"},
		ExpectedNamespaces: []string{"sysdig", "sysdig-agent"},
		LabelSelectors:     []string{"app=sysdig-agent", "app.kubernetes.io/name=sysdig"},
		RequireImageVerification: true,
	})

	// StackRox/RHACS - Network policies
	r.register(&Engine{
		ID:       "stackrox",
		Name:     "StackRox/RHACS",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"quay.io/stackrox-io/",
			"registry.redhat.io/advanced-cluster-security/",
		},
		ImagePatterns: []string{
			"stackrox/main",
			"stackrox/collector",
			"rhacs/main",
		},
		DeploymentPatterns: []string{"central", "sensor", "collector"},
		ExpectedNamespaces: []string{"stackrox", "rhacs-operator"},
		CRDGroups:          []string{"platform.stackrox.io"},
		LabelSelectors:     []string{"app=central", "app=sensor"},
		RequireImageVerification: true,
	})

	// NeuVector - Network segmentation and protection
	r.register(&Engine{
		ID:       "neuvector",
		Name:     "NeuVector",
		Category: CategoryNetwork,
		TrustedRegistries: []string{
			"neuvector/",
			"docker.io/neuvector/",
		},
		ImagePatterns: []string{
			"neuvector/enforcer",
			"neuvector/controller",
			"neuvector/manager",
		},
		DeploymentPatterns: []string{"neuvector-controller-pod", "neuvector-manager-pod"},
		ExpectedNamespaces: []string{"neuvector", "cattle-neuvector-system"},
		CRDGroups:          []string{"neuvector.com"},
		LabelSelectors:     []string{"app=neuvector-controller-pod", "app=neuvector-enforcer-pod"},
		RequireImageVerification: true,
	})

	// =============================================================================
	// Additional Policy/Security Tools with Network Capabilities
	// =============================================================================

	// Polaris - Checks for NetworkPolicy existence as a best practice
	r.register(&Engine{
		ID:       "polaris",
		Name:     "Polaris",
		Category: CategoryNetwork,
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

	// Conftest - OPA-based policy testing for NetworkPolicy resources
	r.register(&Engine{
		ID:       "conftest",
		Name:     "Conftest",
		Category: CategoryNetwork,
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

	// =============================================================================
	// Multitenancy Platforms with Network Isolation
	// =============================================================================

	// Capsule - Tenant network isolation
	r.register(&Engine{
		ID:       "capsule",
		Name:     "Capsule",
		Category: CategoryNetwork,
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

	// Rancher - Project-level network isolation policies
	r.register(&Engine{
		ID:       "rancher",
		Name:     "Rancher",
		Category: CategoryNetwork,
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
		CRDGroups:          []string{"management.cattle.io", "project.cattle.io"},
		LabelSelectors:     []string{"app=rancher"},
		RequireImageVerification: true,
	})
}
