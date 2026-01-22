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
}
