package admission

// registerMeshEngines registers all service mesh engines
func (r *EngineRegistry) registerMeshEngines() {
	// Istio
	r.register(&Engine{
		ID:       "istio",
		Name:     "Istio",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"docker.io/istio/",
			"gcr.io/istio-release/",
			"istio/",
		},
		ImagePatterns: []string{
			"istio/proxyv2",
			"istio/pilot",
			"istio/istiod",
			"istiod",
		},
		DeploymentPatterns: []string{"istiod", "istio-pilot", "istio-ingressgateway", "istio-egressgateway"},
		ExpectedNamespaces: []string{"istio-system", "istio"},
		WebhookPatterns:    []string{"istio-sidecar-injector", "istio-validator"},
		CRDGroups:          []string{"security.istio.io", "networking.istio.io", "telemetry.istio.io"},
		LabelSelectors:     []string{"app=istiod", "istio=pilot"},
		RequireImageVerification: true,
	})

	// Linkerd
	r.register(&Engine{
		ID:       "linkerd",
		Name:     "Linkerd",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"cr.l5d.io/linkerd/",
			"ghcr.io/linkerd/",
		},
		ImagePatterns: []string{
			"linkerd/proxy",
			"linkerd/controller",
			"linkerd-io/proxy",
			"linkerd2-proxy",
		},
		DeploymentPatterns: []string{"linkerd-destination", "linkerd-controller", "linkerd-identity", "linkerd-proxy-injector"},
		ExpectedNamespaces: []string{"linkerd", "linkerd-viz"},
		WebhookPatterns:    []string{"linkerd-proxy-injector", "linkerd-sp-validator"},
		CRDGroups:          []string{"policy.linkerd.io", "server.linkerd.io"},
		LabelSelectors:     []string{"linkerd.io/control-plane-component", "app.kubernetes.io/name=linkerd"},
		RequireImageVerification: true,
	})

	// Cilium Service Mesh
	r.register(&Engine{
		ID:       "cilium-mesh",
		Name:     "Cilium Service Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"cilium/",
			"quay.io/cilium/",
		},
		ImagePatterns: []string{
			"cilium/cilium",
			"cilium/operator",
			"cilium/hubble",
		},
		DeploymentPatterns: []string{"cilium-operator", "hubble-relay"},
		ExpectedNamespaces: []string{"kube-system", "cilium"},
		CRDGroups:          []string{"cilium.io"},
		LabelSelectors:     []string{"k8s-app=cilium", "io.cilium/app=operator"},
		RequireImageVerification: true,
	})

	// Consul Connect
	r.register(&Engine{
		ID:       "consul",
		Name:     "Consul Connect",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"hashicorp/",
			"docker.io/hashicorp/",
		},
		ImagePatterns: []string{
			"hashicorp/consul",
			"consul-k8s",
			"consul-connect-inject",
			"consul-dataplane",
		},
		DeploymentPatterns: []string{"consul-server", "consul-connect-injector"},
		ExpectedNamespaces: []string{"consul", "hashicorp"},
		WebhookPatterns:    []string{"consul-connect-injector"},
		CRDGroups:          []string{"consul.hashicorp.com"},
		LabelSelectors:     []string{"app=consul", "component=connect-injector"},
		RequireImageVerification: true,
	})

	// Open Service Mesh (OSM)
	r.register(&Engine{
		ID:       "osm",
		Name:     "Open Service Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"openservicemesh/",
			"flomesh/",
		},
		ImagePatterns: []string{
			"openservicemesh/osm",
			"osm-controller",
			"osm-injector",
			"flomesh/osm",
		},
		DeploymentPatterns: []string{"osm-controller", "osm-injector", "osm-bootstrap"},
		ExpectedNamespaces: []string{"osm-system", "arc-osm-system"},
		WebhookPatterns:    []string{"osm-mutating", "osm-validating"},
		CRDGroups:          []string{"config.openservicemesh.io", "policy.openservicemesh.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=openservicemesh.io", "app=osm-controller"},
		RequireImageVerification: true,
	})

	// Kuma / Kong Mesh
	r.register(&Engine{
		ID:       "kuma",
		Name:     "Kuma",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"kumahq/",
			"docker.io/kumahq/",
			"kong/",
		},
		ImagePatterns: []string{
			"kumahq/kuma",
			"kuma-cp",
			"kuma-dp",
			"kuma-init",
			"kong/kuma",
		},
		DeploymentPatterns: []string{"kuma-control-plane"},
		ExpectedNamespaces: []string{"kuma-system"},
		WebhookPatterns:    []string{"kuma-admission-mutating", "kuma-validating"},
		CRDGroups:          []string{"kuma.io"},
		LabelSelectors:     []string{"app=kuma-control-plane", "app.kubernetes.io/name=kuma"},
		RequireImageVerification: true,
	})

	// AWS App Mesh
	r.register(&Engine{
		ID:       "appmesh",
		Name:     "AWS App Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"amazon/",
			"public.ecr.aws/",
			"602401143452.dkr.ecr.",
		},
		ImagePatterns: []string{
			"aws-appmesh-envoy",
			"amazon/appmesh",
			"appmesh-controller",
			"appmesh-injector",
		},
		DeploymentPatterns: []string{"appmesh-controller", "appmesh-inject"},
		ExpectedNamespaces: []string{"appmesh-system", "kube-system"},
		WebhookPatterns:    []string{"appmesh-inject"},
		CRDGroups:          []string{"appmesh.k8s.aws"},
		LabelSelectors:     []string{"app.kubernetes.io/name=appmesh-controller"},
		RequireImageVerification: true,
	})

	// Traefik Mesh (formerly Maesh)
	r.register(&Engine{
		ID:       "traefik-mesh",
		Name:     "Traefik Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"traefik/",
			"docker.io/traefik/",
		},
		ImagePatterns: []string{
			"traefik/mesh",
			"traefik-mesh",
			"maesh",
		},
		DeploymentPatterns: []string{"traefik-mesh-controller"},
		ExpectedNamespaces: []string{"traefik-mesh", "maesh"},
		CRDGroups:          []string{"access.smi-spec.io", "specs.smi-spec.io"},
		LabelSelectors:     []string{"app=traefik-mesh"},
		RequireImageVerification: true,
	})

	// NGINX Service Mesh
	r.register(&Engine{
		ID:       "nginx-mesh",
		Name:     "NGINX Service Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"docker-registry.nginx.com/",
		},
		ImagePatterns: []string{
			"nsm-controller",
			"nginx-mesh-sidecar",
			"nginx-mesh-init",
		},
		DeploymentPatterns: []string{"nsm-controller"},
		ExpectedNamespaces: []string{"nginx-mesh"},
		CRDGroups:          []string{"specs.smi.nginx.com"},
		LabelSelectors:     []string{"app.kubernetes.io/name=nginx-service-mesh"},
		RequireImageVerification: true,
	})

	// Gloo Mesh (Solo.io)
	r.register(&Engine{
		ID:       "gloo-mesh",
		Name:     "Gloo Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"gcr.io/gloo-mesh/",
			"quay.io/solo-io/",
		},
		ImagePatterns: []string{
			"gloo-mesh-mgmt-server",
			"gloo-mesh-agent",
		},
		DeploymentPatterns: []string{"gloo-mesh-mgmt-server", "gloo-mesh-agent"},
		ExpectedNamespaces: []string{"gloo-mesh"},
		CRDGroups:          []string{"networking.mesh.gloo.solo.io", "discovery.mesh.gloo.solo.io"},
		LabelSelectors:     []string{"app=gloo-mesh-mgmt-server"},
		RequireImageVerification: true,
	})

	// Flomesh Service Mesh (FSM) - successor to OSM
	r.register(&Engine{
		ID:       "fsm",
		Name:     "Flomesh Service Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"flomesh/",
			"docker.io/flomesh/",
		},
		ImagePatterns: []string{
			"flomesh/fsm-controller",
			"flomesh/fsm-injector",
			"flomesh/fsm-bootstrap",
			"flomesh/pipy",
			"fsm-controller",
			"fsm-injector",
		},
		DeploymentPatterns: []string{"fsm-controller", "fsm-injector", "fsm-bootstrap"},
		ExpectedNamespaces: []string{"fsm-system", "kube-system"},
		WebhookPatterns:    []string{"fsm-mutating", "fsm-validating"},
		CRDGroups:          []string{"flomesh.io", "gateway.flomesh.io", "policy.flomesh.io"},
		LabelSelectors:     []string{"app.kubernetes.io/name=flomesh.io", "app=fsm-controller"},
		RequireImageVerification: true,
	})

	// GCP Traffic Director / Anthos Service Mesh
	r.register(&Engine{
		ID:       "gcp-traffic-director",
		Name:     "GCP Traffic Director",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"gcr.io/gke-release/",
			"gke.gcr.io/",
		},
		ImagePatterns: []string{
			"gke.gcr.io/asm/",
			"traffic-director-proxyv2",
			"td-grpc-bootstrap",
			"gcp-traffic-director",
		},
		DeploymentPatterns: []string{"traffic-director"},
		ExpectedNamespaces: []string{"kube-system", "gke-system", "asm-system"},
		CRDGroups:          []string{"networking.gke.io", "hub.gke.io"},
		LabelSelectors:     []string{"app=traffic-director"},
		RequireImageVerification: true,
	})

	// GCP Anthos Service Mesh
	r.register(&Engine{
		ID:       "anthos-service-mesh",
		Name:     "Anthos Service Mesh",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"gcr.io/gke-release/",
			"gke.gcr.io/",
		},
		ImagePatterns: []string{
			"gke.gcr.io/asm/",
			"asm/proxyv2",
			"asm/pilot",
			"managed-cni",
		},
		DeploymentPatterns: []string{"istiod-asm", "canonical-service-controller"},
		ExpectedNamespaces: []string{"asm-system", "istio-system", "gke-managed-cni"},
		WebhookPatterns:    []string{"istiod-asm"},
		CRDGroups:          []string{"security.istio.io", "networking.istio.io", "mesh.cloud.google.com"},
		LabelSelectors:     []string{"app=istiod", "istio.io/rev"},
		RequireImageVerification: true,
	})

	// Azure Application Gateway Ingress Controller (AGIC)
	r.register(&Engine{
		ID:       "azure-agic",
		Name:     "Azure Application Gateway Ingress",
		Category: CategoryMesh,
		TrustedRegistries: []string{
			"mcr.microsoft.com/",
		},
		ImagePatterns: []string{
			"azure-application-gateway-kubernetes-ingress",
			"application-gateway-kubernetes-ingress",
		},
		DeploymentPatterns: []string{"ingress-appgw-deployment", "ingress-azure"},
		ExpectedNamespaces: []string{"kube-system", "azure-agic"},
		CRDGroups:          []string{"appgw.ingress.k8s.io"},
		LabelSelectors:     []string{"app=ingress-azure"},
		RequireImageVerification: true,
	})
}
