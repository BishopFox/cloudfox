package gcp

import (
	"context"
	"log"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	goauth2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/cloudasset/v1p1beta1"
)

type GCPClient struct {
	TokenSource *oauth2.TokenSource
	TokenInfo *goauth2.Tokeninfo
	CloudresourcemanagerService *cloudresourcemanager.Service
	CloudAssetService *cloudasset.Service
	ResourcesService *cloudasset.ResourcesService
	IamPoliciesService *cloudasset.IamPoliciesService
}

func (g *GCPClient) init() {
	ctx := context.Background()
	var (
		profiles []GCloudProfile
		profile GCloudProfile
	)
	profiles = listAllProfiles()
	profile = profiles[len(profiles)-1]

	// Initiate an http.Client. The following GET request will be
	// authorized and authenticated on the behalf of the SDK user.
	client := profile.oauth_conf.Client(ctx, &(profile.initial_token))
	ts, err := google.DefaultTokenSource(ctx)
	if err != nil {
		log.Fatal(err)
	}
	g.TokenSource = &ts
	oauth2Service, err := goauth2.NewService(ctx, option.WithHTTPClient(client))
	tokenInfo, err := oauth2Service.Tokeninfo().Do()
	if err != nil {
		log.Fatal(err)
	}
	g.TokenInfo = tokenInfo
	cloudresourcemanagerService, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatal(err)
	}
	g.CloudresourcemanagerService = cloudresourcemanagerService
	cloudassetService, err := cloudasset.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatal(err)
	}
	g.CloudAssetService = cloudassetService
	g.ResourcesService = cloudasset.NewResourcesService(cloudassetService)
	g.IamPoliciesService = cloudasset.NewIamPoliciesService(cloudassetService)
	
}

func NewGCPClient() *GCPClient {
	client := new(GCPClient)
	client.init()
	return client
}
