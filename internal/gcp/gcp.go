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
}

func (g *GCPClient) init() {
	ctx := context.Background()
	ts, err := google.DefaultTokenSource(ctx)
	if err != nil {
		log.Fatal(err)
	}
	g.TokenSource = &ts
	oauth2Service, err := goauth2.NewService(ctx, option.WithTokenSource(ts))
	tokenInfo, err := oauth2Service.Tokeninfo().Do()
	if err != nil {
		log.Fatal(err)
	}
	g.TokenInfo = tokenInfo
	cloudresourcemanagerService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Fatal(err)
	}
	g.CloudresourcemanagerService = cloudresourcemanagerService
	cloudassetService, err := cloudasset.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Fatal(err)
	}
	g.CloudAssetService = cloudassetService
}

func NewGCPClient() *GCPClient {
	client := new(GCPClient)
	client.init()
	return client
}
