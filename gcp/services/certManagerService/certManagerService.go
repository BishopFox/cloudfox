package certmanagerservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	certificatemanager "google.golang.org/api/certificatemanager/v1"
	compute "google.golang.org/api/compute/v1"
)

type CertManagerService struct {
	session *gcpinternal.SafeSession
}

func New() *CertManagerService {
	return &CertManagerService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *CertManagerService {
	return &CertManagerService{
		session: session,
	}
}

// Certificate represents an SSL/TLS certificate
type Certificate struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Location        string   `json:"location"`
	Type            string   `json:"type"` // SELF_MANAGED, GOOGLE_MANAGED
	Domains         []string `json:"domains"`
	ExpireTime      string   `json:"expireTime"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	State           string   `json:"state"`
	IssuanceState   string   `json:"issuanceState"`
	AttachedTo      []string `json:"attachedTo"` // LBs or other resources
	Wildcard        bool     `json:"wildcard"`
	Expired         bool     `json:"expired"`
	SelfManaged     bool     `json:"selfManaged"`
}

// SSLCertificate represents a compute SSL certificate (classic)
type SSLCertificate struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Type            string   `json:"type"` // SELF_MANAGED, MANAGED
	Domains         []string `json:"domains"`
	ExpireTime      string   `json:"expireTime"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	CreationTime    string   `json:"creationTime"`
	Wildcard        bool     `json:"wildcard"`
	Expired         bool     `json:"expired"`
	SelfManaged     bool     `json:"selfManaged"`
}

// CertificateMap represents a Certificate Manager certificate map
type CertificateMap struct {
	Name         string   `json:"name"`
	ProjectID    string   `json:"projectId"`
	Location     string   `json:"location"`
	EntryCount   int      `json:"entryCount"`
	Certificates []string `json:"certificates"`
}

// getCertManagerService returns a Certificate Manager service client using cached session if available
func (s *CertManagerService) getCertManagerService(ctx context.Context) (*certificatemanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetCertificateManagerService(ctx, s.session)
	}
	return certificatemanager.NewService(ctx)
}

// getComputeService returns a Compute service client using cached session if available
func (s *CertManagerService) getComputeService(ctx context.Context) (*compute.Service, error) {
	if s.session != nil {
		return sdk.CachedGetComputeService(ctx, s.session)
	}
	return compute.NewService(ctx)
}

// GetCertificates retrieves Certificate Manager certificates
func (s *CertManagerService) GetCertificates(projectID string) ([]Certificate, error) {
	ctx := context.Background()
	service, err := s.getCertManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "certificatemanager.googleapis.com")
	}

	var certificates []Certificate

	// List certificates in all locations (global and regional)
	locations := []string{"global"}

	for _, location := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)
		resp, err := service.Projects.Locations.Certificates.List(parent).Context(ctx).Do()
		if err != nil {
			continue // May not have permissions or no certificates
		}

		for _, cert := range resp.Certificates {
			c := Certificate{
				Name:      extractNameFromPath(cert.Name),
				ProjectID: projectID,
				Location:  location,
				Domains:   cert.SanDnsnames,
			}

			// Determine type and state
			if cert.Managed != nil {
				c.Type = "GOOGLE_MANAGED"
				c.State = cert.Managed.State
				c.IssuanceState = cert.Managed.State
			} else if cert.SelfManaged != nil {
				c.Type = "SELF_MANAGED"
				c.State = "ACTIVE" // Self-managed certs are active if they exist
				c.SelfManaged = true
			}

			// Parse expiration
			if cert.ExpireTime != "" {
				c.ExpireTime = cert.ExpireTime
				expTime, err := time.Parse(time.RFC3339, cert.ExpireTime)
				if err == nil {
					c.DaysUntilExpiry = int(time.Until(expTime).Hours() / 24)
					c.Expired = c.DaysUntilExpiry < 0
				}
			}

			// Check for wildcard domains
			for _, domain := range c.Domains {
				if strings.HasPrefix(domain, "*") {
					c.Wildcard = true
					break
				}
			}

			certificates = append(certificates, c)
		}
	}

	return certificates, nil
}

// GetSSLCertificates retrieves classic Compute Engine SSL certificates
func (s *CertManagerService) GetSSLCertificates(projectID string) ([]SSLCertificate, error) {
	ctx := context.Background()
	service, err := s.getComputeService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var certificates []SSLCertificate

	// Get all SSL certificates (global and regional) using AggregatedList
	// This only requires compute.sslCertificates.list permission (not compute.regions.list)
	req := service.SslCertificates.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.SslCertificateAggregatedList) error {
		for scopeName, scopedList := range page.Items {
			if scopedList.SslCertificates == nil {
				continue
			}
			// Extract region from scope name (format: "regions/us-central1" or "global")
			region := ""
			if strings.HasPrefix(scopeName, "regions/") {
				region = strings.TrimPrefix(scopeName, "regions/")
			}

			for _, cert := range scopedList.SslCertificates {
				c := SSLCertificate{
					Name:         cert.Name,
					ProjectID:    projectID,
					Type:         cert.Type,
					CreationTime: cert.CreationTimestamp,
					SelfManaged:  cert.Type == "SELF_MANAGED",
				}

				// Add region to name for regional certs
				if region != "" {
					c.Name = fmt.Sprintf("%s (%s)", cert.Name, region)
				}

				// Get domains from managed certificate
				if cert.Managed != nil {
					c.Domains = cert.Managed.Domains
				}

				// Parse expiration
				if cert.ExpireTime != "" {
					c.ExpireTime = cert.ExpireTime
					expTime, err := time.Parse(time.RFC3339, cert.ExpireTime)
					if err == nil {
						c.DaysUntilExpiry = int(time.Until(expTime).Hours() / 24)
						c.Expired = c.DaysUntilExpiry < 0
					}
				}

				// Check for wildcard domains
				for _, domain := range c.Domains {
					if strings.HasPrefix(domain, "*") {
						c.Wildcard = true
						break
					}
				}

				certificates = append(certificates, c)
			}
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	return certificates, nil
}

// GetCertificateMaps retrieves certificate maps
func (s *CertManagerService) GetCertificateMaps(projectID string) ([]CertificateMap, error) {
	ctx := context.Background()
	service, err := s.getCertManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "certificatemanager.googleapis.com")
	}

	var maps []CertificateMap

	locations := []string{"global"}

	for _, location := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)
		resp, err := service.Projects.Locations.CertificateMaps.List(parent).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, certMap := range resp.CertificateMaps {
			cm := CertificateMap{
				Name:      extractNameFromPath(certMap.Name),
				ProjectID: projectID,
				Location:  location,
			}

			// Get entries for this map
			entriesResp, err := service.Projects.Locations.CertificateMaps.CertificateMapEntries.List(certMap.Name).Context(ctx).Do()
			if err == nil {
				cm.EntryCount = len(entriesResp.CertificateMapEntries)
				for _, entry := range entriesResp.CertificateMapEntries {
					for _, certRef := range entry.Certificates {
						cm.Certificates = append(cm.Certificates, extractNameFromPath(certRef))
					}
				}
			}

			maps = append(maps, cm)
		}
	}

	return maps, nil
}

func extractNameFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}
