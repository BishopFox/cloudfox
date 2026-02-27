package filestoreservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	file "google.golang.org/api/file/v1"
)

type FilestoreService struct {
	session *gcpinternal.SafeSession
}

func New() *FilestoreService {
	return &FilestoreService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *FilestoreService {
	return &FilestoreService{
		session: session,
	}
}

type FilestoreInstanceInfo struct {
	Name        string   `json:"name"`
	ProjectID   string   `json:"projectId"`
	Location    string   `json:"location"`
	Tier        string   `json:"tier"`
	State       string   `json:"state"`
	Network     string   `json:"network"`
	IPAddresses []string `json:"ipAddresses"`
	Shares      []ShareInfo `json:"shares"`
	CreateTime  string   `json:"createTime"`
	Protocol    string   `json:"protocol"` // NFS_V3, NFS_V4_1
}

type ShareInfo struct {
	Name            string            `json:"name"`
	CapacityGB      int64             `json:"capacityGb"`
	NfsExportOptions []NfsExportOption `json:"nfsExportOptions"`
}

type NfsExportOption struct {
	IPRanges   []string `json:"ipRanges"`
	AccessMode string   `json:"accessMode"` // READ_ONLY, READ_WRITE
	SquashMode string   `json:"squashMode"` // NO_ROOT_SQUASH, ROOT_SQUASH
	AnonUID    int64    `json:"anonUid"`
	AnonGID    int64    `json:"anonGid"`
}

// getService returns a Filestore service client using cached session if available
func (s *FilestoreService) getService(ctx context.Context) (*file.Service, error) {
	if s.session != nil {
		return sdk.CachedGetFilestoreService(ctx, s.session)
	}
	return file.NewService(ctx)
}

func (s *FilestoreService) ListInstances(projectID string) ([]FilestoreInstanceInfo, error) {
	ctx := context.Background()
	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "file.googleapis.com")
	}

	var instances []FilestoreInstanceInfo
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	req := service.Projects.Locations.Instances.List(parent)
	err = req.Pages(ctx, func(page *file.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			info := FilestoreInstanceInfo{
				Name:        extractResourceName(instance.Name),
				ProjectID:   projectID,
				Location:    extractLocation(instance.Name),
				Tier:        instance.Tier,
				State:       instance.State,
				CreateTime:  instance.CreateTime,
				Protocol:    instance.Protocol, // NFS_V3, NFS_V4_1
			}

			if len(instance.Networks) > 0 {
				info.Network = instance.Networks[0].Network
				info.IPAddresses = instance.Networks[0].IpAddresses
			}

			for _, share := range instance.FileShares {
				shareInfo := ShareInfo{
					Name:       share.Name,
					CapacityGB: share.CapacityGb,
				}

				// Parse NFS export options
				for _, opt := range share.NfsExportOptions {
					exportOpt := NfsExportOption{
						IPRanges:   opt.IpRanges,
						AccessMode: opt.AccessMode,
						SquashMode: opt.SquashMode,
						AnonUID:    opt.AnonUid,
						AnonGID:    opt.AnonGid,
					}
					shareInfo.NfsExportOptions = append(shareInfo.NfsExportOptions, exportOpt)
				}

				info.Shares = append(info.Shares, shareInfo)
			}
			instances = append(instances, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "file.googleapis.com")
	}
	return instances, nil
}

func extractResourceName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}

func extractLocation(name string) string {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
