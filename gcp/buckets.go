package gcp

import (
	"context"
	"log"
	"fmt"
	"sort"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal"
	"google.golang.org/api/option"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

var (
	GCPLogger = internal.NewLogger()
)

type BucketsModule struct {
	Client gcp.GCPClient
	StorageClient *storage.Client

	// Filtering data
	Organizations []string
	Folders []string
	Projects []string
}

type ObjectInfo struct {
	ObjectName      string  `json:"objecttName"`
	ObjectSizeBytes float64 `json:"objectSizeBytes"`
	IsPublic        bool    `json:"isPublic"`
}

type BucketInfo struct {
	BucketName   string       `json:"bucketName"`
	BucketSizeMB float64      `json:"bucketSizeMB"`
	Objects      []ObjectInfo `json:"objectInfo"`
}

func (m *BucketsModule) ListBuckets(projects []string) error {
	// retrieve all resource and do filtering
	m.Client.GetResourcesRoots(m.Organizations, m.Folders, m.Projects)
	GCPLogger.InfoM(fmt.Sprintf("Enumerating GCP buckets with account %s...", m.Client.Name), globals.GCP_BUCKETS_MODULE_NAME)

	ctx := context.Background()
	var err error
	m.StorageClient, err = storage.NewClient(ctx, option.WithHTTPClient(m.Client.HTTPClient))

	if err != nil {
		GCPLogger.ErrorM("Could not create GCP storage client...", globals.GCP_BUCKETS_MODULE_NAME)
		return err
	}


	if len(projects) > 0 {
		for _, project := range projects {
			m.ListBucketsInProject(project)
		}
	} else {
		for _, project := range m.Client.Projects {
			m.ListBucketsInProject(project)
		}
	}
	return nil
}


func (m *BucketsModule) ListBucketsInProject(project string) error {
	bucketInfos := make(map[string][]BucketInfo)
	ctx := context.Background()
	GCPLogger.InfoM(fmt.Sprintf("Iterating through project %s...", project), globals.GCP_BUCKETS_MODULE_NAME)
	buckets := m.StorageClient.Buckets(ctx, project)
	for {
		bucketAttrs, err := buckets.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			GCPLogger.ErrorM(fmt.Sprintf("Failed to list buckets : %v", err), globals.GCP_BUCKETS_MODULE_NAME)
			return err
		}

		bucketName := bucketAttrs.Name
		GCPLogger.InfoM(fmt.Sprintf("Enumerating bucket %s...", bucketName), globals.GCP_BUCKETS_MODULE_NAME)

		// List all objects in the bucket and calculate total size
		totalSize := int64(0)
		var objects []ObjectInfo
		it := m.StorageClient.Bucket(bucketName).Objects(ctx, nil)
		for {
			objectAttrs, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatalf("Failed to list objects: %v", err)
				GCPLogger.ErrorM(fmt.Sprintf("Failed to list objects : %v", err), globals.GCP_BUCKETS_MODULE_NAME)
				break
			}

			// Get size
			objectSize := objectAttrs.Size
			totalSize += objectSize

			// Check if public
			isPublic := false
			for _, rule := range objectAttrs.ACL {
				if rule.Entity == storage.AllUsers {
					isPublic = true
					break
				}
			}

			objects = append(objects, ObjectInfo{ObjectName: objectAttrs.Name, ObjectSizeBytes: float64(objectSize), IsPublic: isPublic})

			if totalSize > 3221225472 { // 3 GiB in bytes
				GCPLogger.InfoM(fmt.Sprintf("%s bucket is over 3 GiB. Skipping remaining objects in this bucket...", bucketName), globals.GCP_BUCKETS_MODULE_NAME)
				break
			}
		}
		bucketSizeMB := float64(totalSize) / 1024 / 1024
		bucketInfos[project] = append(bucketInfos[project], BucketInfo{BucketName: bucketName, BucketSizeMB: bucketSizeMB, Objects: objects})
	}
	log.Printf("Sorting resulting list of buckets in descending order %s", project)
	sort.Slice(bucketInfos[project], func(i, j int) bool {
		return bucketInfos[project][i].BucketSizeMB > bucketInfos[project][j].BucketSizeMB
	})

	log.Printf("Done with project %s", project)
	return nil
}
