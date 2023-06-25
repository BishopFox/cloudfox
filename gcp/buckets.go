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

func (m *BucketsModule) GetData(projectIDs []string) error {
	// 	Use:   "getBucketData",
	// Short: "Retrieves storage bucket names and sizes given project id(s).
	GCPLogger.InfoM(fmt.Sprintf("Enumerating GCP buckets with account %s...\n", m.Client.Name), globals.GCP_BUCKETS_MODULE_NAME)

	ctx := context.Background()
	storageclient, err := storage.NewClient(ctx, option.WithHTTPClient(m.Client.HTTPClient))

	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	bucketInfos := make(map[string][]BucketInfo)

	for _, projectID := range projectIDs {
		log.Printf("Iterating through project %s", projectID)
		buckets := storageclient.Buckets(ctx, projectID)
		for {
			bucketAttrs, err := buckets.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatalf("Failed to list buckets: %v", err)
			}

			bucketName := bucketAttrs.Name
			log.Printf("Working on bucket %s", bucketName)

			// List all objects in the bucket and calculate total size
			totalSize := int64(0)
			var objects []ObjectInfo
			it := storageclient.Bucket(bucketName).Objects(ctx, nil)
			for {
				objectAttrs, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					log.Fatalf("Failed to list objects: %v", err)
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
					log.Printf("%s bucket is over 3 GiB. Skipping remaining objects in this bucket...", bucketName)
					break
				}
			}
			bucketSizeMB := float64(totalSize) / 1024 / 1024
			bucketInfos[projectID] = append(bucketInfos[projectID], BucketInfo{BucketName: bucketName, BucketSizeMB: bucketSizeMB, Objects: objects})
		}
		log.Printf("Sorting resulting list of buckets in descending order %s", projectID)
		sort.Slice(bucketInfos[projectID], func(i, j int) bool {
			return bucketInfos[projectID][i].BucketSizeMB > bucketInfos[projectID][j].BucketSizeMB
		})

		log.Printf("Done with project %s", projectID)
	}
	return nil
}
