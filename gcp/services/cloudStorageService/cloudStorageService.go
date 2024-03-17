package cloudstorageservice

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type CloudStorageService struct {
	// DataStoreService datastoreservice.DataStoreService
}

func New() *CloudStorageService {
	return &CloudStorageService{}
}

// type ObjectInfo struct {
// 	ObjectName      string  `json:"objecttName"`
// 	ObjectSizeBytes float64 `json:"objectSizeBytes"`
// 	IsPublic        bool    `json:"isPublic"`
// }

type BucketInfo struct {
	Name      string `json:"name"`
	Location  string `json:"location"`
	ProjectID string `json:"projectID"`
}

func (cs *CloudStorageService) Buckets(projectID string) ([]BucketInfo, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to create client: %v", err)
	}
	defer client.Close()

	var buckets []BucketInfo
	bucketIterator := client.Buckets(ctx, projectID)
	for {
		battrs, err := bucketIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		bucket := BucketInfo{Name: battrs.Name, Location: battrs.Location, ProjectID: projectID}
		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

// func (cs *CloudStorageService) BucketsWithMetaData(projectID string) (map[string][]BucketInfo, error) {
// 	buckets, _ := cs.Buckets(projectID)
// 	bucketInfos := make(map[string][]BucketInfo)
// 	ctx := context.Background()
// 	client, err := storage.NewClient(ctx)
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to create client: %v", err)
// 	}
// 	for {
// 		bucketAttrs, err := buckets.Next()
// 		if err == iterator.Done {
// 			break
// 		}
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to list buckets: %v", err)
// 		}

// 		bucketName := bucketAttrs.Name
// 		log.Printf("Working on bucket %s", bucketName)

// 		// List all objects in the bucket and calculate total size
// 		totalSize := int64(0)
// 		var objects []ObjectInfo
// 		it := client.Bucket(bucketName).Objects(ctx, nil)
// 		for {
// 			objectAttrs, err := it.Next()
// 			if err == iterator.Done {
// 				break
// 			}
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to list objects in bucket %s: %v", bucketName, err)
// 			}

// 			// Get size
// 			objectSize := objectAttrs.Size
// 			totalSize += objectSize

// 			// Check if public
// 			isPublic := false
// 			for _, rule := range objectAttrs.ACL {
// 				if rule.Entity == storage.AllUsers {
// 					isPublic = true
// 					break
// 				}
// 			}

// 			objects = append(objects, ObjectInfo{ObjectName: objectAttrs.Name, ObjectSizeBytes: float64(objectSize), IsPublic: isPublic})

// 			if totalSize > 3221225472 { // 3 GiB in bytes
// 				log.Printf("%s bucket is over 3 GiB. Skipping remaining objects in this bucket...", bucketName)
// 				break
// 			}
// 		}
// 		bucketSizeMB := float64(totalSize) / 1024 / 1024
// 		bucketInfos[projectID] = append(bucketInfos[projectID], BucketInfo{BucketName: bucketName, BucketSizeMB: bucketSizeMB, Objects: objects})
// 	}
// 	log.Printf("Sorting resulting list of buckets in descending order %s", projectID)
// 	sort.Slice(bucketInfos[projectID], func(i, j int) bool {
// 		return bucketInfos[projectID][i].BucketSizeMB > bucketInfos[projectID][j].BucketSizeMB
// 	})

// 	return bucketInfos, nil
// }
