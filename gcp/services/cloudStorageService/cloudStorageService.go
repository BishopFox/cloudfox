package cloudstorageservice

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type CloudStorageService struct {
	ctx    context.Context
	client *storage.Client
}

func New() *CloudStorageService {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to create client: %v", err))
	}
	return &CloudStorageService{
		ctx:    ctx,
		client: client,
	}
}

// type ObjectInfo struct {
// 	ObjectName      string  `json:"objecttName"`
// 	ObjectSizeBytes float64 `json:"objectSizeBytes"`
// 	IsPublic        bool    `json:"isPublic"`
// }

type BucketInfo struct {
	Name      string
	Location  string
	ProjectID string
	IsPublic  string
}

// Buckets retrieves all buckets in the specified project.
func (cs *CloudStorageService) Buckets(projectID string) ([]BucketInfo, error) {
	var buckets []BucketInfo
	bucketIterator := cs.client.Buckets(cs.ctx, projectID)
	for {
		battrs, err := bucketIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		bucket := BucketInfo{
			Name:      battrs.Name,
			Location:  battrs.Location,
			ProjectID: projectID,
			IsPublic:  cs.isBucketPublic(battrs),
		}
		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

// Close closes the Cloud Storage client.
func (cs *CloudStorageService) Close() error {
	return cs.client.Close()
}

// isBucketPublic checks if a bucket is publicly accessible.
func (cs *CloudStorageService) isBucketPublic(bucketAttrs *storage.BucketAttrs) string {
	if bucketAttrs.PublicAccessPrevention == storage.PublicAccessPreventionEnforced {
		return "No"
	}

	if bucketAttrs.UniformBucketLevelAccess.Enabled {
		// With Uniform Bucket-Level Access enabled, ACLs are disabled.
		policy, err := cs.client.Bucket(bucketAttrs.Name).IAM().V3().Policy(cs.ctx)
		if err != nil {
			panic(err)
		}

		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					return fmt.Sprintf("Yes - IAM (%v)", member)
				}
			}
		}
	} else {
		acls := bucketAttrs.ACL
		for _, acl := range acls {
			if acl.Entity == storage.AllUsers || acl.Entity == storage.AllAuthenticatedUsers {
				return fmt.Sprintf("Yes - ACL (%v)", acl.Entity)
			}
		}

		defaultAcls := bucketAttrs.DefaultObjectACL
		for _, acl := range defaultAcls {
			if acl.Entity == storage.AllUsers || acl.Entity == storage.AllAuthenticatedUsers {
				return fmt.Sprintf("Yes - Default ACL (%v)", acl.Entity)
			}
		}
	}

	return "No"
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
