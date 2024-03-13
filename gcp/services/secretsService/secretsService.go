package secretservice

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
)

// Wrappers and abstracting types to facilitate mocking the client responses
type Iterator interface {
	Next() (*secretmanagerpb.Secret, error)
}

type SecretsManagerClientWrapper struct {
	Closer       func() error
	SecretLister func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator
}

func (w *SecretsManagerClientWrapper) Close() error {
	return w.Closer()
}

func (w *SecretsManagerClientWrapper) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator {
	return w.SecretLister(ctx, req, opts...)

}

type SecretsService struct {
	Client *SecretsManagerClientWrapper
}

// New function to facilitate using the ss client
func New(client *secretmanager.Client) SecretsService {
	ss := SecretsService{
		Client: &SecretsManagerClientWrapper{
			Closer: client.Close,
			SecretLister: func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator {
				return client.ListSecrets(ctx, req, opts...)
			},
		},
	}
	return ss
}

type SecretInfo struct {
	Name         string            `json:"name"`
	ProjectID    string            `json:"projectID"`
	CreationTime string            `json:"creationTime"`
	Labels       map[string]string `json:"labels"`
	Rotation     string            `json:"rotation,omitempty"`
}

func (ss *SecretsService) Secrets(projectID string) ([]SecretInfo, error) {
	var secrets []SecretInfo
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
	}

	ctx := context.Background()
	it := ss.Client.ListSecrets(ctx, req)
	for {
		resp, err := it.Next() //Here it errors out
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %v", err)
		}

		secrets = append(secrets, SecretInfo{
			Name:         resp.Name,
			ProjectID:    projectID,
			CreationTime: resp.CreateTime.AsTime().String(),
			Labels:       resp.Labels,
			Rotation:     resp.Rotation.String(),
		})
	}
	return secrets, nil
}
