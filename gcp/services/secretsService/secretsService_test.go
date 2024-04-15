package secretservice_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	secretservice "github.com/BishopFox/cloudfox/gcp/services/secretsService"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockSecretManagerClient struct {
	secrets []*secretmanagerpb.Secret
}

func (m *mockSecretManagerClient) Close() error {
	return nil
}

// SecretIterator simulates the iterator over secrets.
type SecretIterator struct {
	secrets          []*secretmanagerpb.Secret // Current secrets batch
	nextIndex        int                       // Index of the next secret to return
	InternalFetch    func(pageSize int, pageToken string) (results []*secretmanagerpb.Secret, nextPageToken string, err error)
	currentPageToken string
}

func (it *SecretIterator) Next() (*secretmanagerpb.Secret, error) {
	// If we have reached the end of the current secrets batch, attempt to fetch the next batch
	if it.nextIndex >= len(it.secrets) {
		var err error
		it.secrets, it.currentPageToken, err = it.InternalFetch(10, it.currentPageToken) // Assuming a fixed page size for simplicity
		if err != nil {
			return nil, err // Propagate errors from fetch
		}
		it.nextIndex = 0 // Reset the index for the new batch

		// If the fetched batch is empty, we have reached the end of the iteration
		if len(it.secrets) == 0 {
			return nil, iterator.Done
		}
	}

	// Retrieve the next secret and increment the index
	secret := it.secrets[it.nextIndex]
	it.nextIndex++
	return secret, nil
}

// ListSecrets simulates the ListSecrets method of the SecretManagerClient interface.
func (m *mockSecretManagerClient) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) secretservice.Iterator {
	it := &SecretIterator{}

	// Copy secrets to avoid modifying the original slice
	allSecrets := make([]*secretmanagerpb.Secret, len(m.secrets))
	copy(allSecrets, m.secrets)

	// Simulate internal fetch by setting InternalFetch to a function that returns the next set of secrets
	nextIndex := 0
	it.InternalFetch = func(pageSize int, pageToken string) (results []*secretmanagerpb.Secret, nextPageToken string, err error) {
		// Check if we have reached the end of the secrets slice
		if nextIndex >= len(allSecrets) {
			return nil, "", iterator.Done
		}

		// Determine the slice of secrets to return
		endIndex := nextIndex + pageSize
		if endIndex > len(allSecrets) {
			endIndex = len(allSecrets)
		}
		results = allSecrets[nextIndex:endIndex]
		nextIndex = endIndex

		// Simulate the nextPageToken logic (omitted for brevity, always return empty string in this mock)
		nextPageToken = ""
		return results, nextPageToken, nil
	}

	return it
}

func TestSecrets(t *testing.T) {
	mockClient := &mockSecretManagerClient{}
	ss := secretservice.SecretsService{
		Client: &secretservice.SecretsManagerClientWrapper{
			Closer: mockClient.Close,
			SecretLister: func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) secretservice.Iterator {
				return mockClient.ListSecrets(ctx, req, opts...)
			},
		},
	}

	tests := []struct {
		name      string
		projectID string
		secrets   []*secretmanagerpb.Secret
		want      []secretservice.SecretInfo
		wantErr   bool
	}{
		{
			name:      "Retrieve secrets successfully",
			projectID: "my-project",
			secrets: []*secretmanagerpb.Secret{
				{
					Name:       "projects/my-project/secrets/secret1",
					Labels:     map[string]string{"env": "test"},
					CreateTime: timestamppb.New(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
				},
			},
			want: []secretservice.SecretInfo{
				{
					Name:         "projects/my-project/secrets/secret1",
					ProjectID:    "my-project",
					CreationTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).String(),
					Labels:       map[string]string{"env": "test"},
				},
			},
			wantErr: false,
		},
		{
			name:      "No secrets found",
			projectID: "empty-project",
			secrets:   []*secretmanagerpb.Secret{},
			want:      []secretservice.SecretInfo{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient.secrets = tt.secrets
			got, err := ss.Secrets(tt.projectID) // Adapt this call to match the actual method signature
			if (err != nil) != tt.wantErr {
				t.Errorf("[%s] Secrets() error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("[%s] Secrets() got length = %v, want length %v", tt.name, len(got), len(tt.want))
				return
			}

			for i, g := range got {
				w := tt.want[i]

				// Compare Name, Labels, and CreationTime as string
				if g.Name != w.Name || !reflect.DeepEqual(g.Labels, w.Labels) || g.CreationTime != w.CreationTime {
					t.Errorf("Secrets() got = %v, want %v", g, w)
				}
			}
		})
	}
}
