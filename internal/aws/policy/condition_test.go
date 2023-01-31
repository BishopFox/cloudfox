package policy

import "testing"

func TestGetAccountIDInARN(t *testing.T) {
	tests := []struct {
		S    string
		want string
	}{
		{S: "abc123", want: ""},
		{S: "arn:aws:iam::123456789012:root", want: "123456789012"},
		{S: "arn:aws:iam::123456789012:role/any-role-name", want: "123456789012"},
		{S: "arn:aws:sts::123456789012:assumed-role/any-role-name/session-name", want: "123456789012"},
		{S: "arn:aws:iam::123456789012:user/any-user-name", want: "123456789012"},
		{S: "arn:aws:sts::123456789012:federated-user/any-user-name", want: "123456789012"},
		{S: "arn:aws:cloudwatch:us-east-2:123456789012:alarm:*", want: "123456789012"},
	}

	for _, tt := range tests {

		actual := getAccountIDInARN(tt.S)
		if tt.want != actual {
			t.Errorf("getAccountIDInARN(%s) wrong: want %s but got %s", tt.S, tt.want, actual)
		}
	}
}
