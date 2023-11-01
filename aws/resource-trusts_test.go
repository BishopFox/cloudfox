package aws

import (
	"testing"
)

func TestIsResourcePolicyInteresting(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "test1",
			input:    "Everyone can sqs:SendMessage & can sqs:ReceiveMessage",
			expected: true,
		},
		{
			name:     "PrincipalOrgPaths",
			input:    "aws:PrincipalOrgPaths",
			expected: true,
		},
		{
			name:     "Empty",
			input:    "",
			expected: false,
		},
		{
			name:     "NotInteresting",
			input:    "sns.amazonaws.com can lambda:InvokeFunction",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := isResourcePolicyInteresting(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected %v but got %v for input %s", tc.expected, actual, tc.input)
			}
		})
	}
}
