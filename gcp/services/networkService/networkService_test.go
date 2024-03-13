package networkservice_test

import (
	"testing"

	networkservice "github.com/BishopFox/cloudfox/gcp/services/networkService"
)

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		// IPv4 tests
		{"10.1.2.3", true},     // falls within 10.0.0.0/8
		{"172.17.0.1", true},   // falls within 172.16.0.0/12
		{"192.168.10.1", true}, // falls within 192.168.0.0/16
		{"11.1.2.3", false},    // public IP
		{"172.32.0.1", false},  // public IP
		{"192.169.0.1", false}, // public IP
		{"8.8.8.8", false},     // public IP
		// IPv6 tests
		{"fc00::1", true},               // falls within fc00::/7
		{"fd00::1", true},               // falls within fd00::/8
		{"fe80::1", false},              // link-local address, not ULA
		{"2001:0db8:85a3::8a2e", false}, // public IP
	}

	for _, test := range tests {
		result := networkservice.IsInternalIP(test.input)
		if result != test.expect {
			t.Errorf("IsInternalIP(%s) = %v; want %v", test.input, result, test.expect)
		}
	}
}
