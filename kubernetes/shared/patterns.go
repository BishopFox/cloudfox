package shared

import (
	"regexp"
	"strings"
)

// --- Suspicious Pattern Detection Functions ---
// These functions detect malicious patterns in container commands, args, and images.
// Used by cronjobs, daemonsets, deployments, jobs, pods, replicasets, statefulsets.

// DetectReverseShells detects reverse shell patterns in commands and args
func DetectReverseShells(commands []string, args []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/tcp/`), "Bash TCP reverse shell"},
		{regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/udp/`), "Bash UDP reverse shell"},
		{regexp.MustCompile(`nc\s+-e\s+/bin/(bash|sh)`), "Netcat reverse shell"},
		{regexp.MustCompile(`nc\s+.*\s+-e\s+/bin/(bash|sh)`), "Netcat reverse shell with options"},
		{regexp.MustCompile(`mkfifo\s+/tmp/[a-z];.*nc\s+`), "Named pipe reverse shell"},
		{regexp.MustCompile(`python.*socket.*subprocess`), "Python reverse shell"},
		{regexp.MustCompile(`perl.*socket.*open\(STDIN`), "Perl reverse shell"},
		{regexp.MustCompile(`ruby.*socket.*exec`), "Ruby reverse shell"},
		{regexp.MustCompile(`php.*fsockopen.*exec`), "PHP reverse shell"},
		{regexp.MustCompile(`socat.*exec:.*pty`), "Socat reverse shell"},
		{regexp.MustCompile(`ncat.*--sh-exec`), "Ncat reverse shell"},
		{regexp.MustCompile(`telnet.*\|.*bin/(bash|sh)`), "Telnet reverse shell"},
	}

	allText := strings.Join(append(commands, args...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}
	return findings
}

// DetectCryptoMiners detects crypto mining patterns in commands, args, and images
func DetectCryptoMiners(commands []string, args []string, images []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`(?i)xmrig`), "XMRig crypto miner"},
		{regexp.MustCompile(`(?i)minerd`), "CPU miner (minerd)"},
		{regexp.MustCompile(`(?i)cpuminer`), "CPU miner"},
		{regexp.MustCompile(`(?i)stratum\+tcp://`), "Stratum mining pool connection"},
		{regexp.MustCompile(`(?i)--donate-level`), "Miner donation level flag"},
		{regexp.MustCompile(`(?i)--coin=monero`), "Monero mining"},
		{regexp.MustCompile(`(?i)--coin=ethereum`), "Ethereum mining"},
		{regexp.MustCompile(`(?i)--algo=cryptonight`), "CryptoNight algorithm mining"},
		{regexp.MustCompile(`(?i)ethminer`), "Ethereum miner"},
		{regexp.MustCompile(`(?i)claymore`), "Claymore miner"},
		{regexp.MustCompile(`(?i)phoenixminer`), "PhoenixMiner"},
		{regexp.MustCompile(`(?i)t-rex`), "T-Rex miner"},
		{regexp.MustCompile(`(?i)--pool=`), "Mining pool configuration"},
		{regexp.MustCompile(`(?i)--wallet=`), "Crypto wallet address"},
		{regexp.MustCompile(`(?i)--user=.*\.(worker|miner)`), "Mining worker configuration"},
	}

	allText := strings.Join(append(append(commands, args...), images...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}
	return findings
}

// DetectDataExfiltration detects data exfiltration patterns in commands and args
func DetectDataExfiltration(commands []string, args []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`curl.*http.*\|.*bash`), "Curl pipe to bash (backdoor download)"},
		{regexp.MustCompile(`wget.*http.*\|.*bash`), "Wget pipe to bash (backdoor download)"},
		{regexp.MustCompile(`curl.*-X\s+POST.*--data`), "HTTP POST with data (exfiltration)"},
		{regexp.MustCompile(`base64.*\|.*curl`), "Base64 encode and curl (data exfiltration)"},
		{regexp.MustCompile(`tar.*\|.*curl.*-T`), "Tar and upload via curl"},
		{regexp.MustCompile(`aws\s+s3\s+cp.*s3://`), "AWS S3 copy to external bucket"},
		{regexp.MustCompile(`gsutil\s+cp.*gs://`), "GCP Cloud Storage upload"},
		{regexp.MustCompile(`kubectl\s+cp.*:.*\.`), "kubectl cp from pod (data extraction)"},
		{regexp.MustCompile(`scp.*@.*:`), "SCP file transfer"},
		{regexp.MustCompile(`rsync.*@.*:`), "Rsync file transfer"},
		{regexp.MustCompile(`nc.*>.*\.(zip|tar|gz|tgz)`), "Netcat file transfer"},
		{regexp.MustCompile(`find\s+/.*-name.*\|.*curl`), "Find files and exfiltrate"},
		{regexp.MustCompile(`cat\s+/etc/shadow.*\|`), "Shadow file access and pipe"},
		{regexp.MustCompile(`cat\s+/etc/passwd.*\|`), "Passwd file access and pipe"},
		{regexp.MustCompile(`env.*\|.*curl`), "Environment variable exfiltration"},
	}

	allText := strings.Join(append(commands, args...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			// Special handling for AWS S3: exclude "internal" buckets
			if strings.Contains(p.desc, "AWS S3") && strings.Contains(allText, "s3://internal") {
				continue
			}
			findings = append(findings, p.desc)
		}
	}
	return findings
}

// DetectContainerEscape detects container escape patterns in commands, args, and hostPaths
func DetectContainerEscape(commands []string, args []string, hostPaths []string) []string {
	var findings []string
	patterns := []struct {
		regex *regexp.Regexp
		desc  string
	}{
		{regexp.MustCompile(`nsenter\s+--target\s+1`), "nsenter escape to host PID namespace"},
		{regexp.MustCompile(`nsenter.*--mount.*--uts.*--ipc.*--net.*--pid`), "nsenter full namespace escape"},
		{regexp.MustCompile(`docker\.sock`), "Docker socket access (container escape)"},
		{regexp.MustCompile(`containerd\.sock`), "Containerd socket access (container escape)"},
		{regexp.MustCompile(`crio\.sock`), "CRI-O socket access (container escape)"},
		{regexp.MustCompile(`runc`), "runc binary (potential container escape)"},
		{regexp.MustCompile(`ctr\s+`), "containerd CLI (container runtime access)"},
		{regexp.MustCompile(`crictl`), "CRI CLI (container runtime access)"},
		{regexp.MustCompile(`mount.*proc.*sys`), "Proc/sys mount (escape technique)"},
		{regexp.MustCompile(`unshare`), "unshare namespace manipulation"},
	}

	allText := strings.Join(append(commands, args...), " ")
	for _, p := range patterns {
		if p.regex.MatchString(allText) {
			findings = append(findings, p.desc)
		}
	}

	// Check hostPath mounts for critical escape vectors
	for _, hp := range hostPaths {
		if strings.Contains(hp, "docker.sock") {
			findings = append(findings, "HostPath: docker.sock mounted (CRITICAL escape)")
		}
		if strings.Contains(hp, "containerd.sock") {
			findings = append(findings, "HostPath: containerd.sock mounted (CRITICAL escape)")
		}
		if strings.Contains(hp, "/var/run") {
			findings = append(findings, "HostPath: /var/run mounted (socket access)")
		}
		if hp == "/" || hp == "/host" || strings.HasPrefix(hp, "/:") {
			findings = append(findings, "HostPath: root filesystem mounted (CRITICAL escape)")
		}
	}

	return findings
}

// DetectAllSuspiciousPatterns runs all pattern detection and returns combined results
func DetectAllSuspiciousPatterns(commands []string, args []string, images []string, hostPaths []string) []string {
	var allPatterns []string
	allPatterns = append(allPatterns, DetectReverseShells(commands, args)...)
	allPatterns = append(allPatterns, DetectCryptoMiners(commands, args, images)...)
	allPatterns = append(allPatterns, DetectDataExfiltration(commands, args)...)
	allPatterns = append(allPatterns, DetectContainerEscape(commands, args, hostPaths)...)
	return allPatterns
}
