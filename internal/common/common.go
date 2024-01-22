package common

import "github.com/dominikbraun/graph"

type PermissionsRow struct {
	AWSService string
	Type       string
	Name       string
	Arn        string
	PolicyType string
	PolicyName string
	PolicyArn  string
	Effect     string
	Action     string
	Resource   string
	Condition  string
}

var PermissionRowsFromAllProfiles []PermissionsRow

var GlobalGraph graph.Graph[string, string]
