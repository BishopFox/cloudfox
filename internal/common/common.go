package common

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
