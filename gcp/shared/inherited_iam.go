package shared

// InheritedAccessRoles maps resource types to the project-level roles that
// grant implicit access to ALL resources of that type. Principals with these
// roles at the project level can access every resource even without a direct
// resource-level IAM binding.
var InheritedAccessRoles = map[string][]string{
	"bucket": {
		"roles/owner", "roles/editor",
		"roles/storage.admin", "roles/storage.objectAdmin",
		"roles/storage.objectViewer", "roles/storage.objectCreator",
	},
	"dataset": {
		"roles/owner", "roles/editor",
		"roles/bigquery.admin", "roles/bigquery.dataEditor",
		"roles/bigquery.dataViewer", "roles/bigquery.dataOwner",
	},
	"table": {
		"roles/owner", "roles/editor",
		"roles/bigquery.admin", "roles/bigquery.dataEditor",
		"roles/bigquery.dataViewer", "roles/bigquery.dataOwner",
	},
	"topic": {
		"roles/owner", "roles/editor",
		"roles/pubsub.admin", "roles/pubsub.editor", "roles/pubsub.publisher",
	},
	"subscription": {
		"roles/owner", "roles/editor",
		"roles/pubsub.admin", "roles/pubsub.editor", "roles/pubsub.subscriber",
	},
	"secret": {
		"roles/owner", "roles/editor",
		"roles/secretmanager.admin", "roles/secretmanager.secretAccessor",
		"roles/secretmanager.secretVersionAdder",
	},
	"cryptoKey": {
		"roles/owner",
		"roles/cloudkms.admin", "roles/cloudkms.cryptoKeyEncrypterDecrypter",
		"roles/cloudkms.cryptoKeyDecrypter",
	},
	"function": {
		"roles/owner", "roles/editor",
		"roles/cloudfunctions.admin", "roles/cloudfunctions.developer",
		"roles/cloudfunctions.invoker",
	},
	"cloudrun": {
		"roles/owner", "roles/editor",
		"roles/run.admin", "roles/run.developer", "roles/run.invoker",
	},
	"instance": {
		"roles/owner", "roles/editor",
		"roles/compute.admin", "roles/compute.instanceAdmin",
		"roles/compute.instanceAdmin.v1",
	},
}

// IsInheritedRole checks whether the given role grants inherited access
// for the specified resource type.
func IsInheritedRole(resourceType, role string) bool {
	roles, ok := InheritedAccessRoles[resourceType]
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// BindingSource returns a display-ready binding source string.
// If the source is empty, defaults to "Resource" (direct binding).
func BindingSource(source string) string {
	if source == "" {
		return "Resource"
	}
	return source
}
