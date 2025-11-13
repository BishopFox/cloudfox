#!/bin/bash

# Script to migrate Azure modules from HandleOutput to HandleOutputSmart
# This script updates Pattern 1 modules (standard subscription-based modules)

set -e

# List of Pattern 1 modules to update (excluding vms, arc, principals which are already done)
MODULES=(
    "acr"
    "accesskeys"
    "aks"
    "app-configuration"
    "appgw"
    "automation"
    "batch"
    "container-apps"
    "databases"
    "databricks"
    "deployments"
    "devops-artifacts"
    "devops-pipelines"
    "devops-projects"
    "devops-repos"
    "disks"
    "endpoints"
    "filesystems"
    "functions"
    "iothub"
    "keyvaults"
    "load-testing"
    "logicapps"
    "machine-learning"
    "network-interfaces"
    "policy"
    "privatelink"
    "redis"
    "storage"
    "synapse"
    "webapps"
    "whoami"
)

# Special modules (tenant-level - Pattern 3)
TENANT_MODULES=(
    "rbac"
)

echo "Migrating ${#MODULES[@]} Pattern 1 modules to HandleOutputSmart..."

for module in "${MODULES[@]}"; do
    FILE="./azure/commands/${module}.go"

    if [ ! -f "$FILE" ]; then
        echo "SKIP: $FILE does not exist"
        continue
    fi

    echo "Processing $module.go..."

    # Create backup
    cp "$FILE" "$FILE.bak"

    # Step 1: Add context.Context parameter to writeOutput function signature
    sed -i 's/func (m \*\([^)]*\)) writeOutput(logger internal\.Logger)/func (m *\1) writeOutput(ctx context.Context, logger internal.Logger)/g' "$FILE"

    # Step 2: Update writeOutput call sites to pass ctx
    sed -i 's/m\.writeOutput(logger)/m.writeOutput(ctx, logger)/g' "$FILE"

    # Step 3: Replace HandleOutput with HandleOutputSmart and add scope determination logic
    # This is complex, so we'll use a Python script for this part
    python3 - <<'PYTHON_SCRIPT'
import sys
import re

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    content = f.read()

# Pattern to find HandleOutput call
old_pattern = r'''(\t// Write output.*?\n\tif err := internal\.HandleOutput\(\n\t\t"Azure",\n\t\tm\.Format,\n\t\tm\.OutputDirectory,\n\t\tm\.Verbosity,\n\t\tm\.WrapTable,\n\t\t)m\.Subscriptions\[0\](,\n\t\tm\.UserUPN,\n\t\tm\.TenantName,\n\t\toutput,\n\t\); err != nil \{)'''

new_code = r'''\1// Determine output scope (single subscription vs tenant-wide consolidation)
\tscopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName)
\tscopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

\t// Write output using HandleOutputSmart (automatic streaming for large datasets)
\tif err := internal.HandleOutputSmart(
\t\t"Azure",
\t\tm.Format,
\t\tm.OutputDirectory,
\t\tm.Verbosity,
\t\tm.WrapTable,
\t\tscopeType,
\t\tscopeIDs,
\t\tscopeNames,
\t\tm.UserUPN,
\t\toutput,
\t); err != nil {'''

# Perform replacement
content = re.sub(old_pattern, new_code, content)

with open(file_path, 'w') as f:
    f.write(content)
PYTHON_SCRIPT "$FILE"

    echo "✓ Migrated $module.go"
done

echo ""
echo "Migrating ${#TENANT_MODULES[@]} tenant-level modules..."

for module in "${TENANT_MODULES[@]}"; do
    FILE="./azure/commands/${module}.go"

    if [ ! -f "$FILE" ]; then
        echo "SKIP: $FILE does not exist"
        continue
    fi

    echo "Processing $module.go (tenant-level)..."

    # Create backup
    cp "$FILE" "$FILE.bak"

    # Add context parameter
    sed -i 's/func (m \*\([^)]*\)) writeOutput(logger internal\.Logger)/func (m *\1) writeOutput(ctx context.Context, logger internal.Logger)/g' "$FILE"
    sed -i 's/m\.writeOutput(logger)/m.writeOutput(ctx, logger)/g' "$FILE"

    # For tenant modules, use tenant scope explicitly
    sed -i 's/"_Tenant Level",/scopeType,\n\t\tscopeIDs,\n\t\tscopeNames,/g' "$FILE"
    sed -i 's/internal\.HandleOutput(/internal.HandleOutputSmart(/g' "$FILE"

    # Add scope determination before HandleOutputSmart call
    sed -i '/Write output using/i\\t// Tenant-level module - always use tenant scope\n\tscopeType := "tenant"\n\tscopeIDs := []string{m.TenantID}\n\tscopeNames := []string{m.TenantName}\n' "$FILE"

    echo "✓ Migrated $module.go (tenant-level)"
done

echo ""
echo "Migration complete! Please review changes and run: go build ./..."
