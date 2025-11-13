#!/usr/bin/env python3
"""
Migrate Azure modules from HandleOutput to HandleOutputSmart - Version 2
Fixed version with better regex patterns
"""

import re
import sys
from pathlib import Path

# Modules to update (excluding already migrated: vms, arc, principals)
PATTERN_1_MODULES = [
    "vms", "arc", "principals",  # Re-apply these since git checkout reverted them
    "accesskeys", "acr", "aks", "app-configuration", "appgw",
    "automation", "batch", "container-apps", "databases", "databricks",
    "deployments", "devops-artifacts", "devops-pipelines", "devops-projects", "devops-repos",
    "disks", "endpoints", "filesystems", "functions", "iothub",
    "keyvaults", "load-testing", "logicapps", "machine-learning", "network-interfaces",
    "policy", "privatelink", "redis", "storage", "synapse",
    "webapps", "whoami"
]

def update_pattern_1_module(file_path):
    """Update a Pattern 1 module (standard subscription-based)"""
    with open(file_path, 'r') as f:
        content = f.read()

    original_content = content

    # Step 1: Update writeOutput function signature to accept context.Context
    content = re.sub(
        r'func \(m \*(\w+Module)\) writeOutput\(logger internal\.Logger\)',
        r'func (m *\1) writeOutput(ctx context.Context, logger internal.Logger)',
        content
    )

    # Step 2: Update writeOutput call sites to pass ctx
    content = re.sub(
        r'(\s+)m\.writeOutput\(logger\)',
        r'\1m.writeOutput(ctx, logger)',
        content
    )

    # Step 3: Replace the entire HandleOutput block
    # More precise pattern matching
    pattern = (
        r'(\t)// Write output[^\n]*\n'
        r'(\tif err := internal\.HandleOutput\(\n)'
        r'(\t\t"Azure",\n)'
        r'(\t\tm\.Format,\n)'
        r'(\t\tm\.OutputDirectory,\n)'
        r'(\t\tm\.Verbosity,\n)'
        r'(\t\tm\.WrapTable,\n)'
        r'\t\tm\.Subscriptions\[0\],\n'
        r'(\t\tm\.UserUPN,\n)'
        r'\t\tm\.TenantName,\n'
        r'(\t\toutput,\n)'
        r'(\t\); err != nil \{)'
    )

    replacement = (
        r'\1// Determine output scope (single subscription vs tenant-wide consolidation)\n'
        r'\1scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName)\n'
        r'\1scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)\n'
        r'\n'
        r'\1// Write output using HandleOutputSmart (automatic streaming for large datasets)\n'
        r'\2'
        r'\3\4\5\6\7'
        r'\t\tscopeType,\n'
        r'\t\tscopeIDs,\n'
        r'\t\tscopeNames,\n'
        r'\8\9\10'
    )

    # Replace HandleOutput with HandleOutputSmart in the replacement
    replacement = replacement.replace('internal.HandleOutput', 'internal.HandleOutputSmart')

    content = re.sub(pattern, replacement, content)

    if content == original_content:
        return False, "No changes made - pattern not found"

    with open(file_path, 'w') as f:
        f.write(content)

    return True, "Updated successfully"

def update_tenant_module(file_path):
    """Update tenant-level module (principals already done)"""
    with open(file_path, 'r') as f:
        content = f.read()

    original_content = content

    # Step 1: Update writeOutput function signature
    content = re.sub(
        r'func \(m \*(\w+Module)\) writeOutput\(logger internal\.Logger\)',
        r'func (m *\1) writeOutput(ctx context.Context, logger internal.Logger)',
        content
    )

    # Step 2: Update writeOutput call sites
    content = re.sub(
        r'(\s+)m\.writeOutput\(logger\)',
        r'\1m.writeOutput(ctx, logger)',
        content
    )

    # Step 3: Replace HandleOutput for tenant-level modules
    pattern = (
        r'(\t)// Write output[^\n]*\n'
        r'(\tif err := internal\.HandleOutput\(\n)'
        r'(\t\t"Azure",\n)'
        r'(\t\tm\.Format,\n)'
        r'(\t\tm\.OutputDirectory,\n)'
        r'(\t\tm\.Verbosity,\n)'
        r'(\t\tm\.WrapTable,\n)'
        r'\t\t"_Tenant Level",\n'
        r'(\t\tm\.UserUPN,\n)'
        r'\t\tm\.TenantName,\n'
        r'(\t\toutput,\n)'
        r'(\t\); err != nil \{)'
    )

    replacement = (
        r'\1// Tenant-level module - always use tenant scope\n'
        r'\1scopeType := "tenant"\n'
        r'\1scopeIDs := []string{m.TenantID}\n'
        r'\1scopeNames := []string{m.TenantName}\n'
        r'\n'
        r'\1// Write output using HandleOutputSmart (automatic streaming for large datasets)\n'
        r'\tif err := internal.HandleOutputSmart(\n'
        r'\3\4\5\6\7'
        r'\t\tscopeType,\n'
        r'\t\tscopeIDs,\n'
        r'\t\tscopeNames,\n'
        r'\8\9\10'
    )

    content = re.sub(pattern, replacement, content)

    if content == original_content:
        return False, "No changes made - pattern not found"

    with open(file_path, 'w') as f:
        f.write(content)

    return True, "Updated successfully"

def main():
    base_path = Path("./azure/commands")

    print("Migrating Azure modules to HandleOutputSmart (v2)...")
    print(f"Pattern 1 modules: {len(PATTERN_1_MODULES)}")
    print()

    success_count = 0
    skip_count = 0
    error_count = 0

    # Update Pattern 1 modules
    for module in PATTERN_1_MODULES:
        file_path = base_path / f"{module}.go"

        if not file_path.exists():
            print(f"⚠️  SKIP: {module}.go - file not found")
            skip_count += 1
            continue

        # Special handling for principals (tenant-level)
        if module == "principals":
            try:
                updated, message = update_tenant_module(file_path)
                if updated:
                    print(f"✅ {module}.go (tenant-level) - {message}")
                    success_count += 1
                else:
                    print(f"⚠️  {module}.go (tenant-level) - {message}")
                    skip_count += 1
            except Exception as e:
                print(f"❌ {module}.go - Error: {e}")
                error_count += 1
            continue

        try:
            updated, message = update_pattern_1_module(file_path)
            if updated:
                print(f"✅ {module}.go - {message}")
                success_count += 1
            else:
                print(f"⚠️  {module}.go - {message}")
                skip_count += 1
        except Exception as e:
            print(f"❌ {module}.go - Error: {e}")
            error_count += 1

    print()
    print(f"Summary: {success_count} updated, {skip_count} skipped, {error_count} errors")

    if error_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
