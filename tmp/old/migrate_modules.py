#!/usr/bin/env python3
"""
Migrate Azure modules from HandleOutput to HandleOutputSmart
This script updates Pattern 1 modules (standard subscription-based modules)
"""

import re
import sys
from pathlib import Path

# Modules to update (excluding already migrated: vms, arc, principals)
PATTERN_1_MODULES = [
    "accesskeys", "acr", "aks", "app-configuration", "appgw",
    "automation", "batch", "container-apps", "databases", "databricks",
    "deployments", "devops-artifacts", "devops-pipelines", "devops-projects", "devops-repos",
    "disks", "endpoints", "filesystems", "functions", "iothub",
    "keyvaults", "load-testing", "logicapps", "machine-learning", "network-interfaces",
    "policy", "privatelink", "redis", "storage", "synapse",
    "webapps", "whoami"
]

# Pattern 3: Tenant-level modules (use tenant scope explicitly)
PATTERN_3_MODULES = [
    "rbac"
]

def update_pattern_1_module(file_path):
    """Update a Pattern 1 module (standard subscription-based)"""
    with open(file_path, 'r') as f:
        content = f.read()

    original_content = content

    # Step 1: Update writeOutput function signature to accept context.Context
    # Match various module struct names (e.g., StorageModule, AksModule, etc.)
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

    # Step 3: Replace HandleOutput with HandleOutputSmart
    # Pattern to match the HandleOutput call block
    old_pattern = re.compile(
        r'(\t// Write output[^\n]*\n)'
        r'(\tif err := internal\.HandleOutput\(\n)'
        r'(\t\t"Azure",\n)'
        r'(\t\tm\.Format,\n)'
        r'(\t\tm\.OutputDirectory,\n)'
        r'(\t\tm\.Verbosity,\n)'
        r'(\t\tm\.WrapTable,\n)'
        r'(\t\t)m\.Subscriptions\[0\](,\n)'
        r'(\t\tm\.UserUPN,\n)'
        r'(\t\tm\.TenantName,\n)'
        r'(\t\toutput,\n)'
        r'(\t\); err != nil \{)',
        re.MULTILINE
    )

    new_code = (
        r'\1'
        r'\t// Determine output scope (single subscription vs tenant-wide consolidation)\n'
        r'\tscopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName)\n'
        r'\tscopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)\n'
        r'\n'
        r'\2'
        r'\3\4\5\6\7'
        r'\t\tscopeType,\n'
        r'\t\tscopeIDs,\n'
        r'\t\tscopeNames,\n'
        r'\9\10\11'
    )

    # Replace HandleOutput with HandleOutputSmart
    new_code = new_code.replace('internal.HandleOutput', 'internal.HandleOutputSmart')
    new_code = new_code.replace('// Write output', '// Write output using HandleOutputSmart (automatic streaming for large datasets)')

    content = old_pattern.sub(new_code, content)

    if content == original_content:
        return False, "No changes made - pattern not found"

    with open(file_path, 'w') as f:
        f.write(content)

    return True, "Updated successfully"

def update_pattern_3_module(file_path):
    """Update a Pattern 3 module (tenant-level)"""
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

    # Step 3: Replace HandleOutput with HandleOutputSmart for tenant modules
    # Pattern for tenant-level modules (they use "_Tenant Level" as scope)
    old_pattern = re.compile(
        r'(\t// Write output[^\n]*\n)'
        r'(\tif err := internal\.HandleOutput\(\n)'
        r'(\t\t"Azure",\n)'
        r'(\t\tm\.Format,\n)'
        r'(\t\tm\.OutputDirectory,\n)'
        r'(\t\tm\.Verbosity,\n)'
        r'(\t\tm\.WrapTable,\n)'
        r'(\t\t)"_Tenant Level"(,\n)'
        r'(\t\tm\.UserUPN,\n)'
        r'(\t\tm\.TenantName,\n)'
        r'(\t\toutput,\n)'
        r'(\t\); err != nil \{)',
        re.MULTILINE
    )

    new_code = (
        r'\1'
        r'\t// Tenant-level module - always use tenant scope\n'
        r'\tscopeType := "tenant"\n'
        r'\tscopeIDs := []string{m.TenantID}\n'
        r'\tscopeNames := []string{m.TenantName}\n'
        r'\n'
        r'\t// Write output using HandleOutputSmart (automatic streaming for large datasets)\n'
        r'\tif err := internal.HandleOutputSmart(\n'
        r'\3\4\5\6\7'
        r'\t\tscopeType,\n'
        r'\t\tscopeIDs,\n'
        r'\t\tscopeNames,\n'
        r'\9\10\11'
    )

    content = old_pattern.sub(new_code, content)

    if content == original_content:
        return False, "No changes made - pattern not found"

    with open(file_path, 'w') as f:
        f.write(content)

    return True, "Updated successfully"

def main():
    base_path = Path("./azure/commands")

    print("Migrating Azure modules to HandleOutputSmart...")
    print(f"Pattern 1 modules: {len(PATTERN_1_MODULES)}")
    print(f"Pattern 3 modules: {len(PATTERN_3_MODULES)}")
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

    # Update Pattern 3 modules
    for module in PATTERN_3_MODULES:
        file_path = base_path / f"{module}.go"

        if not file_path.exists():
            print(f"⚠️  SKIP: {module}.go - file not found")
            skip_count += 1
            continue

        try:
            updated, message = update_pattern_3_module(file_path)
            if updated:
                print(f"✅ {module}.go (tenant-level) - {message}")
                success_count += 1
            else:
                print(f"⚠️  {module}.go (tenant-level) - {message}")
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
