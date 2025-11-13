#!/bin/bash

# Script to find subscription column index for each module
# This helps us update all modules systematically

echo "Module,SubscriptionColumn" > /tmp/module_subscription_columns.csv

for module in *.go; do
    if [ "$module" != "rbac.go" ]; then
        # Find header definition and subscription column
        subscription_col=$(grep -A 30 'Header.*\[\]string{' "$module" | \
            grep -n -E '(Subscription Name|Subscription ID|Subscription\")' | \
            head -1 | \
            cut -d: -f1)

        if [ -n "$subscription_col" ]; then
            # Adjust for 0-based index (grep line numbers are 1-based, and we need to subtract 1 for the Header line)
            col_index=$((subscription_col - 2))
            echo "$module,$col_index"
        else
            echo "$module,NOT_FOUND"
        fi
    fi
done
