#!/bin/bash
# Script to automatically fix godot linting issues (comments not ending in periods)

# Find all Go files and fix comments that don't end in periods
find project-* -name "*.go" -type f | while read -r file; do
    # Use sed to add periods to comments that don't end with them
    # This handles both // and /* */ style comments
    sed -i '' -E 's|^([[:space:]]*//)([^/].*[^.!?:)])$|\1\2.|g' "$file"
    sed -i '' -E 's|^([[:space:]]*//[[:space:]]*)([A-Z].*[^.!?:)])$|\1\2.|g' "$file"
done

echo "Fixed godot issues in all Go files"

