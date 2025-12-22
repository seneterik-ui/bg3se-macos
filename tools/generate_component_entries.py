#!/usr/bin/env python3
"""
Generate component_offsets.h entries from Ghidra-extracted component sizes.

Usage:
    python3 tools/generate_component_entries.py [--json path/to/component_sizes.json]

This script:
1. Reads component sizes extracted by Ghidra batch script
2. Cross-references with existing TypeIds (component_typeid.c)
3. Generates skeleton entries for component_offsets.h
"""

import json
import re
import sys
import os
from pathlib import Path

# Default paths
DEFAULT_JSON = Path(__file__).parent.parent / "ghidra/offsets/component_sizes.json"
TYPEID_FILE = Path(__file__).parent.parent / "src/entity/component_typeid.c"
OFFSETS_FILE = Path(__file__).parent.parent / "src/entity/component_offsets.h"

def load_component_sizes(json_path):
    """Load component sizes from Ghidra extraction output."""
    with open(json_path) as f:
        data = json.load(f)
    return data.get("components", {})

def load_existing_typeids():
    """Parse existing TypeId entries from component_typeid.c."""
    typeids = set()
    if not TYPEID_FILE.exists():
        return typeids

    with open(TYPEID_FILE) as f:
        content = f.read()

    # Match patterns like: {"eoc::HealthComponent", 0x10...}
    for match in re.finditer(r'\{"([^"]+)"', content):
        typeids.add(match.group(1))

    return typeids

def load_existing_offsets():
    """Parse components already defined in component_offsets.h."""
    defined = set()
    if not OFFSETS_FILE.exists():
        return defined

    with open(OFFSETS_FILE) as f:
        content = f.read()

    # Match patterns like: g_HealthComponent_Properties
    for match in re.finditer(r'g_(\w+)Component_Properties', content):
        # Convert back to full name (approximate)
        name = match.group(1)
        defined.add(name)

    return defined

def sanitize_name(component_name):
    """Convert eoc::HealthComponent to HealthComponent for C identifier."""
    # Remove namespace prefix
    if "::" in component_name:
        name = component_name.split("::")[-1]
    else:
        name = component_name
    # Remove any template parameters
    name = re.sub(r'<.*>', '', name)
    return name

def generate_skeleton_entry(component_name, size, size_hex):
    """Generate a skeleton component_offsets.h entry."""
    safe_name = sanitize_name(component_name)

    return f'''
// ============================================================================
// {safe_name} ({component_name})
// ARM64 Verified: Size {size_hex} (via Ghidra AddComponent<{component_name}>)
// TODO: Add property definitions from Windows BG3SE headers
// ============================================================================

static const ComponentPropertyDef g_{safe_name}_Properties[] = {{
    // TODO: Add properties here
    // Example: {{ "PropertyName", 0x00, FIELD_TYPE_INT32, 0, true }},
    {{ NULL, 0, 0, 0, false }}  // Sentinel
}};

// Registry entry (add to g_AllComponentLayouts):
// {{ "{component_name}", g_{safe_name}_Properties, ARRAY_SIZE(g_{safe_name}_Properties) - 1, {size_hex} }},
'''

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate component_offsets.h entries")
    parser.add_argument("--json", default=str(DEFAULT_JSON), help="Path to component_sizes.json")
    parser.add_argument("--namespace", help="Filter by namespace (e.g., eoc, esv)")
    parser.add_argument("--min-size", type=int, default=0, help="Minimum size filter")
    parser.add_argument("--max-size", type=int, default=9999, help="Maximum size filter")
    parser.add_argument("--new-only", action="store_true", help="Only show components not in offsets.h")
    args = parser.parse_args()

    # Load data
    if not os.path.exists(args.json):
        print(f"Error: {args.json} not found", file=sys.stderr)
        print("Run Ghidra batch_extract_component_sizes.py first", file=sys.stderr)
        sys.exit(1)

    components = load_component_sizes(args.json)
    existing_typeids = load_existing_typeids()
    existing_offsets = load_existing_offsets()

    print(f"Loaded {len(components)} components from Ghidra extraction")
    print(f"Found {len(existing_typeids)} TypeIds in component_typeid.c")
    print(f"Found {len(existing_offsets)} components in component_offsets.h")
    print()

    # Filter and sort
    filtered = []
    for name, data in components.items():
        size = data["size"]

        # Apply filters
        if args.namespace:
            if not name.startswith(args.namespace + "::"):
                continue
        if size < args.min_size or size > args.max_size:
            continue
        if args.new_only:
            safe_name = sanitize_name(name)
            if safe_name in existing_offsets:
                continue

        filtered.append((name, data))

    # Sort by namespace then name
    filtered.sort(key=lambda x: x[0])

    print(f"Generating entries for {len(filtered)} components")
    print("=" * 70)

    for name, data in filtered:
        entry = generate_skeleton_entry(name, data["size"], data["size_hex"])
        print(entry)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Count by namespace
    ns_counts = {}
    for name, _ in filtered:
        ns = name.split("::")[0] if "::" in name else "other"
        ns_counts[ns] = ns_counts.get(ns, 0) + 1

    for ns, count in sorted(ns_counts.items(), key=lambda x: -x[1]):
        print(f"  {ns}:: {count} components")

    print(f"\nTotal: {len(filtered)} skeleton entries generated")
    print("\nTo use: Copy the relevant entries to src/entity/component_offsets.h")
    print("and add property definitions from Windows BG3SE headers.")

if __name__ == "__main__":
    main()
