#!/usr/bin/env python3
"""
Merge generated layouts into component_offsets.h
"""

import re
from pathlib import Path

def main():
    offsets_file = Path("src/entity/component_offsets.h")
    integrated_file = Path("ghidra/offsets/staging/integrated_new_layouts.c")

    # Read existing file
    content = offsets_file.read_text()
    integrated = integrated_file.read_text()

    # Extract layout definitions (everything before REGISTRY ENTRIES)
    layout_defs = integrated.split("// === REGISTRY ENTRIES")[0].strip()

    # Extract registry entries
    registry_match = re.search(r'/\*\n(.*?)\n\*/', integrated, re.DOTALL)
    if not registry_match:
        print("ERROR: Could not find registry entries")
        return 1
    registry_entries = registry_match.group(1).strip()

    # Find insertion points
    # 1. Insert layout definitions before "static const ComponentLayoutDef* g_AllComponentLayouts[]"
    array_pattern = r'static const ComponentLayoutDef\* g_AllComponentLayouts\[\]'
    array_match = re.search(array_pattern, content)
    if not array_match:
        print("ERROR: Could not find g_AllComponentLayouts array")
        return 1

    insert_pos1 = array_match.start()

    # 2. Insert registry entries before "NULL  // Sentinel"
    sentinel_pattern = r'    NULL  // Sentinel\n\};'
    sentinel_match = re.search(sentinel_pattern, content)
    if not sentinel_match:
        print("ERROR: Could not find sentinel")
        return 1

    insert_pos2 = sentinel_match.start()

    # Build new content
    new_content = (
        content[:insert_pos1] +
        "\n" + layout_defs + "\n\n" +
        content[insert_pos1:insert_pos2] +
        "    // === AUTO-GENERATED LAYOUTS (365 new components) ===\n" +
        registry_entries + "\n" +
        content[insert_pos2:]
    )

    # Write output
    offsets_file.write_text(new_content)

    # Count results
    layout_count = new_content.count("ComponentLayoutDef g_")
    print(f"Merged successfully!")
    print(f"Total layouts: {layout_count}")
    print(f"File size: {len(new_content)} bytes")

    return 0

if __name__ == "__main__":
    exit(main())
