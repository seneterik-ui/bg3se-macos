#!/usr/bin/env python3
"""
Integrate generated component layouts into component_offsets.h
Filters out duplicates and produces merged output.
"""

import re
import sys
from pathlib import Path

def extract_layouts(content):
    """Extract individual layout blocks from generated C file."""
    layouts = {}
    # Match complete layout blocks: comment + PropertyDef + LayoutDef
    pattern = r'(// (\S+) - .*?ComponentLayoutDef g_\w+_Layout = \{[^}]+\};)'

    for match in re.finditer(pattern, content, re.DOTALL):
        full_block = match.group(1)
        component_name = match.group(2)
        layouts[component_name] = full_block

    return layouts

def load_existing_components(filepath):
    """Load list of existing component names."""
    content = Path(filepath).read_text()
    names = set()
    for match in re.finditer(r'\.componentName = "([^"]+)"', content):
        names.add(match.group(1))
    return names

def main():
    staging_dir = Path("ghidra/offsets/staging")
    existing_file = Path("src/entity/component_offsets.h")

    # Load existing component names
    existing = load_existing_components(existing_file)
    print(f"Existing components: {len(existing)}")

    # Collect all generated layouts
    all_layouts = {}
    for gen_file in staging_dir.glob("generated_*.c"):
        content = gen_file.read_text()
        layouts = extract_layouts(content)
        print(f"{gen_file.name}: {len(layouts)} layouts")
        all_layouts.update(layouts)

    print(f"Total generated: {len(all_layouts)}")

    # Filter to new only
    new_layouts = {k: v for k, v in all_layouts.items() if k not in existing}
    print(f"New layouts to add: {len(new_layouts)}")

    # Generate output file
    output_path = Path("ghidra/offsets/staging/integrated_new_layouts.c")

    with open(output_path, 'w') as f:
        f.write("// ============================================================================\n")
        f.write("// AUTO-GENERATED COMPONENT LAYOUTS\n")
        f.write(f"// New layouts: {len(new_layouts)}\n")
        f.write("// ============================================================================\n\n")

        # Group by namespace
        namespaces = {'ecl': [], 'eoc': [], 'esv': [], 'ls': []}
        for name, block in sorted(new_layouts.items()):
            ns = name.split('::')[0]
            if ns in namespaces:
                namespaces[ns].append((name, block))
            else:
                namespaces.setdefault('other', []).append((name, block))

        registry_entries = []

        for ns in ['eoc', 'esv', 'ecl', 'ls', 'other']:
            if ns not in namespaces or not namespaces[ns]:
                continue
            f.write(f"\n// === {ns}:: namespace ({len(namespaces[ns])} layouts) ===\n\n")

            for name, block in namespaces[ns]:
                f.write(block)
                f.write("\n\n")

                # Extract layout variable name for registry
                layout_match = re.search(r'(g_\w+_Layout)\s*=', block)
                if layout_match:
                    registry_entries.append(layout_match.group(1))

        # Write registry entries
        f.write("\n// === REGISTRY ENTRIES (add to g_AllComponentLayouts) ===\n")
        f.write("/*\n")
        for entry in registry_entries:
            f.write(f"    &{entry},\n")
        f.write("*/\n")

    print(f"\nOutput written to: {output_path}")
    print(f"Registry entries: {len(registry_entries)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
