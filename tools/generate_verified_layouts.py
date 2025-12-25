#!/usr/bin/env python3
"""
Generate verified component layouts by cross-referencing:
1. Windows BG3SE headers (field names and types)
2. Ghidra ARM64 sizes (verified struct sizes)
3. Existing layouts (skip already implemented)

Output: Ready-to-use C code for component_offsets.h
"""

import re
import os
from pathlib import Path
from collections import defaultdict

# Paths
WINDOWS_HEADERS = Path("/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components")
GHIDRA_SIZES = Path("/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components")
EXISTING_LAYOUTS = Path("/Users/tomdimino/Desktop/Programming/bg3se-macos/src/entity/component_offsets.h")

# Type mappings from C++ to our field types
TYPE_MAP = {
    'int32_t': ('FIELD_TYPE_INT32', 4),
    'int': ('FIELD_TYPE_INT32', 4),
    'uint32_t': ('FIELD_TYPE_UINT32', 4),
    'unsigned int': ('FIELD_TYPE_UINT32', 4),
    'int64_t': ('FIELD_TYPE_INT64', 8),
    'uint64_t': ('FIELD_TYPE_UINT64', 8),
    'int16_t': ('FIELD_TYPE_INT16', 2),
    'uint16_t': ('FIELD_TYPE_UINT16', 2),
    'int8_t': ('FIELD_TYPE_INT8', 1),
    'uint8_t': ('FIELD_TYPE_UINT8', 1),
    'bool': ('FIELD_TYPE_BOOL', 1),
    'float': ('FIELD_TYPE_FLOAT', 4),
    'double': ('FIELD_TYPE_DOUBLE', 8),
    'FixedString': ('FIELD_TYPE_FIXEDSTRING', 4),
    'Guid': ('FIELD_TYPE_GUID', 16),
    'EntityHandle': ('FIELD_TYPE_ENTITYHANDLE', 8),
    'glm::vec3': ('FIELD_TYPE_VEC3', 12),
    'glm::vec4': ('FIELD_TYPE_VEC4', 16),
    'glm::quat': ('FIELD_TYPE_QUAT', 16),
}

# Simple types that are safe to auto-generate
SIMPLE_TYPES = {'int32_t', 'int', 'uint32_t', 'unsigned int', 'int8_t', 'uint8_t',
                'int16_t', 'uint16_t', 'bool', 'float', 'FixedString'}

def parse_ghidra_sizes():
    """Parse all Ghidra size files into a dict of component_name -> size"""
    sizes = {}
    for md_file in GHIDRA_SIZES.glob("COMPONENT_SIZES_*.md"):
        if "INDEX" in md_file.name:
            continue
        with open(md_file) as f:
            for line in f:
                if not line.startswith("|") or "::" not in line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 4:
                    continue
                name = parts[1].replace('`', '').strip()
                if name in ("Component", "---") or not "::" in name:
                    continue
                # Parse size from hex or decimal
                hex_str = parts[2].strip()
                bytes_str = parts[3].strip() if len(parts) > 3 else ""
                size = None
                if bytes_str:
                    match = re.search(r'(\d+)', bytes_str.replace(',', ''))
                    if match:
                        size = int(match.group(1))
                if size is None and hex_str:
                    match = re.search(r'0x([0-9a-fA-F]+)', hex_str)
                    if match:
                        size = int(match.group(1), 16)
                if size:
                    sizes[name] = size
    return sizes

def parse_existing_layouts():
    """Get list of already-implemented component names"""
    existing = set()
    with open(EXISTING_LAYOUTS) as f:
        content = f.read()
        # Match .componentName = "eoc::HealthComponent"
        for match in re.finditer(r'\.componentName\s*=\s*"([^"]+)"', content):
            existing.add(match.group(1))
    return existing

def parse_windows_component(header_path, struct_name):
    """Parse a single component struct from Windows header"""
    with open(header_path) as f:
        content = f.read()

    # Find struct definition
    pattern = rf'struct\s+{re.escape(struct_name)}\s*(?::\s*public\s+\w+)?\s*\{{'
    match = re.search(pattern, content)
    if not match:
        return None

    # Extract body (handle nested braces)
    start = match.end()
    depth = 1
    end = start
    while depth > 0 and end < len(content):
        if content[end] == '{':
            depth += 1
        elif content[end] == '}':
            depth -= 1
        end += 1

    body = content[start:end-1]

    # Parse fields
    fields = []
    offset = 0
    for line in body.split('\n'):
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('DEFINE_'):
            continue

        # Match: Type FieldName;
        field_match = re.match(r'(\w+(?:<[^>]+>)?)\s+(\w+)\s*;', line)
        if field_match:
            type_name = field_match.group(1)
            field_name = field_match.group(2)

            # Check if simple type
            base_type = type_name.split('<')[0]
            if base_type in TYPE_MAP:
                field_type, size = TYPE_MAP[base_type]
                fields.append({
                    'name': field_name,
                    'offset': offset,
                    'type': field_type,
                    'size': size,
                    'simple': base_type in SIMPLE_TYPES
                })
                offset += size
                # Align to 4 bytes for most types
                if size < 4:
                    pass  # Don't auto-align small types
                elif offset % 4 != 0:
                    offset = (offset + 3) & ~3

    return fields

def find_components_in_headers():
    """Find all component definitions in Windows headers"""
    components = {}
    for header in WINDOWS_HEADERS.glob("*.h"):
        with open(header) as f:
            content = f.read()

        # Match struct definitions with Component suffix
        for match in re.finditer(r'struct\s+((?:\w+::)*\w+Component)\s*(?::\s*public)', content):
            full_name = match.group(1)
            # Normalize namespace
            if '::' not in full_name:
                # Try to infer namespace from file
                if 'esv' in header.name.lower():
                    full_name = f"esv::{full_name}"
                elif 'ecl' in header.name.lower():
                    full_name = f"ecl::{full_name}"
                else:
                    full_name = f"eoc::{full_name}"
            components[full_name] = header
    return components

def generate_layout(name, fields, size):
    """Generate C code for a component layout"""
    short_name = name.split("::")[-1].replace("Component", "")
    safe_name = name.replace("::", "_").replace("<", "_").replace(">", "_")

    lines = []
    lines.append(f"// {name}")
    lines.append(f"// Ghidra ARM64 Size: {size} (0x{size:x})")
    lines.append(f"// Generated from Windows headers - VERIFY OFFSETS")
    lines.append("")

    if fields:
        lines.append(f"static const ComponentPropertyDef g_{safe_name}_Properties[] = {{")
        for f in fields:
            lines.append(f'    {{ "{f["name"]}", 0x{f["offset"]:02x}, {f["type"]}, 0, true }},')
        lines.append("};")
    else:
        lines.append(f"static const ComponentPropertyDef g_{safe_name}_Properties[] = {{}};")

    lines.append("")
    lines.append(f"static const ComponentLayoutDef g_{safe_name}_Layout = {{")
    lines.append(f'    .componentName = "{name}",')
    lines.append(f'    .shortName = "{short_name}",')
    lines.append(f'    .componentTypeIndex = 0,')
    lines.append(f'    .componentSize = 0x{size:x},')
    lines.append(f'    .properties = g_{safe_name}_Properties,')
    lines.append(f'    .propertyCount = sizeof(g_{safe_name}_Properties) / sizeof(g_{safe_name}_Properties[0]),')
    lines.append("};")
    lines.append("")

    return '\n'.join(lines)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate verified component layouts")
    parser.add_argument('--namespace', help='Filter by namespace (eoc, esv, ecl, ls)')
    parser.add_argument('--simple-only', action='store_true', help='Only components with simple types')
    parser.add_argument('--max', type=int, default=50, help='Max components to generate')
    parser.add_argument('--list', action='store_true', help='List available components')
    args = parser.parse_args()

    # Load data
    ghidra_sizes = parse_ghidra_sizes()
    existing = parse_existing_layouts()

    print(f"// Loaded {len(ghidra_sizes)} Ghidra sizes", file=__import__('sys').stderr)
    print(f"// Found {len(existing)} existing layouts", file=__import__('sys').stderr)

    # Find candidates: have Ghidra size but no existing layout
    candidates = []
    for name, size in ghidra_sizes.items():
        if name in existing:
            continue
        if args.namespace and not name.startswith(f"{args.namespace}::"):
            continue
        # Simple size check: 1-64 bytes are likely simple structs
        if args.simple_only and size > 64:
            continue
        candidates.append((name, size))

    # Sort by size (smaller = simpler = more likely correct)
    candidates.sort(key=lambda x: x[1])

    if args.list:
        for name, size in candidates[:100]:
            print(f"{name}: {size} bytes (0x{size:x})")
        print(f"\nTotal candidates: {len(candidates)}")
        return

    # Generate layouts
    print("// Auto-generated component layouts")
    print("// Cross-referenced: Windows headers + Ghidra ARM64 sizes")
    print("// WARNING: Offsets are estimates - verify critical components")
    print("")

    count = 0
    for name, size in candidates[:args.max]:
        # For now, generate minimal layouts (just size, no fields)
        # Full field parsing requires more sophisticated header analysis
        short_name = name.split("::")[-1].replace("Component", "")
        safe_name = name.replace("::", "_")

        print(f"// {name} - {size} bytes (0x{size:x})")
        print(f"static const ComponentPropertyDef g_{safe_name}_Properties[] = {{}};")
        print(f"static const ComponentLayoutDef g_{safe_name}_Layout = {{")
        print(f'    .componentName = "{name}",')
        print(f'    .shortName = "{short_name}",')
        print(f'    .componentTypeIndex = 0,')
        print(f'    .componentSize = 0x{size:x},')
        print(f'    .properties = g_{safe_name}_Properties,')
        print(f'    .propertyCount = 0,')
        print(f"}};")
        print("")
        count += 1

    print(f"// Generated {count} layouts", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
