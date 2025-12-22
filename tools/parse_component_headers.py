#!/usr/bin/env python3
"""
parse_component_headers.py - Parse Windows BG3SE component headers

Extracts component property definitions from Windows BG3SE GameDefinitions/Components/*.h
and generates C property definitions compatible with our component_offsets.h format.

Usage:
    python3 tools/parse_component_headers.py [--list] [--component NAME]

Examples:
    python3 tools/parse_component_headers.py --list           # List all components
    python3 tools/parse_component_headers.py --component Health  # Show Health properties
    python3 tools/parse_component_headers.py > property_defs.c   # Generate all
"""

import re
import sys
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

# Windows BG3SE source path
WINDOWS_BG3SE_PATH = "/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components"

@dataclass
class Property:
    name: str
    cpp_type: str
    c_type: str
    offset: int  # Estimated offset
    size: int
    is_array: bool = False
    array_count: int = 1

@dataclass
class Component:
    short_name: str      # e.g., "Health"
    full_name: str       # e.g., "eoc::HealthComponent"
    properties: List[Property]
    source_file: str

# Type mapping from C++ to C with sizes
TYPE_MAP = {
    # Primitives
    'int': ('int32_t', 4),
    'int32_t': ('int32_t', 4),
    'uint32_t': ('uint32_t', 4),
    'int16_t': ('int16_t', 2),
    'uint16_t': ('uint16_t', 2),
    'int8_t': ('int8_t', 1),
    'uint8_t': ('uint8_t', 1),
    'bool': ('bool', 1),
    'float': ('float', 4),
    'double': ('double', 8),

    # BG3 types
    'EntityHandle': ('uint64_t', 8),
    'FixedString': ('uint32_t', 4),  # Index into string table
    'Guid': ('uint8_t', 16),  # 16-byte GUID
    'AbilityId': ('uint8_t', 1),
    'ItemSlot': ('uint8_t', 1),
    'DiceSizeId': ('uint8_t', 1),

    # Enums (default to int)
    'EEquipmentType': ('int32_t', 4),
    'ArmorSetState': ('int32_t', 4),
    'ItemUseType': ('uint8_t', 1),
    'WeaponSetType': ('int32_t', 4),
    'CanInteractFlags': ('uint32_t', 4),

    # Complex types - treat as opaque
    'Array': ('void*', 8),  # Dynamic array
    'HashMap': ('void*', 8),
    'HashSet': ('void*', 8),
    'LegacyRefMap': ('void*', 8),
    'TrackedCompactSet': ('void*', 8),
    'STDString': ('void*', 8),
}

def parse_type(cpp_type: str) -> tuple:
    """Parse a C++ type and return (c_type, size, is_array, array_count)."""
    cpp_type = cpp_type.strip()

    # Check for std::array
    array_match = re.match(r'std::array<([^,]+),\s*(\d+)>', cpp_type)
    if array_match:
        inner_type = array_match.group(1).strip()
        count = int(array_match.group(2))
        c_type, size = TYPE_MAP.get(inner_type, ('void*', 8))
        return (c_type, size * count, True, count)

    # Check for Array<T>
    if cpp_type.startswith('Array<'):
        return ('void*', 8, True, 0)  # Dynamic array, size unknown

    # Check for template types
    if '<' in cpp_type:
        base_type = cpp_type.split('<')[0]
        if base_type in TYPE_MAP:
            return (*TYPE_MAP[base_type], False, 1)
        return ('void*', 8, False, 1)

    # Direct lookup
    if cpp_type in TYPE_MAP:
        c_type, size = TYPE_MAP[cpp_type]
        return (c_type, size, False, 1)

    # Unknown type
    return ('void*', 8, False, 1)

def parse_component_struct(content: str, filename: str) -> List[Component]:
    """Parse component struct definitions from file content."""
    components = []

    # Match struct definitions with DEFINE_COMPONENT
    struct_pattern = re.compile(
        r'struct\s+(\w+)\s*:\s*public\s+BaseComponent\s*\{[^}]*'
        r'DEFINE_COMPONENT\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)',
        re.DOTALL
    )

    for match in struct_pattern.finditer(content):
        struct_name = match.group(1)
        short_name = match.group(2)
        full_name = match.group(3)

        # Find the full struct body
        start = match.start()
        brace_count = 0
        end = start
        for i, c in enumerate(content[start:], start):
            if c == '{':
                brace_count += 1
            elif c == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break

        struct_body = content[start:end]

        # Parse properties
        properties = []
        offset = 0  # Start after BaseComponent header (8 bytes)

        # Match member declarations
        member_pattern = re.compile(
            r'(?:\[\[bg3::\w+(?:\([^)]*\))?\]\]\s*)?'  # Optional attribute
            r'(\w+(?:<[^>]+>)?(?:::\w+)?)\s+'  # Type
            r'(\w+)\s*;'  # Name
        )

        for m in member_pattern.finditer(struct_body):
            if 'DEFINE_COMPONENT' in m.group(0):
                continue

            cpp_type = m.group(1)
            name = m.group(2)

            # Skip hidden fields
            if '[[bg3::hidden]]' in struct_body[max(0, m.start()-50):m.start()]:
                continue

            c_type, size, is_array, array_count = parse_type(cpp_type)

            # Align offset
            if size >= 8:
                offset = (offset + 7) & ~7
            elif size >= 4:
                offset = (offset + 3) & ~3
            elif size >= 2:
                offset = (offset + 1) & ~1

            prop = Property(
                name=name,
                cpp_type=cpp_type,
                c_type=c_type,
                offset=offset,
                size=size,
                is_array=is_array,
                array_count=array_count
            )
            properties.append(prop)

            offset += size

        if properties:  # Only add components with properties
            components.append(Component(
                short_name=short_name,
                full_name=full_name,
                properties=properties,
                source_file=filename
            ))

    return components

def parse_all_components() -> List[Component]:
    """Parse all component definitions from Windows BG3SE headers."""
    all_components = []

    components_dir = Path(WINDOWS_BG3SE_PATH)
    if not components_dir.exists():
        print(f"Error: Windows BG3SE path not found: {WINDOWS_BG3SE_PATH}", file=sys.stderr)
        return []

    for header in components_dir.glob("*.h"):
        try:
            content = header.read_text()
            components = parse_component_struct(content, header.name)
            all_components.extend(components)
        except Exception as e:
            print(f"Error parsing {header.name}: {e}", file=sys.stderr)

    return all_components

def generate_property_def(comp: Component) -> str:
    """Generate C property definition for a component."""
    lines = []
    lines.append(f"// {comp.full_name} (from {comp.source_file})")
    lines.append(f"// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!")
    lines.append(f"static const ComponentPropertyDef g_{comp.short_name}Component_Properties[] = {{")

    for prop in comp.properties:
        # Map to FieldType enum from component_property.h
        type_enum = "FIELD_TYPE_INT32"
        if prop.c_type == 'float':
            type_enum = "FIELD_TYPE_FLOAT"
        elif prop.c_type == 'double':
            type_enum = "FIELD_TYPE_DOUBLE"
        elif prop.c_type == 'uint64_t':
            type_enum = "FIELD_TYPE_UINT64"
        elif prop.c_type == 'int64_t':
            type_enum = "FIELD_TYPE_INT64"
        elif prop.c_type == 'uint32_t':
            type_enum = "FIELD_TYPE_UINT32"
        elif prop.c_type == 'uint16_t':
            type_enum = "FIELD_TYPE_UINT16"
        elif prop.c_type == 'int16_t':
            type_enum = "FIELD_TYPE_INT16"
        elif prop.c_type == 'uint8_t':
            type_enum = "FIELD_TYPE_UINT8"
        elif prop.c_type == 'int8_t':
            type_enum = "FIELD_TYPE_INT8"
        elif prop.c_type == 'bool':
            type_enum = "FIELD_TYPE_BOOL"
        elif 'Guid' in prop.cpp_type:
            type_enum = "FIELD_TYPE_GUID"
        elif prop.c_type == 'void*':
            # Pointer types - treat as entity handle or skip
            type_enum = "FIELD_TYPE_ENTITY_HANDLE"

        array_count = prop.array_count if prop.is_array else 0
        # Full struct: name, offset, type, arraySize, readOnly, elemType, elemSize
        lines.append(f'    {{ "{prop.name}", 0x{prop.offset:02x}, {type_enum}, {array_count}, false, ELEM_TYPE_UNKNOWN, 0 }},')

    lines.append("};")
    lines.append("")

    # Generate layout definition
    lines.append(f"static const ComponentLayoutDef g_{comp.short_name}Component_Layout = {{")
    lines.append(f'    .componentName = "{comp.full_name}",')
    lines.append(f'    .shortName = "{comp.short_name}",')
    lines.append(f'    .componentTypeIndex = 0,  // Set dynamically from TypeId')
    lines.append(f'    .componentSize = 0x{max((p.offset + p.size) for p in comp.properties) if comp.properties else 0:02x},')
    lines.append(f'    .properties = g_{comp.short_name}Component_Properties,')
    lines.append(f'    .propertyCount = sizeof(g_{comp.short_name}Component_Properties) / sizeof(g_{comp.short_name}Component_Properties[0]),')
    lines.append("};")
    lines.append("")

    return '\n'.join(lines)

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Parse Windows BG3SE component headers")
    parser.add_argument("--list", action="store_true", help="List all discovered components")
    parser.add_argument("--component", type=str, help="Show specific component details")
    parser.add_argument("--high-priority", action="store_true", help="Only show high-priority components")
    args = parser.parse_args()

    components = parse_all_components()

    if not components:
        print("No components found!", file=sys.stderr)
        sys.exit(1)

    if args.list:
        print(f"Found {len(components)} components with property definitions:")
        print()
        for comp in sorted(components, key=lambda c: c.full_name):
            print(f"  {comp.short_name:30} {comp.full_name:50} ({len(comp.properties)} props)")
        return

    if args.component:
        matches = [c for c in components if args.component.lower() in c.short_name.lower()]
        if not matches:
            print(f"No component matching '{args.component}'", file=sys.stderr)
            sys.exit(1)

        for comp in matches:
            print(f"Component: {comp.full_name}")
            print(f"Short name: {comp.short_name}")
            print(f"Source: {comp.source_file}")
            print(f"Properties ({len(comp.properties)}):")
            for prop in comp.properties:
                print(f"  +0x{prop.offset:02x} {prop.name:25} {prop.cpp_type:30} -> {prop.c_type}")
            print()
            print("Generated definition:")
            print(generate_property_def(comp))
        return

    # Generate all
    high_priority = ['Health', 'Stats', 'Armor', 'BaseHp', 'Classes', 'Data',
                     'Experience', 'Resistances', 'Movement', 'Value', 'Weapon',
                     'SpellBook', 'PassiveContainer', 'Tag', 'Race', 'Origin',
                     'Background', 'God', 'TurnBased', 'Concentration', 'DisplayName']

    if args.high_priority:
        components = [c for c in components if c.short_name in high_priority]

    sorted_components = sorted(components, key=lambda c: c.full_name)

    print("/**")
    print(" * generated_property_defs.h - Auto-generated component property definitions")
    print(" *")
    print(f" * Generated from Windows BG3SE headers by tools/parse_component_headers.py")
    print(f" * Total components: {len(components)}")
    print(" *")
    print(" * WARNING: Offsets are ESTIMATED from Windows x64 ABI.")
    print(" * ARM64 may differ for complex types. Verify via runtime probing!")
    print(" *")
    print(" * Usage: Include this file in component_offsets.h and add entries to g_AllComponentLayouts[]")
    print(" */")
    print()
    print("#ifndef GENERATED_PROPERTY_DEFS_H")
    print("#define GENERATED_PROPERTY_DEFS_H")
    print()
    print('#include "component_property.h"')
    print()

    # Generate all property definitions and layouts
    for comp in sorted_components:
        print(generate_property_def(comp))

    # Generate the generated layouts array
    print("// ============================================================================")
    print("// Generated Layouts Array")
    print("// Add these to g_AllComponentLayouts[] in component_offsets.h")
    print("// ============================================================================")
    print()
    print(f"#define GENERATED_COMPONENT_COUNT {len(sorted_components)}")
    print()
    print("static const ComponentLayoutDef* g_GeneratedComponentLayouts[] = {")
    for comp in sorted_components:
        print(f"    &g_{comp.short_name}Component_Layout,")
    print("};")
    print()
    print("#endif // GENERATED_PROPERTY_DEFS_H")

if __name__ == "__main__":
    main()
