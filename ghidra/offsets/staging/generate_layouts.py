#!/usr/bin/env python3
"""
Generate C component layouts from Windows BG3SE headers and Ghidra ARM64 sizes.
"""

import re
import os
from pathlib import Path

# Type mapping from C++ to field types
TYPE_MAP = {
    'int32_t': ('FIELD_TYPE_INT32', 4),
    'int': ('FIELD_TYPE_INT32', 4),
    'uint32_t': ('FIELD_TYPE_UINT32', 4),
    'uint8_t': ('FIELD_TYPE_UINT8', 1),
    'uint16_t': ('FIELD_TYPE_UINT32', 2),
    'int8_t': ('FIELD_TYPE_INT32', 1),
    'bool': ('FIELD_TYPE_BOOL', 1),
    'float': ('FIELD_TYPE_FLOAT', 4),
    'FixedString': ('FIELD_TYPE_FIXEDSTRING', 4),
    'Guid': ('FIELD_TYPE_GUID', 16),
    'EntityHandle': ('FIELD_TYPE_ENTITYHANDLE', 8),
    'double': ('FIELD_TYPE_FLOAT', 8),  # Treat as 8-byte float
    # Enum types (typically 1-4 bytes, we'll use 4 for safety)
    'AbilityId': ('FIELD_TYPE_INT32', 4),
    'SkillId': ('FIELD_TYPE_INT32', 4),
    'DamageType': ('FIELD_TYPE_INT32', 4),
    'DiceSizeId': ('FIELD_TYPE_INT32', 4),
    'SpellAttackType': ('FIELD_TYPE_INT32', 4),
    'ResourceReplenishType': ('FIELD_TYPE_INT32', 4),
    'SpellSchoolId': ('FIELD_TYPE_INT32', 4),
    'BoostType': ('FIELD_TYPE_INT32', 4),
    'ResistanceBoostFlags': ('FIELD_TYPE_UINT8', 1),
    'WeaponFlags': ('FIELD_TYPE_UINT32', 4),
    'AttributeFlags': ('FIELD_TYPE_UINT32', 4),
}

def parse_size_files(component_sizes_dir):
    """Parse all COMPONENT_SIZES_EOC_*.md files."""
    sizes = {}
    md_files = Path(component_sizes_dir).glob('COMPONENT_SIZES_EOC_*.md')

    for md_file in md_files:
        with open(md_file, 'r') as f:
            content = f.read()
            # Match table rows: | eoc::ComponentName | 0xHEX | BYTES | Notes |
            pattern = r'\|\s*(eoc::[:\w]+Component)\s*\|\s*0x([0-9a-fA-F]+)\s*\|\s*(\d+)\s*\|'
            for match in re.finditer(pattern, content):
                component_name = match.group(1)
                hex_size = match.group(2)
                byte_size = int(match.group(3))
                sizes[component_name] = {
                    'hex': hex_size,
                    'bytes': byte_size
                }

    return sizes

def parse_windows_header(header_path):
    """Parse Windows BG3SE header file to extract component definitions."""
    components = {}

    with open(header_path, 'r') as f:
        content = f.read()

    # Find struct definitions
    # Pattern: struct ComponentName : public BaseComponent { ... fields ... }
    struct_pattern = r'struct\s+(\w+Component)\s*:\s*public\s+BaseComponent\s*\{([^}]+)\}'

    for match in re.finditer(struct_pattern, content):
        struct_name = match.group(1)
        body = match.group(2)

        # Extract DEFINE_COMPONENT to get full namespace name
        define_match = re.search(r'DEFINE_COMPONENT\([^,]+,\s*"([^"]+)"\)', body)
        if not define_match:
            continue

        full_name = define_match.group(1)
        if not full_name.startswith('eoc::'):
            continue

        # Parse fields
        fields = []
        field_lines = body.split('\n')
        for line in field_lines:
            line = line.strip()
            # Skip DEFINE_COMPONENT, comments, empty lines
            if not line or line.startswith('//') or 'DEFINE_COMPONENT' in line or line.startswith('[['):
                continue

            # Simple field pattern: type name;
            field_match = re.match(r'([\w:<>, ]+?)\s+(\w+)\s*;', line)
            if field_match:
                field_type = field_match.group(1).strip()
                field_name = field_match.group(2).strip()
                fields.append((field_name, field_type))

        if fields:
            components[full_name] = {
                'struct_name': struct_name,
                'fields': fields
            }

    # Parse DEFN_BOOST macros
    # Pattern: DEFN_BOOST(ComponentName, ShortName, { fields })
    boost_pattern = r'DEFN_BOOST\((\w+),\s*\w+,\s*\{([^}]+)\}\)'

    for match in re.finditer(boost_pattern, content):
        boost_name = match.group(1)
        body = match.group(2)

        # Construct full component name
        full_name = f'eoc::{boost_name}BoostComponent'

        # Parse fields
        fields = []
        field_lines = body.split('\n')
        for line in field_lines:
            line = line.strip()
            # Skip comments, empty lines, legacy annotations
            if not line or line.startswith('//') or line.startswith('[['):
                continue

            # Field pattern: type name;
            field_match = re.match(r'([\w:<>, ]+?)\s+(\w+)\s*;', line)
            if field_match:
                field_type = field_match.group(1).strip()
                field_name = field_match.group(2).strip()
                fields.append((field_name, field_type))

        if fields:
            components[full_name] = {
                'struct_name': f'{boost_name}BoostComponent',
                'fields': fields
            }

    return components

def get_field_type_and_size(cpp_type):
    """Convert C++ type to field type and size."""
    # Strip const, &, *, std::
    cpp_type = cpp_type.replace('const', '').replace('&', '').replace('*', '').strip()
    cpp_type = re.sub(r'std::', '', cpp_type)

    # Check direct mapping
    if cpp_type in TYPE_MAP:
        return TYPE_MAP[cpp_type]

    # Handle arrays and complex types
    if cpp_type.startswith('array<') or cpp_type.startswith('Array<'):
        return ('FIELD_TYPE_ARRAY', 16)  # Array = ptr + capacity + size

    if 'Guid' in cpp_type:
        return ('FIELD_TYPE_GUID', 16)

    if 'Handle' in cpp_type:
        return ('FIELD_TYPE_ENTITYHANDLE', 8)

    # Default to unknown (skip)
    return (None, 0)

def align_offset(offset, alignment=4):
    """Align offset to specified boundary."""
    remainder = offset % alignment
    if remainder != 0:
        offset += alignment - remainder
    return offset

def generate_layout(component_name, struct_info, component_size):
    """Generate C code for a component layout."""
    fields = struct_info['fields']
    struct_name = struct_info['struct_name']

    # Generate property definitions
    properties = []
    offset = 0

    for field_name, field_type in fields:
        field_type_enum, field_size = get_field_type_and_size(field_type)

        if field_type_enum is None:
            # Skip complex types we can't map
            continue

        # Align offset for this field
        if field_size >= 4:
            offset = align_offset(offset, 4)

        # Add property
        is_array = 'Array' in field_type or 'array' in field_type
        properties.append({
            'name': field_name,
            'offset': offset,
            'type': field_type_enum,
            'size': field_size,
            'is_array': is_array
        })

        offset += field_size

    if not properties:
        return None

    # Generate C code
    short_name = component_name.split('::')[-1]
    c_code = []
    c_code.append(f"// {component_name} - {component_size} bytes (0x{component_size:X})")
    c_code.append(f"// Source: {struct_name} from Windows BG3SE")
    c_code.append(f"static const ComponentPropertyDef g_eoc_{short_name}_Properties[] = {{")

    for prop in properties:
        array_flag = "true" if prop['is_array'] else "false"
        c_code.append(f"    {{ \"{prop['name']}\", 0x{prop['offset']:02X}, {prop['type']}, 0, {array_flag} }},")

    c_code.append("};")
    c_code.append(f"static const ComponentLayoutDef g_eoc_{short_name}_Layout = {{")
    c_code.append(f"    .componentName = \"{component_name}\",")
    c_code.append(f"    .shortName = \"{short_name}\",")
    c_code.append(f"    .componentTypeIndex = 0,")
    c_code.append(f"    .componentSize = 0x{component_size:X},")
    c_code.append(f"    .properties = g_eoc_{short_name}_Properties,")
    c_code.append(f"    .propertyCount = sizeof(g_eoc_{short_name}_Properties) / sizeof(g_eoc_{short_name}_Properties[0]),")
    c_code.append("};")
    c_code.append("")

    return '\n'.join(c_code)

def main():
    # Paths
    bg3se_components_dir = '/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components'
    sizes_dir = '/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components'
    output_file = '/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/staging/generated_eoc_layouts.c'
    existing_file = '/Users/tomdimino/Desktop/Programming/bg3se-macos/src/entity/component_offsets.h'

    # Parse sizes from Ghidra
    print("Parsing component sizes from Ghidra...")
    sizes = parse_size_files(sizes_dir)
    print(f"Found {len(sizes)} components with sizes")

    # Parse existing layouts to avoid duplicates
    print("Checking existing layouts...")
    existing = set()
    with open(existing_file, 'r') as f:
        content = f.read()
        # Find all g_eoc_*_Layout definitions
        for match in re.finditer(r'g_eoc_(\w+)_Layout', content):
            existing.add(match.group(1))
    print(f"Found {len(existing)} existing layouts")

    # Parse Windows headers
    print("Parsing Windows BG3SE headers...")
    all_components = {}
    header_files = [
        'Stats.h', 'Boosts.h', 'Item.h', 'Combat.h', 'Data.h',
        'CharacterCreation.h', 'Inventory.h', 'Spell.h', 'Status.h'
    ]

    for header_name in header_files:
        header_path = os.path.join(bg3se_components_dir, header_name)
        if os.path.exists(header_path):
            components = parse_windows_header(header_path)
            all_components.update(components)
            print(f"  {header_name}: {len(components)} components")

    print(f"Total Windows components: {len(all_components)}")

    # Generate layouts
    print("\nGenerating layouts...")
    generated = []
    skipped = []

    for component_name, size_info in sorted(sizes.items()):
        # Check if already exists
        short_name = component_name.split('::')[-1]
        if short_name in existing:
            skipped.append(f"{component_name} (already exists)")
            continue

        # Skip if too large (complex) - but be more generous for boost components
        max_size = 256 if 'Boost' in component_name else 128
        if size_info['bytes'] > max_size:
            skipped.append(f"{component_name} (too large: {size_info['bytes']} bytes)")
            continue

        # Find in Windows headers
        if component_name not in all_components:
            skipped.append(f"{component_name} (no Windows header)")
            continue

        struct_info = all_components[component_name]
        layout_code = generate_layout(component_name, struct_info, size_info['bytes'])

        if layout_code:
            generated.append(layout_code)
            print(f"  ✓ {component_name}")
        else:
            skipped.append(f"{component_name} (no mappable fields)")

    # Write output
    print(f"\nWriting {len(generated)} layouts to {output_file}...")
    with open(output_file, 'w') as f:
        f.write("// Generated component layouts for eoc:: namespace\n")
        f.write("// Auto-generated by generate_layouts.py\n")
        f.write("// DO NOT EDIT - Verify offsets before using in production\n\n")
        f.write('\n'.join(generated))

    print(f"\n✓ Generated {len(generated)} layouts")
    print(f"✓ Skipped {len(skipped)} components")
    print(f"\nOutput: {output_file}")

if __name__ == '__main__':
    main()
