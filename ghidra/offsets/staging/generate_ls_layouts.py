#!/usr/bin/env python3
"""
Generate C component layouts for ls:: namespace by cross-referencing:
1. Ghidra ARM64 sizes from COMPONENT_SIZES_LS*.md
2. Windows BG3SE header field definitions
"""

import re
import sys
from pathlib import Path

# Field type to C type and size mapping
TYPE_MAPPING = {
    'int32_t': ('FIELD_TYPE_INT32', 4),
    'int': ('FIELD_TYPE_INT32', 4),
    'uint32_t': ('FIELD_TYPE_UINT32', 4),
    'uint8_t': ('FIELD_TYPE_UINT8', 1),
    'bool': ('FIELD_TYPE_BOOL', 1),
    'float': ('FIELD_TYPE_FLOAT', 4),
    'glm::vec3': ('FIELD_TYPE_VEC3', 12),
    'glm::quat': ('FIELD_TYPE_QUAT', 16),
    'FixedString': ('FIELD_TYPE_FIXEDSTRING', 4),
    'Guid': ('FIELD_TYPE_GUID', 16),
    'EntityHandle': ('FIELD_TYPE_ENTITYHANDLE', 8),
}

def parse_component_sizes(md_file):
    """Parse COMPONENT_SIZES_LS*.md to extract component names and sizes."""
    components = {}
    with open(md_file) as f:
        for line in f:
            # Match table rows: | ls::ComponentName | 0xHEX | BYTES | ... |
            match = re.match(r'\|\s*(ls::\S+)\s*\|\s*0x([0-9a-fA-F]+)\s*\|\s*(\d+)', line)
            if match:
                name = match.group(1)
                hex_size = match.group(2)
                byte_size = int(match.group(3))
                components[name] = {
                    'size_hex': hex_size,
                    'size_bytes': byte_size,
                    'source_file': md_file.name
                }
    return components

def find_component_struct(component_name, header_dir):
    """Find struct definition in Windows headers."""
    # Extract short name (e.g., ls::TransformComponent -> Transform)
    short_name = component_name.split('::')[-1].replace('Component', '')

    # Search in all .h files
    for header_file in Path(header_dir).glob('**/*.h'):
        try:
            with open(header_file, encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Look for struct definition with DEFINE_COMPONENT macro
                # More flexible pattern to capture full struct
                pattern = rf'struct\s+\w*Component\s*:\s*public\s+Base\w*Component\s*\{{([^{{}}]*DEFINE[^{{}}]*"{re.escape(component_name)}"[^{{}}]*)\}};'
                match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
                if match:
                    return {
                        'header_file': header_file.name,
                        'struct_text': match.group(0)
                    }
        except Exception as e:
            continue
    return None

def parse_struct_fields(struct_text):
    """Parse field definitions from struct text."""
    fields = []
    lines = struct_text.split('\n')
    for line in lines:
        # Match field declarations: Type FieldName;
        match = re.match(r'\s+(\S+(?:\s*\*)?)\s+(\w+);', line)
        if match:
            field_type = match.group(1).strip()
            field_name = match.group(2)
            fields.append({
                'type': field_type,
                'name': field_name
            })
    return fields

def generate_component_layout(component_name, size_info, fields):
    """Generate C code for component layout."""
    short_name = component_name.split('::')[-1].replace('Component', '')
    size_hex = size_info['size_hex']
    size_bytes = size_info['size_bytes']

    # Generate property definitions
    props = []
    offset = 0
    for field in fields:
        field_type = field['type'].replace('*', '').strip()
        field_name = field['name']

        # Map to FIELD_TYPE
        if field_type in TYPE_MAPPING:
            type_enum, type_size = TYPE_MAPPING[field_type]
            props.append(f'    {{ "{field_name}", 0x{offset:02x}, {type_enum}, 0, true }},')
            offset += type_size
        else:
            # Unknown type - comment it out
            props.append(f'    // {{ "{field_name}", 0x{offset:02x}, UNKNOWN_{field_type.upper()}, 0, true }},')

    if not props:
        # Tag component (no fields)
        props_def = f"static const ComponentPropertyDef g_ls_{short_name}_Properties[] = {{}};"
    else:
        props_def = f"static const ComponentPropertyDef g_ls_{short_name}_Properties[] = {{\n" + '\n'.join(props) + "\n};"

    layout = f"""// {component_name} - {size_bytes} bytes (0x{size_hex})
// Source: {size_info.get('header_file', 'Ghidra')}
{props_def}
static const ComponentLayoutDef g_ls_{short_name}_Layout = {{
    .componentName = "{component_name}",
    .shortName = "{short_name}",
    .componentTypeIndex = 0,
    .componentSize = 0x{size_hex},
    .properties = g_ls_{short_name}_Properties,
    .propertyCount = sizeof(g_ls_{short_name}_Properties) / sizeof(g_ls_{short_name}_Properties[0]),
}};
"""
    return layout

if __name__ == '__main__':
    # Paths
    sizes_dir = Path('/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components')
    header_dir = Path('/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions')

    # Parse all COMPONENT_SIZES_LS*.md files
    all_components = {}
    for md_file in sizes_dir.glob('COMPONENT_SIZES_LS*.md'):
        components = parse_component_sizes(md_file)
        all_components.update(components)

    print(f"// Auto-generated ls:: component layouts")
    print(f"// Total components: {len(all_components)}")
    print()

    # Generate layouts for simple components first (sorted by size)
    sorted_components = sorted(all_components.items(), key=lambda x: x[1]['size_bytes'])

    generated_count = 0
    for comp_name, size_info in sorted_components:
        if generated_count >= 50:  # Limit to 50 components
            break

        # Skip singletons and components without sizes
        if 'Singleton' in comp_name or size_info['size_bytes'] == 0:
            continue

        # Try to find struct definition in Windows headers
        struct_info = find_component_struct(comp_name, header_dir)
        if struct_info:
            fields = parse_struct_fields(struct_info['struct_text'])
            size_info['header_file'] = struct_info['header_file']
        else:
            fields = []

        layout = generate_component_layout(comp_name, size_info, fields)
        print(layout)
        generated_count += 1

    print(f"\n// Generated {generated_count} component layouts")
