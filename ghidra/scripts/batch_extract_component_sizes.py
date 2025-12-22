# Batch Extract Component Sizes from AddComponent<T> Functions
# @category BG3SE
#
# Iterates ALL AddComponent template instantiations in the binary,
# decompiles each, and extracts the component struct size from
# ComponentFrameStorageAllocRaw calls.
#
# Output: JSON file with component name -> size mapping
#
# Run: analyzeHeadless /path/to/project BG3 -noanalysis -postScript batch_extract_component_sizes.py

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
import re
import json
import os

# Output file location
OUTPUT_FILE = os.path.expanduser("~/Desktop/Programming/bg3se-macos/ghidra/offsets/component_sizes.json")

def extract_component_name(func_name):
    """
    Extract component type from demangled AddComponent function name.

    Examples:
        ecs::EntityWorld::AddComponent<eoc::HealthComponent,...> -> eoc::HealthComponent
        AddComponent<esv::CharacterComponent,...> -> esv::CharacterComponent
    """
    # Pattern: AddComponent<TypeName, ...> or AddComponent<TypeName>
    match = re.search(r'AddComponent<([^,>]+)', func_name)
    if match:
        return match.group(1).strip()
    return None

def extract_alloc_size(decompiled_code):
    """
    Extract size from ComponentFrameStorageAllocRaw call.

    Patterns:
        ComponentFrameStorageAllocRaw(..., 0x30, ...) -> 0x30
        _ComponentFrameStorageAllocRaw(ptr, 48, ...) -> 48
    """
    # Pattern 1: Hex literal (0x...)
    match = re.search(r'ComponentFrameStorageAllocRaw\s*\([^,]+,\s*(0x[0-9a-fA-F]+)', decompiled_code)
    if match:
        return int(match.group(1), 16)

    # Pattern 2: Decimal literal
    match = re.search(r'ComponentFrameStorageAllocRaw\s*\([^,]+,\s*(\d+)', decompiled_code)
    if match:
        return int(match.group(1))

    # Pattern 3: Direct size in function call (some have different arg order)
    match = re.search(r'Alloc(?:Raw)?\s*\([^)]*?(?:0x([0-9a-fA-F]+)|(\d{2,}))[^)]*\)', decompiled_code)
    if match:
        if match.group(1):
            return int(match.group(1), 16)
        elif match.group(2):
            return int(match.group(2))

    return None

def main():
    print("=" * 70)
    print("BATCH COMPONENT SIZE EXTRACTION")
    print("Scanning for all AddComponent<T> functions...")
    print("=" * 70)

    # Initialize decompiler
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    # Find all functions with "AddComponent" in name
    symbol_table = currentProgram.getSymbolTable()
    results = {}
    errors = []
    processed = 0

    # Iterate all function symbols
    for sym in symbol_table.getAllSymbols(True):
        if sym.getSymbolType() != SymbolType.FUNCTION:
            continue

        name = sym.getName()

        # Filter for AddComponent template instantiations
        if "AddComponent<" not in name:
            continue

        processed += 1

        # Extract component type from function name
        component_name = extract_component_name(name)
        if not component_name:
            errors.append({"function": name, "error": "Could not parse component name"})
            continue

        # Skip duplicates (same component may have multiple template variants)
        if component_name in results:
            continue

        # Get function and decompile
        func = getFunctionAt(sym.getAddress())
        if not func:
            errors.append({"function": name, "error": "Function not found at address"})
            continue

        result = decomp.decompileFunction(func, 30, None)  # 30 second timeout
        if not result or not result.decompileCompleted():
            errors.append({"function": name, "error": "Decompilation failed"})
            continue

        code = result.getDecompiledFunction().getC()

        # Extract allocation size
        size = extract_alloc_size(code)
        if size:
            results[component_name] = {
                "size": size,
                "size_hex": "0x{:02x}".format(size),
                "address": str(sym.getAddress()),
                "function": name[:100]  # Truncate long names
            }
            print("[OK] {} -> {} bytes".format(component_name, size))
        else:
            errors.append({
                "function": name[:100],
                "component": component_name,
                "error": "Could not extract size from decompiled code"
            })
            print("[??] {} - no size found".format(component_name))

    decomp.dispose()

    # Summary
    print("\n" + "=" * 70)
    print("EXTRACTION COMPLETE")
    print("=" * 70)
    print("Functions processed: {}".format(processed))
    print("Components with sizes: {}".format(len(results)))
    print("Errors/skipped: {}".format(len(errors)))

    # Group by namespace
    namespaces = {}
    for comp, data in results.items():
        ns = comp.split("::")[0] if "::" in comp else "other"
        if ns not in namespaces:
            namespaces[ns] = 0
        namespaces[ns] += 1

    print("\nBy namespace:")
    for ns, count in sorted(namespaces.items(), key=lambda x: -x[1]):
        print("  {}: {}".format(ns, count))

    # Write output
    output = {
        "metadata": {
            "total_functions": processed,
            "components_extracted": len(results),
            "errors": len(errors)
        },
        "components": results,
        "errors": errors[:50]  # Limit error output
    }

    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(output, f, indent=2, sort_keys=True)
        print("\nOutput written to: {}".format(OUTPUT_FILE))
    except Exception as e:
        print("\nFailed to write output: {}".format(e))
        # Print to console as fallback
        print("\n--- JSON OUTPUT ---")
        print(json.dumps(output, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
