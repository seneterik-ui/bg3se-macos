# Find prototype loading functions
#
# Searches for functions that load/parse spell/status data and insert into managers
#
# Run: ./ghidra/scripts/run_analysis.sh find_prototype_loading.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time

start_time = time.time()
init_progress("Prototype Loading Discovery")

def decompile_function(func_addr, timeout=120):
    """Decompile a function and return C code"""
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return None, None

    try:
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, timeout, monitor)
        if result.decompileCompleted():
            return func.getName(), result.getDecompiledFunction().getC()
    except Exception as e:
        return func.getName() if func else None, "Error: " + str(e)
    return func.getName(), None

def search_symbols(patterns):
    """Search for symbols matching any of the patterns"""
    symbol_table = currentProgram.getSymbolTable()
    matches = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        for pattern in patterns:
            if pattern.lower() in name.lower():
                matches.append({
                    'name': name,
                    'address': sym.getAddress().getOffset(),
                    'pattern': pattern,
                })
                break

    return matches

def main():
    output = []
    output.append("# Prototype Loading Function Discovery\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # Search for loading/parsing functions
    output.append("## Loading/Parsing Function Search\n\n")
    progress("Searching for loading functions...")

    load_patterns = [
        "LoadSpell",
        "ParseSpell",
        "LoadStatus",
        "ParseStatus",
        "LoadPassive",
        "ParsePassive",
        "LoadPrototype",
        "ParsePrototype",
        "SpellPrototype::Load",
        "StatusPrototype::Load",
        "SyncStat",
        "SyncSpell",
        "SyncStatus",
        "InitFromStats",
        "CreatePrototype",
        "BuildPrototype",
    ]

    matches = search_symbols(load_patterns)

    if matches:
        output.append("| Pattern | Name | Address |\n")
        output.append("|---------|------|----------|\n")
        for m in matches[:40]:
            output.append("| {} | `{}` | `0x{:x}` |\n".format(
                m['pattern'], m['name'][:50], m['address']))
    else:
        output.append("No matches found for loading patterns.\n")
    output.append("\n")

    # Search for RefMap/HashMap insert functions
    output.append("## RefMap/HashMap Insert Functions\n\n")
    progress("Searching for insert functions...")

    insert_patterns = [
        "RefMap",
        "DEPRECATED_RefMap",
        "::Insert",
        "::Add",
        "::Set",
        "HashMap::Insert",
        "operator[]",
    ]

    insert_matches = search_symbols(insert_patterns)

    # Filter to prototype-related
    proto_inserts = [m for m in insert_matches if
                    'Spell' in m['name'] or 'Status' in m['name'] or
                    'Passive' in m['name'] or 'Prototype' in m['name'] or
                    'RefMap' in m['name']]

    if proto_inserts:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for m in proto_inserts[:30]:
            output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:60], m['address']))
    else:
        output.append("No prototype-related insert functions found.\n")
    output.append("\n")

    # Search for Stats::Load or Stats::Sync functions
    output.append("## Stats System Functions\n\n")
    progress("Searching for stats functions...")

    stats_patterns = [
        "RPGStats::Load",
        "RPGStats::Sync",
        "Stats::Load",
        "Stats::Sync",
        "CRPGStats",
        "StatsLoader",
        "LoadStats",
    ]

    stats_matches = search_symbols(stats_patterns)

    if stats_matches:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for m in stats_matches[:30]:
            output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:60], m['address']))
    output.append("\n")

    # Analyze key functions
    output.append("## Function Analysis\n\n")

    # Look for functions containing "Prototype" AND "Sync" or "Load"
    progress("Looking for sync/load prototype functions...")

    symbol_table = currentProgram.getSymbolTable()
    key_funcs = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        name_lower = name.lower()
        if 'prototype' in name_lower and ('sync' in name_lower or 'load' in name_lower or 'init' in name_lower):
            key_funcs.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })

    if key_funcs:
        output.append("### Key Prototype Functions\n\n")
        for f in key_funcs[:10]:
            output.append("#### {} (0x{:x})\n\n".format(f['name'][:50], f['address']))

            func_name, decomp = decompile_function(f['address'])
            if decomp:
                output.append("```c\n")
                if len(decomp) > 2000:
                    output.append(decomp[:2000] + "\n... (truncated)\n")
                else:
                    output.append(decomp)
                output.append("```\n\n")

    # Look at the RefMap operator[] which is used for insertion
    output.append("## RefMap Access Pattern\n\n")
    progress("Looking for RefMap access...")

    # From earlier analysis, GetPassivePrototype uses DEPRECATED_RefMapImpl::operator[]
    # Let's find that function
    refmap_funcs = []
    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if 'DEPRECATED_RefMapImpl' in name and 'operator' in name:
            refmap_funcs.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })

    if refmap_funcs:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for f in refmap_funcs[:20]:
            output.append("| `{}` | `0x{:x}` |\n".format(f['name'][:70], f['address']))
        output.append("\n")

        # Decompile first one
        if refmap_funcs:
            f = refmap_funcs[0]
            output.append("### Sample RefMap operator[] (0x{:x})\n\n".format(f['address']))
            func_name, decomp = decompile_function(f['address'])
            if decomp:
                output.append("```c\n")
                if len(decomp) > 3000:
                    output.append(decomp[:3000] + "\n... (truncated)\n")
                else:
                    output.append(decomp)
                output.append("```\n\n")

    # Summary
    output.append("## Summary\n\n")
    output.append("Look for functions that:\n")
    output.append("1. Take a stats object and a prototype manager\n")
    output.append("2. Call RefMap::operator[] or Insert to add prototype\n")
    output.append("3. Populate prototype fields from stats properties\n")

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/prototype_loading_discovery.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
