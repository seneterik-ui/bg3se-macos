# Find SpellPrototype Init/Create functions
#
# Searches for SpellPrototype initialization, constructor, and related functions
#
# Run: ./ghidra/scripts/run_analysis.sh find_spell_prototype_init.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time

start_time = time.time()
init_progress("SpellPrototype Init Discovery")

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

def search_symbols(patterns, exact=False):
    """Search for symbols matching any of the patterns"""
    symbol_table = currentProgram.getSymbolTable()
    matches = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        for pattern in patterns:
            if exact:
                if pattern == name:
                    matches.append({
                        'name': name,
                        'address': sym.getAddress().getOffset(),
                        'pattern': pattern,
                    })
                    break
            else:
                if pattern.lower() in name.lower():
                    matches.append({
                        'name': name,
                        'address': sym.getAddress().getOffset(),
                        'pattern': pattern,
                    })
                    break

    return matches

def get_xrefs_to(addr):
    """Get all references to an address"""
    refs = []
    ref_mgr = currentProgram.getReferenceManager()
    for ref in ref_mgr.getReferencesTo(toAddr(addr)):
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        func_name = func.getName() if func else "unknown"
        refs.append({
            'from_addr': from_addr.getOffset(),
            'func_name': func_name,
            'type': str(ref.getReferenceType()),
        })
    return refs

def main():
    output = []
    output.append("# SpellPrototype Init Discovery\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # Search for SpellPrototype methods
    output.append("## SpellPrototype Methods\n\n")
    progress("Searching for SpellPrototype methods...")

    spell_proto_patterns = [
        "SpellPrototype::",
        "SpellPrototype.",
        "eoc::SpellPrototype",
    ]

    matches = search_symbols(spell_proto_patterns)

    if matches:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        # Filter to unique names
        seen = set()
        for m in matches:
            key = m['address']
            if key not in seen:
                seen.add(key)
                output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:80], m['address']))
        output.append("\n")
    else:
        output.append("No SpellPrototype methods found.\n\n")

    # Search specifically for Init/Create functions
    output.append("## Init/Create Functions\n\n")
    progress("Searching for Init/Create functions...")

    init_patterns = [
        "SpellPrototype::Init",
        "SpellPrototype::Create",
        "SpellPrototype::Build",
        "SpellPrototype::Setup",
        "SpellPrototypeManager::Create",
        "SpellPrototypeManager::Init",
        "SpellPrototypeManager::Add",
        "SpellPrototypeManager::Insert",
        "SpellPrototypeManager::Register",
        "SpellPrototypeManager::Sync",
    ]

    init_matches = search_symbols(init_patterns)

    if init_matches:
        output.append("| Pattern | Name | Address |\n")
        output.append("|---------|------|----------|\n")
        for m in init_matches:
            output.append("| {} | `{}` | `0x{:x}` |\n".format(
                m['pattern'], m['name'][:60], m['address']))
        output.append("\n")
    else:
        output.append("No direct Init/Create functions found. Looking for indirect patterns...\n\n")

    # Analyze ParseSpellAnimations - this is a SpellPrototype method
    PARSE_SPELL_ANIMATIONS = 0x101f779dc

    output.append("## ParseSpellAnimations Analysis\n\n")
    output.append("This is a known `eoc::SpellPrototype` method at `0x{:x}`\n\n".format(PARSE_SPELL_ANIMATIONS))
    progress("Analyzing ParseSpellAnimations...")

    # Get XREFs to this function
    xrefs = get_xrefs_to(PARSE_SPELL_ANIMATIONS)

    if xrefs:
        output.append("### XREFs to ParseSpellAnimations\n\n")
        output.append("| From Function | From Address | Type |\n")
        output.append("|--------------|--------------|------|\n")
        for ref in xrefs[:20]:
            output.append("| `{}` | `0x{:x}` | {} |\n".format(
                ref['func_name'][:50], ref['from_addr'], ref['type']))
        output.append("\n")

        # Decompile the first caller
        if xrefs:
            caller_func = getFunctionContaining(toAddr(xrefs[0]['from_addr']))
            if caller_func:
                output.append("### First Caller Decompilation\n\n")
                func_name, decomp = decompile_function(caller_func.getEntryPoint().getOffset())
                if decomp:
                    output.append("**Function:** `{}` at `0x{:x}`\n\n".format(
                        func_name, caller_func.getEntryPoint().getOffset()))
                    output.append("```c\n")
                    if len(decomp) > 5000:
                        output.append(decomp[:5000] + "\n... (truncated)\n")
                    else:
                        output.append(decomp)
                    output.append("```\n\n")

    # Search for SpellPrototype constructors
    output.append("## SpellPrototype Constructor Search\n\n")
    progress("Searching for constructors...")

    ctor_patterns = [
        "SpellPrototype::SpellPrototype",
        "SpellPrototypeC1E",
        "SpellPrototypeC2E",
    ]

    ctor_matches = search_symbols(ctor_patterns)

    if ctor_matches:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for m in ctor_matches:
            output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:70], m['address']))
        output.append("\n")

        # Decompile first constructor
        if ctor_matches:
            output.append("### Constructor Decompilation\n\n")
            func_name, decomp = decompile_function(ctor_matches[0]['address'])
            if decomp:
                output.append("```c\n")
                if len(decomp) > 4000:
                    output.append(decomp[:4000] + "\n... (truncated)\n")
                else:
                    output.append(decomp)
                output.append("```\n\n")
    else:
        output.append("No explicit constructors found.\n\n")

    # Look at GetSpellPrototype to understand how prototypes are retrieved/created
    GET_SPELL_PROTOTYPE = 0x10346e740  # SpellCastWrapper::GetSpellPrototype

    output.append("## GetSpellPrototype XREFs\n\n")
    progress("Analyzing GetSpellPrototype callers...")

    xrefs = get_xrefs_to(GET_SPELL_PROTOTYPE)

    if xrefs:
        output.append("First 10 callers:\n")
        output.append("| From Function | From Address |\n")
        output.append("|--------------|---------------|\n")
        for ref in xrefs[:10]:
            output.append("| `{}` | `0x{:x}` |\n".format(
                ref['func_name'][:50], ref['from_addr']))
        output.append("\n")

    # Search for SyncStat functions (Windows pattern)
    output.append("## SyncStat Search\n\n")
    progress("Searching for SyncStat functions...")

    sync_patterns = [
        "SyncStat",
        "Sync_Stat",
        "SyncWithPrototype",
        "RegisterPrototype",
        "UpdatePrototype",
    ]

    sync_matches = search_symbols(sync_patterns)

    # Filter out PhysX syncState
    proto_sync = [m for m in sync_matches if 'physx' not in m['name'].lower()
                  and 'phx' not in m['name'].lower()
                  and 'Scb' not in m['name']]

    if proto_sync:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for m in proto_sync[:20]:
            output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:70], m['address']))
        output.append("\n")
    else:
        output.append("No SyncStat functions found (excluding PhysX).\n\n")

    # Search for SpellPrototypeManager methods
    output.append("## SpellPrototypeManager Methods\n\n")
    progress("Searching for SpellPrototypeManager methods...")

    mgr_patterns = [
        "SpellPrototypeManager::",
        "SpellPrototypeManager.",
        "eoc::SpellPrototypeManager",
    ]

    mgr_matches = search_symbols(mgr_patterns)

    if mgr_matches:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        seen = set()
        for m in mgr_matches:
            key = m['address']
            if key not in seen:
                seen.add(key)
                output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:80], m['address']))
        output.append("\n")

        # Decompile first non-destructor method
        for m in mgr_matches:
            if '~' not in m['name'] and 'D0Ev' not in m['name'] and 'D1Ev' not in m['name']:
                output.append("### Sample Method Decompilation\n\n")
                func_name, decomp = decompile_function(m['address'])
                if decomp:
                    output.append("**{}** at `0x{:x}`\n\n".format(func_name, m['address']))
                    output.append("```c\n")
                    if len(decomp) > 4000:
                        output.append(decomp[:4000] + "\n... (truncated)\n")
                    else:
                        output.append(decomp)
                    output.append("```\n\n")
                break

    # Summary
    output.append("## Key Findings Summary\n\n")
    output.append("- SpellPrototype methods found: {}\n".format(len(matches) if matches else 0))
    output.append("- Init/Create functions found: {}\n".format(len(init_matches) if init_matches else 0))
    output.append("- SpellPrototypeManager methods found: {}\n".format(len(mgr_matches) if mgr_matches else 0))
    output.append("- ParseSpellAnimations at: `0x{:x}`\n".format(PARSE_SPELL_ANIMATIONS))
    output.append("\n")

    duration = time.time() - start_time
    output.append("**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/spell_prototype_init_discovery.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
