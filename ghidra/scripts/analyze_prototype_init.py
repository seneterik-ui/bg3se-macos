# Analyze prototype initialization flow
#
# Traces from __GLOBAL__sub_I_SpellPrototype.cpp to understand how
# spell prototypes are created and registered with the manager.
#
# Run: ./ghidra/scripts/run_analysis.sh analyze_prototype_init.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time

start_time = time.time()
init_progress("Prototype Init Analysis")

# Static initializers discovered earlier
STATIC_INITS = {
    "__GLOBAL__sub_I_SpellPrototype.cpp": 0x1066e389c,
    "__GLOBAL__sub_I_StatusPrototypeManager.cpp": 0x106704ad4,
    "__GLOBAL__sub_I_PassivePrototype.cpp": 0x106691108,
}

# Manager singletons
MANAGERS = {
    "SpellPrototypeManager::m_ptr": 0x1089bac80,
    "StatusPrototypeManager::m_ptr": 0x1089bdb30,
    "PassivePrototypeManager": 0x108aeccd8,
}

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
        return func.getName(), "Error: " + str(e)
    return func.getName(), None

def get_called_functions(func_addr):
    """Get list of functions called by this function"""
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return []

    called = []
    ref_mgr = currentProgram.getReferenceManager()

    # Iterate through function body
    body = func.getBody()
    addr_iter = body.getAddresses(True)

    while addr_iter.hasNext():
        addr = addr_iter.next()
        refs = ref_mgr.getReferencesFrom(addr)
        for ref in refs:
            if ref.getReferenceType().isCall():
                target = ref.getToAddress()
                target_func = getFunctionAt(target)
                if target_func:
                    called.append({
                        'name': target_func.getName(),
                        'address': target.getOffset(),
                        'from': addr.getOffset(),
                    })

    return called

def find_init_functions():
    """Search for Init functions related to prototypes"""
    symbol_table = currentProgram.getSymbolTable()
    init_funcs = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        # Look for Init functions in prototype-related contexts
        if 'Init' in name and ('Prototype' in name or 'Spell' in name or 'Status' in name or 'Passive' in name):
            if '::' in name or 'sub_I' not in name:  # Skip static initializers
                init_funcs.append({
                    'name': name,
                    'address': sym.getAddress().getOffset(),
                })

    return init_funcs

def main():
    output = []
    output.append("# Prototype Initialization Flow Analysis\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # Search for Init functions
    output.append("## Init Functions Found\n\n")
    progress("Searching for Init functions...")

    init_funcs = find_init_functions()
    if init_funcs:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for f in init_funcs[:30]:
            output.append("| `{}` | `0x{:x}` |\n".format(f['name'][:60], f['address']))
    else:
        output.append("No Init functions found with expected naming patterns.\n")
    output.append("\n")

    # Analyze static initializers
    output.append("## Static Initializer Analysis\n\n")

    for name, addr in STATIC_INITS.items():
        progress("Analyzing {}...".format(name))

        func_name, decomp = decompile_function(addr)
        if not func_name:
            output.append("### {} (0x{:x})\n".format(name, addr))
            output.append("**Error:** Function not found\n\n")
            continue

        output.append("### {} (0x{:x})\n".format(name, addr))
        output.append("**Actual name:** `{}`\n\n".format(func_name))

        # Get called functions
        called = get_called_functions(addr)
        if called:
            output.append("**Functions called:**\n")
            for c in called[:15]:
                output.append("- `{}` at `0x{:x}`\n".format(c['name'], c['address']))
            output.append("\n")

        # Show decompiled code
        if decomp:
            output.append("**Decompiled:**\n```c\n")
            # Truncate if too long
            if len(decomp) > 3000:
                output.append(decomp[:3000] + "\n... (truncated)\n")
            else:
                output.append(decomp)
            output.append("```\n\n")

        output.append("---\n\n")

    # Look for prototype registration patterns
    output.append("## Searching for Registration Patterns\n\n")
    progress("Searching for registration patterns...")

    # Search for functions that might register prototypes
    symbol_table = currentProgram.getSymbolTable()
    register_funcs = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if ('Register' in name or 'Add' in name or 'Insert' in name) and \
           ('Prototype' in name or 'Spell' in name or 'Status' in name):
            register_funcs.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })

    if register_funcs:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for f in register_funcs[:20]:
            output.append("| `{}` | `0x{:x}` |\n".format(f['name'][:60], f['address']))
    else:
        output.append("No explicit registration functions found.\n")
    output.append("\n")

    # Analyze SpellPrototypeManager structure by looking at GetSpellPrototype
    output.append("## GetSpellPrototype Analysis (for RefMap pattern)\n\n")
    progress("Analyzing GetSpellPrototype...")

    get_spell_proto_addr = 0x10346e740  # SpellCastWrapper::GetSpellPrototype
    func_name, decomp = decompile_function(get_spell_proto_addr)

    if decomp:
        output.append("**GetSpellPrototype decompiled (shows lookup pattern):**\n```c\n")
        if len(decomp) > 4000:
            output.append(decomp[:4000] + "\n... (truncated)\n")
        else:
            output.append(decomp)
        output.append("```\n\n")

    # Summary
    output.append("## Summary\n\n")
    output.append("**Static initializers** set up the manager singletons.\n")
    output.append("**GetSpellPrototype** shows the lookup pattern (RefMap access).\n")
    output.append("**Next:** Find where prototypes are first inserted into the RefMap.\n")

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/prototype_init_analysis.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
