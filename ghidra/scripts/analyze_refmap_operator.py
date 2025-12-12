# Analyze DEPRECATED_RefMapImpl::operator[] for insertion pattern
#
# The operator[] on maps typically inserts if not found, so this is how
# we can add new prototypes to the manager.
#
# Run: ./ghidra/scripts/run_analysis.sh analyze_refmap_operator.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time

start_time = time.time()
init_progress("RefMap Operator Analysis")

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

def main():
    output = []
    output.append("# RefMap Operator[] Analysis\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # Find all DEPRECATED_RefMapImpl::operator[] functions
    output.append("## DEPRECATED_RefMapImpl::operator[] Functions\n\n")
    progress("Searching for operator[] functions...")

    symbol_table = currentProgram.getSymbolTable()
    operator_funcs = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if 'DEPRECATED_RefMapImpl' in name and 'operator' in name:
            operator_funcs.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })

    if operator_funcs:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for f in operator_funcs[:30]:
            output.append("| `{}` | `0x{:x}` |\n".format(f['name'][:80], f['address']))
        output.append("\n")

    # Look for SpellPrototype-related RefMap
    output.append("## SpellPrototype RefMap Functions\n\n")
    progress("Finding SpellPrototype RefMap...")

    spell_refmap = [f for f in operator_funcs if 'SpellPrototype' in f['name'] or 'Spell' in f['name']]

    if spell_refmap:
        for f in spell_refmap[:5]:
            output.append("### {} (0x{:x})\n\n".format(f['name'][:60], f['address']))
            progress("Decompiling {}...".format(f['name'][:30]))
            name, decomp = decompile_function(f['address'])
            if decomp:
                output.append("```c\n")
                if len(decomp) > 4000:
                    output.append(decomp[:4000] + "\n... (truncated)\n")
                else:
                    output.append(decomp)
                output.append("```\n\n")

    # Decompile a generic operator[] to understand the pattern
    output.append("## Generic operator[] Pattern\n\n")
    progress("Analyzing generic operator[]...")

    if operator_funcs:
        # Pick one that's not too specific
        for f in operator_funcs:
            if 'ObjectHandleRefMap' in f['name'] or 'FixedString' in f['name']:
                output.append("### {} (0x{:x})\n\n".format(f['name'][:60], f['address']))
                name, decomp = decompile_function(f['address'])
                if decomp:
                    output.append("```c\n")
                    if len(decomp) > 4000:
                        output.append(decomp[:4000] + "\n... (truncated)\n")
                    else:
                        output.append(decomp)
                    output.append("```\n\n")
                break

    # Look for Insert/Add functions
    output.append("## Insert/Add Functions\n\n")
    progress("Finding Insert/Add functions...")

    insert_funcs = []
    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if ('Insert' in name or 'Add' in name or 'Emplace' in name) and 'RefMap' in name:
            insert_funcs.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })

    if insert_funcs:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for f in insert_funcs[:20]:
            output.append("| `{}` | `0x{:x}` |\n".format(f['name'][:80], f['address']))
        output.append("\n")

        # Decompile first Insert
        if insert_funcs:
            f = insert_funcs[0]
            output.append("### Insert Function Decompilation\n\n")
            output.append("**{}** at `0x{:x}`\n\n".format(f['name'][:60], f['address']))
            name, decomp = decompile_function(f['address'])
            if decomp:
                output.append("```c\n")
                if len(decomp) > 4000:
                    output.append(decomp[:4000] + "\n... (truncated)\n")
                else:
                    output.append(decomp)
                output.append("```\n\n")

    # Summary
    output.append("## Summary\n\n")
    output.append("**Key addresses found:**\n")
    output.append("- SpellPrototype::Init: `0x101f72754`\n")
    output.append("- RefMap operator[] functions: {}\n".format(len(operator_funcs)))
    output.append("- Insert/Add functions: {}\n".format(len(insert_funcs)))
    output.append("\n**Implementation approach:**\n")
    output.append("1. Get SpellPrototypeManager singleton\n")
    output.append("2. Call operator[] with new spell name (this inserts if not found)\n")
    output.append("3. Call SpellPrototype::Init on the returned prototype\n")

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/refmap_operator_analysis.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
