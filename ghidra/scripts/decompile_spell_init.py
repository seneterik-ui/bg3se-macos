# Decompile the SpellPrototype Init function
#
# Based on XREFs to ParseSpellAnimations, there's an Init function at ~0x101f744xx
#
# Run: ./ghidra/scripts/run_analysis.sh decompile_spell_init.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time

start_time = time.time()
init_progress("SpellPrototype Init Decompilation")

def decompile_function(func_addr, timeout=180):
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

def get_function_containing_address(addr):
    """Get the function containing the given address"""
    func = getFunctionContaining(toAddr(addr))
    if func:
        return func.getEntryPoint().getOffset(), func.getName()
    return None, None

def main():
    output = []
    output.append("# SpellPrototype Init Function Decompilation\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # The call to ParseSpellAnimations at 0x101f744b8 is inside the Init function
    # Let's find what function contains this address
    CALL_ADDR = 0x101f744b8

    output.append("## Finding Init Function\n\n")
    progress("Finding function containing call to ParseSpellAnimations...")

    func_addr, func_name = get_function_containing_address(CALL_ADDR)

    if func_addr:
        output.append("**Function containing call at 0x{:x}:**\n".format(CALL_ADDR))
        output.append("- Name: `{}`\n".format(func_name))
        output.append("- Entry: `0x{:x}`\n\n".format(func_addr))

        # Decompile this function
        progress("Decompiling Init function...")
        name, decomp = decompile_function(func_addr)

        if decomp:
            output.append("## Init Function Decompilation\n\n")
            output.append("**{}** at `0x{:x}`\n\n".format(name, func_addr))
            output.append("```c\n")
            output.append(decomp)
            output.append("```\n\n")
        else:
            output.append("**Error:** Could not decompile function\n\n")
    else:
        output.append("**Error:** Could not find function containing address\n\n")

    # Also look at related Init functions nearby
    output.append("## Searching for Related Init Functions\n\n")
    progress("Searching for Init functions...")

    symbol_table = currentProgram.getSymbolTable()
    init_funcs = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        addr = sym.getAddress().getOffset()
        # Look for Init functions in the same address range (0x101f7....)
        if 'Init' in name and 0x101f70000 <= addr <= 0x101f80000:
            init_funcs.append({
                'name': name,
                'address': addr,
            })

    if init_funcs:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for f in sorted(init_funcs, key=lambda x: x['address']):
            output.append("| `{}` | `0x{:x}` |\n".format(f['name'][:70], f['address']))
        output.append("\n")

        # Decompile any that look like SpellPrototype Init
        for f in init_funcs:
            if 'SpellPrototype' in f['name'] or 'Spell' in f['name']:
                progress("Decompiling {}...".format(f['name'][:30]))
                name, decomp = decompile_function(f['address'])
                if decomp:
                    output.append("### {} (0x{:x})\n\n".format(f['name'][:50], f['address']))
                    output.append("```c\n")
                    if len(decomp) > 6000:
                        output.append(decomp[:6000] + "\n... (truncated)\n")
                    else:
                        output.append(decomp)
                    output.append("```\n\n")

    # Look for the specific Init symbol
    output.append("## All 'Init' Symbols at Entry Point ~0x101f74\n\n")
    progress("Looking for Init at entry point...")

    func = getFunctionAt(toAddr(0x101f74254))  # Guessing entry based on call address
    if func:
        output.append("Function at 0x101f74254: `{}`\n\n".format(func.getName()))

    # Try a few possible entry points
    for entry in [0x101f74254, 0x101f74000, 0x101f73f00, 0x101f74100]:
        func = getFunctionAt(toAddr(entry))
        if func:
            output.append("Function at 0x{:x}: `{}`\n".format(entry, func.getName()))

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/spell_init_decompilation.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
