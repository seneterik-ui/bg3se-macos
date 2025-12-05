#!/usr/bin/env python3
"""
find_getfixedstring.py - Find RPGStats::GetFixedString and trace FixedStrings offset

Strategy:
1. Search for "GetFixedString" symbol
2. If not found, search for a function that:
   - Takes RPGStats* (x0) and int stringId (w1)
   - Returns &FixedStrings[stringId]
3. Trace the offset used to access FixedStrings member
"""

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def find_symbol_by_name(name_pattern):
    """Find symbols matching a pattern."""
    matches = []
    sm = currentProgram.getSymbolTable()
    for symbol in sm.getAllSymbols(True):
        if name_pattern.lower() in symbol.getName().lower():
            matches.append(symbol)
    return matches

def find_string_address(search_str):
    """Find address of a string in the binary."""
    memory = currentProgram.getMemory()

    for block in memory.getBlocks():
        if not block.isInitialized():
            continue

        start = block.getStart()
        try:
            size = block.getSize()
            if size > 100000000:  # Skip huge blocks
                continue
            data = bytearray(size)
            block.getBytes(start, data)

            idx = bytes(data).find(search_str.encode('utf-8'))
            if idx >= 0:
                return start.add(idx)
        except:
            continue
    return None

def find_xrefs(addr):
    """Find cross-references to an address."""
    refs = []
    refManager = currentProgram.getReferenceManager()
    for ref in refManager.getReferencesTo(addr):
        refs.append(ref.getFromAddress())
    return refs

def analyze_function_instructions(func):
    """Analyze instructions in a function for ADRP+LDR patterns."""
    listing = currentProgram.getListing()
    results = []

    if not func:
        return results

    for inst in listing.getInstructions(func.getBody(), True):
        mnemonic = inst.getMnemonicString()
        addr = inst.getAddress()

        # Look for ADD with immediate (often used for struct offset)
        if mnemonic == "add":
            ops = []
            for i in range(inst.getNumOperands()):
                ops.append(inst.getDefaultOperandRepresentation(i))
            if len(ops) >= 3:
                results.append({
                    'addr': addr,
                    'mnemonic': mnemonic,
                    'ops': ops
                })

        # Look for LDR with offset
        if mnemonic in ["ldr", "ldp"]:
            ops = []
            for i in range(inst.getNumOperands()):
                ops.append(inst.getDefaultOperandRepresentation(i))
            results.append({
                'addr': addr,
                'mnemonic': mnemonic,
                'ops': ops
            })

    return results

def decompile_function(func):
    """Decompile function and return C code."""
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)

    if not func:
        return None

    results = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())

    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None

def main():
    print("=" * 70)
    print("Finding RPGStats::GetFixedString and FixedStrings offset")
    print("=" * 70)

    # Step 1: Search for GetFixedString symbols
    print("\n[1] Searching for GetFixedString symbols...")
    symbols = find_symbol_by_name("GetFixedString")

    for sym in symbols[:20]:
        print("  {} at {}".format(sym.getName(), sym.getAddress()))

        func = getFunctionAt(sym.getAddress())
        if func:
            # Analyze instructions
            insts = analyze_function_instructions(func)
            for inst in insts[:30]:
                print("    {}: {} {}".format(inst['addr'], inst['mnemonic'], inst['ops']))

            # Try decompilation
            code = decompile_function(func)
            if code:
                print("\n  Decompiled:")
                for line in code.split('\n')[:30]:
                    print("    {}".format(line))

    # Step 2: Search for FixedStrings symbol
    print("\n[2] Searching for FixedStrings symbols...")
    symbols = find_symbol_by_name("FixedStrings")
    for sym in symbols[:10]:
        print("  {} at {}".format(sym.getName(), sym.getAddress()))

    # Step 3: Search for RPGStats::Get functions
    print("\n[3] Searching for RPGStats Get functions...")
    get_symbols = find_symbol_by_name("RPGStats")
    for sym in get_symbols[:30]:
        name = sym.getName()
        if "Get" in name and ("Fixed" in name or "String" in name or "Float" in name or "Int" in name or "Guid" in name):
            print("  {} at {}".format(name, sym.getAddress()))

            func = getFunctionAt(sym.getAddress())
            if func:
                code = decompile_function(func)
                if code and len(code) < 2000:
                    print("  Decompiled:")
                    for line in code.split('\n')[:20]:
                        print("    {}".format(line))

    # Step 4: Search for TrackedCompactSet symbols
    print("\n[4] Searching for TrackedCompactSet symbols...")
    symbols = find_symbol_by_name("TrackedCompactSet")
    for sym in symbols[:10]:
        print("  {} at {}".format(sym.getName(), sym.getAddress()))

    # Step 5: Search for CompactSet symbols
    print("\n[5] Searching for CompactSet symbols...")
    symbols = find_symbol_by_name("CompactSet")
    for sym in symbols[:10]:
        print("  {} at {}".format(sym.getName(), sym.getAddress()))

    # Step 6: Look for gRPGStats global
    print("\n[6] Searching for gRPGStats global...")
    symbols = find_symbol_by_name("gRPGStats")
    for sym in symbols[:5]:
        print("  {} at {}".format(sym.getName(), sym.getAddress()))

        # Find references to this global
        xrefs = find_xrefs(sym.getAddress())
        print("    {} references".format(len(xrefs)))
        for xref in xrefs[:5]:
            print("      From {}".format(xref))

    # Step 7: Look for functions accessing RPGStats fields at high offsets
    print("\n[7] Searching for RPGStats field access patterns...")
    # The FixedStrings field should be accessed at offset 0x2xx or 0x3xx
    # Look for functions with names containing "Stat" that use such offsets

    stat_symbols = find_symbol_by_name("Stat")
    interesting = []
    for sym in stat_symbols:
        name = sym.getName()
        # Filter for likely getter functions
        if any(x in name for x in ["Get", "get", "Load", "Parse", "Read"]):
            func = getFunctionAt(sym.getAddress())
            if func:
                insts = analyze_function_instructions(func)
                for inst in insts:
                    # Look for high offsets (0x200+)
                    for op in inst.get('ops', []):
                        if '#0x' in op.lower():
                            try:
                                # Extract hex value
                                hex_part = op.lower().split('#0x')[1].split(']')[0].split(',')[0]
                                val = int(hex_part, 16)
                                if 0x200 <= val <= 0x400:
                                    interesting.append({
                                        'func': name,
                                        'addr': sym.getAddress(),
                                        'inst_addr': inst['addr'],
                                        'offset': val
                                    })
                            except:
                                pass

    print("  Found {} functions with high offset (0x200-0x400) accesses:".format(len(interesting)))
    seen = set()
    for item in interesting[:30]:
        key = (str(item['func']), item['offset'])
        if key not in seen:
            seen.add(key)
            print("    {} at {}: offset 0x{:x}".format(item['func'], item['addr'], item['offset']))

    print("\n" + "=" * 70)
    print("Analysis complete")
    print("=" * 70)

if __name__ == "__main__":
    main()
