#!/usr/bin/env python3
"""
find_rpgstats.py - Find gRPGStats global pointer

Strategy:
1. Search for "eoc::RPGStatsComponent" string and find XREFs
2. Search for "esv::RPGStatsSystem" string and find XREFs
3. Look for functions that access a global pointer to stats
4. Search for patterns like loading stats files

Expected pattern from Windows BG3SE:
- gRPGStats is a global double pointer (stats::RPGStats**)
- Pattern: mov reg, [gRPGStats]; mov reg, [reg]; call ClearStats
"""

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from progress_utils import init_progress, progress, finish_progress
import re

def find_string_address(search_str):
    """Find address of a string in the binary."""
    memory = currentProgram.getMemory()
    listing = currentProgram.getListing()

    # Search in all memory blocks
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue

        start = block.getStart()
        end = block.getEnd()

        # Read block content
        try:
            data = bytearray(block.getSize())
            block.getBytes(start, data)
            data_str = bytes(data)

            # Search for string
            idx = data_str.find(search_str.encode('utf-8'))
            if idx >= 0:
                addr = start.add(idx)
                print("[+] Found '{}' at {}".format(search_str[:40], addr))
                return addr
        except:
            continue

    return None

def find_xrefs(addr):
    """Find cross-references to an address."""
    refs = []
    refManager = currentProgram.getReferenceManager()

    iterator = refManager.getReferencesTo(addr)
    for ref in iterator:
        refs.append(ref.getFromAddress())

    return refs

def analyze_function_for_global(func_addr):
    """Analyze a function to find global pointer accesses."""
    listing = currentProgram.getListing()
    func = getFunctionContaining(func_addr)

    if not func:
        return None

    print("[*] Analyzing function at {} ({})".format(func.getEntryPoint(), func.getName()))

    # Get function body
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)

    globals_found = []

    for inst in inst_iter:
        mnemonic = inst.getMnemonicString()

        # Look for ADRP (Address to Register with Page)
        if mnemonic == "adrp":
            # Get the page address being loaded
            operand = inst.getDefaultOperandRepresentation(1)
            print("  ADRP at {}: {}".format(inst.getAddress(), operand))

            # Look for following LDR that builds the full address
            next_inst = listing.getInstructionAfter(inst.getAddress())
            if next_inst and next_inst.getMnemonicString() in ["ldr", "add"]:
                print("    Followed by {} at {}".format(
                    next_inst.getMnemonicString(),
                    next_inst.getAddress()))
                globals_found.append((inst.getAddress(), operand))

    return globals_found

def search_for_stats_patterns():
    """Search for patterns related to stats system."""

    print("=" * 60)
    print("Searching for RPGStats-related patterns")
    print("=" * 60)

    # Pattern 1: Search for RPGStatsComponent type name
    patterns = [
        "eoc::RPGStatsComponent",
        "esv::RPGStatsSystem",
        "esv::stats::Loader",
        "GetStatsExtraDataValue",
    ]

    for i, pattern in enumerate(patterns):
        pct = 20 + (i * 40 // len(patterns))
        progress("Searching for: %s" % pattern, pct)
        print("\n[*] Searching for: {}".format(pattern))
        addr = find_string_address(pattern)

        if addr:
            xrefs = find_xrefs(addr)
            print("    XREFs: {}".format(len(xrefs)))

            for xref in xrefs[:5]:  # Limit to first 5
                print("      -> {}".format(xref))
                analyze_function_for_global(xref)

def search_data_segment():
    """Search __DATA segment for potential RPGStats pointer."""
    memory = currentProgram.getMemory()

    progress("Searching __DATA segment", 70)
    print("\n" + "=" * 60)
    print("Searching __DATA segment for potential stats pointers")
    print("=" * 60)

    for block in memory.getBlocks():
        name = block.getName()
        if "__DATA" in name or ".data" in name.lower():
            print("\n[*] Block: {} ({} - {})".format(
                name, block.getStart(), block.getEnd()))
            print("    Size: {} bytes".format(block.getSize()))

def main():
    """Main entry point."""
    init_progress("find_rpgstats.py")

    print("\n" + "=" * 60)
    print("RPGStats Global Pointer Finder")
    print("=" * 60 + "\n")

    progress("Starting RPGStats search", 10)

    # Search for string patterns
    search_for_stats_patterns()

    # Search data segments
    search_data_segment()

    progress("Analysis complete", 90)
    print("\n[*] Analysis complete")
    print("[*] Manual next steps:")
    print("    1. Find XREFs to identified strings")
    print("    2. Trace ADRP+LDR patterns to find global pointers")
    print("    3. Verify pointer leads to CNamedElementManager structure")

    finish_progress()

if __name__ == "__main__":
    main()
