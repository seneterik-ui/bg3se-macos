# Find StaticData Manager Singletons
# Traces TypeId xrefs to find ADRP+LDR singleton patterns
#
# Usage: ./ghidra/scripts/run_analysis.sh find_staticdata_singletons.py
#
# This script finds manager singletons that aren't exported via dlsym by:
# 1. Looking up known manager TypeId addresses
# 2. Finding all xrefs to each TypeId
# 3. Analyzing nearby instructions for ADRP+LDR (singleton load) patterns
# 4. Extracting and reporting the singleton addresses

from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.flatapi import FlatProgramAPI
import re

# Known manager TypeId addresses (from nm -gU | c++filt)
MANAGER_TYPEIDS = {
    "FeatManager": 0x1088efd00,
    "RaceManager": 0x1088fe380,
    "BackgroundManager": 0x1088fa968,
    "OriginManager": 0x1088fa988,
    "GodManager": 0x1088fa958,
    "ClassDescriptionManager": 0x1088efce8,
    "ActionResourceManager": 0x1088f6cf0,
    "ProgressionManager": 0x1088f6d20,
    "FeatDescriptionManager": 0x1088efd10,
}

def get_refs_to(addr):
    """Get all references to an address"""
    refs = []
    refManager = currentProgram.getReferenceManager()
    iterator = refManager.getReferencesTo(toAddr(addr))
    while iterator.hasNext():
        refs.append(iterator.next())
    return refs

def analyze_adrp_ldr_pattern(func_addr, search_range=0x100):
    """
    Search for ADRP+LDR pattern near an address that loads a singleton.
    Returns list of potential singleton addresses.

    ARM64 singleton load pattern:
        ADRP Xn, #page
        LDR  Xn, [Xn, #offset]
    """
    singletons = []
    listing = currentProgram.getListing()

    start = toAddr(func_addr - search_range)
    end = toAddr(func_addr + search_range)

    instr_iter = listing.getInstructions(start, True)

    adrp_info = {}  # reg -> (page_addr, instr_addr)

    while instr_iter.hasNext():
        instr = instr_iter.next()
        if instr.getAddress().getOffset() > end.getOffset():
            break

        mnemonic = instr.getMnemonicString()

        if mnemonic == "adrp":
            # ADRP Xn, #page - loads page-aligned address into register
            ops = instr.toString().split()
            if len(ops) >= 3:
                try:
                    reg = ops[1].rstrip(',')
                    # Extract the page address from operand
                    page_str = ops[2].replace('#', '').replace('0x', '')
                    page_addr = int(page_str, 16) if page_str else 0
                    adrp_info[reg] = (page_addr, instr.getAddress().getOffset())
                except:
                    pass

        elif mnemonic == "ldr" and "," in instr.toString():
            # LDR Xn, [Xm, #offset] - loads value from (page + offset)
            ops = instr.toString()
            # Look for pattern: ldr Xn, [Xm, #0x...]
            match = re.search(r'ldr\s+(\w+),\s*\[(\w+),\s*#?(0x)?([0-9a-fA-F]+)\]', ops)
            if match:
                dest_reg = match.group(1)
                base_reg = match.group(2)
                offset = int(match.group(4), 16) if match.group(3) else int(match.group(4))

                if base_reg in adrp_info:
                    page_addr, adrp_addr = adrp_info[base_reg]
                    singleton_addr = page_addr + offset
                    singletons.append({
                        'addr': singleton_addr,
                        'adrp_at': adrp_addr,
                        'ldr_at': instr.getAddress().getOffset(),
                        'register': dest_reg
                    })

    return singletons

def main():
    print("=" * 70)
    print("StaticData Manager Singleton Discovery")
    print("=" * 70)
    print("")

    results = {}

    for manager_name, typeid_addr in MANAGER_TYPEIDS.items():
        print("\n[%s] TypeId at 0x%x" % (manager_name, typeid_addr))
        print("-" * 50)

        # Get all references to the TypeId
        refs = get_refs_to(typeid_addr)
        print("  Found %d references to TypeId" % len(refs))

        manager_singletons = set()

        for ref in refs:
            from_addr = ref.getFromAddress().getOffset()
            ref_type = ref.getReferenceType()

            # Look for READ references (accessing the TypeId)
            if ref_type.isRead() or ref_type.isData():
                # Search nearby for ADRP+LDR patterns
                singletons = analyze_adrp_ldr_pattern(from_addr)

                for s in singletons:
                    # Filter to likely singleton addresses (in data segment)
                    if 0x108000000 < s['addr'] < 0x10A000000:
                        manager_singletons.add(s['addr'])
                        print("    Potential singleton: 0x%x" % s['addr'])
                        print("      ADRP at 0x%x, LDR at 0x%x" % (s['adrp_at'], s['ldr_at']))

        results[manager_name] = list(manager_singletons)

    print("\n")
    print("=" * 70)
    print("SUMMARY: Discovered Singleton Addresses")
    print("=" * 70)

    for manager_name, addrs in results.items():
        if addrs:
            print("\n%s:" % manager_name)
            for addr in sorted(addrs):
                print("  0x%x" % addr)
        else:
            print("\n%s: No singleton found (may need hook-based capture)" % manager_name)

    print("\n")
    print("Next Steps:")
    print("1. Verify addresses by runtime probing with Ext.Debug.ReadPtr()")
    print("2. Check if singleton is double-pointer (dereference twice)")
    print("3. Add verified addresses to staticdata_manager.c")

if __name__ == "__main__":
    main()
