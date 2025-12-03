# find_c600_offset.py
# Find code that uses 0xC600 offset (GlobalStringTable MainTable offset)
# This offset is unique to GlobalStringTable and identifies the exact location

from ghidra.program.model.listing import CodeUnit

def log(msg):
    print("[C600] " + msg)

def search_for_c600():
    """Search for instructions adding 0xC600 (MainTable offset)"""
    log("=== Searching for 0xC600 (MainTable offset = 50688) ===")

    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()

    textBlock = memory.getBlock("__TEXT")
    if not textBlock:
        log("ERROR: No __TEXT section")
        return []

    results = []
    instIter = listing.getInstructions(textBlock.getStart(), True)
    count = 0

    while instIter.hasNext() and count < 50000000:
        count += 1
        try:
            inst = instIter.next()
            mnemonic = inst.getMnemonicString().lower()
            inst_str = inst.toString().lower()

            # Look for ADD with 0xC600 or 50688
            if mnemonic == "add" and ("0xc600" in inst_str or "#50688" in inst_str or "50688" in inst_str):
                func = currentProgram.getFunctionManager().getFunctionContaining(inst.getAddress())
                func_name = func.getName() if func else "unknown"
                log("  Found: %s at %s" % (inst.toString(), inst.getAddress()))
                log("    In function: %s" % func_name)
                results.append({
                    'addr': inst.getAddress(),
                    'inst': inst.toString(),
                    'func': func,
                    'func_name': func_name
                })

                # Analyze this function to find GlobalStringTable pointer
                if func:
                    analyze_function_for_gst(func, inst.getAddress())

        except Exception as e:
            pass

        if count % 5000000 == 0:
            log("  Scanned %d instructions..." % count)

    log("  Total: Scanned %d instructions, found %d 0xC600 patterns" % (count, len(results)))
    return results

def analyze_function_for_gst(func, c600_addr):
    """Analyze function containing 0xC600 add to find GST pointer"""
    log("    Analyzing function: %s" % func.getName())

    listing = currentProgram.getListing()
    body = func.getBody()

    # Collect instructions before the 0xC600 add
    adrp_instructions = []
    ldr_instructions = []

    instIter = listing.getInstructions(body, True)
    while instIter.hasNext():
        inst = instIter.next()
        if inst.getAddress().getOffset() >= c600_addr.getOffset():
            break

        mnemonic = inst.getMnemonicString().lower()

        if mnemonic == "adrp":
            # Get destination register and target
            try:
                dest_reg = inst.getRegister(0)
                ops = inst.getOpObjects(1)
                if ops and len(ops) > 0:
                    target = str(ops[0])
                    adrp_instructions.append({
                        'addr': inst.getAddress(),
                        'reg': dest_reg.getName() if dest_reg else 'unknown',
                        'target': target,
                        'inst': inst.toString()
                    })
            except:
                pass

        elif mnemonic == "ldr":
            # Track LDR instructions
            try:
                refs = inst.getReferencesFrom()
                for ref in refs:
                    ldr_instructions.append({
                        'addr': inst.getAddress(),
                        'target': str(ref.getToAddress()),
                        'inst': inst.toString()
                    })
            except:
                pass

    # Print ADRP targets found before the 0xC600 add
    if adrp_instructions:
        log("    ADRP instructions before 0xC600 add:")
        for a in adrp_instructions[-10:]:  # Last 10
            log("      %s: %s -> %s" % (a['addr'], a['reg'], a['target']))

    if ldr_instructions:
        log("    LDR with references before 0xC600 add:")
        for l in ldr_instructions[-10:]:  # Last 10
            log("      %s: -> %s" % (l['addr'], l['target']))

            # Try to calculate offset from base
            try:
                target_val = int(l['target'].replace("0x", ""), 16)
                base = 0x100000000
                offset = target_val - base
                if 0 < offset < 0x10000000:
                    log("        *** POTENTIAL GST OFFSET: 0x%x ***" % offset)
            except:
                pass

def search_for_strings():
    """Search for FixedString-related strings"""
    log("\n=== Searching for FixedString/StringTable strings ===")

    listing = currentProgram.getListing()

    markers = ["FixedString", "StringTable", "ls::FixedString", "gGlobalStringTable"]

    dataIter = listing.getDefinedData(True)
    while dataIter.hasNext():
        try:
            data = dataIter.next()
            if data.hasStringValue():
                val = data.getValue()
                if val:
                    try:
                        val_str = str(val)[:100]
                        for marker in markers:
                            if marker.lower() in val_str.lower():
                                log("  Found string at %s: %s" % (data.getAddress(), val_str))
                                refs = getReferencesTo(data.getAddress())
                                for ref in refs:
                                    log("    XREF from: %s" % ref.getFromAddress())
                                    func = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress())
                                    if func:
                                        log("      In function: %s" % func.getName())
                                break
                    except:
                        pass
        except:
            pass

# Main
print("=" * 70)
print("GlobalStringTable Search via 0xC600 Offset")
print("=" * 70)

results = search_for_c600()
search_for_strings()

print("\n" + "=" * 70)
print("Summary: Found %d 0xC600 patterns" % len(results))
if results:
    print("These functions likely access GlobalStringTable:")
    for r in results:
        print("  %s at %s" % (r['func_name'], r['addr']))
print("=" * 70)
