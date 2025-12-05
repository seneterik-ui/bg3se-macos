# Find ModifierList structure offsets in BG3 ARM64
# Specifically looking for the Name field offset

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import PointerDataType
from progress_utils import init_progress, progress, finish_progress

def log(msg):
    print("[ModifierList] " + str(msg))

def search_for_symbol(pattern):
    """Search for symbols matching a pattern"""
    results = []
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getAllSymbols(False)
    for sym in symbols:
        if pattern.lower() in sym.getName().lower():
            results.append(sym)
    return results

def main():
    init_progress("find_modifierlist_offsets.py")
    log("=== ModifierList Structure Analysis ===")

    progress("Searching ModifierList symbols", 10)
    ml_symbols = search_for_symbol("ModifierList")
    log("Found %d ModifierList symbols" % len(ml_symbols))
    for sym in ml_symbols[:20]:
        log("  %s at 0x%x" % (sym.getName(), sym.getAddress().getOffset()))

    progress("Searching RPGStats symbols", 30)
    rpg_symbols = search_for_symbol("RPGStats")
    log("Found %d RPGStats symbols" % len(rpg_symbols))
    for sym in rpg_symbols[:20]:
        log("  %s at 0x%x" % (sym.getName(), sym.getAddress().getOffset()))

    # Search for stat type names like "Weapon", "Armor", etc.
    # These are FixedString constants that would be used as ModifierList names
    type_names = ["Weapon", "Armor", "SpellData", "StatusData", "PassiveData", "Character"]

    progress("Searching stat type name strings", 50)
    log("\n=== Searching for stat type name strings ===")
    for i, type_name in enumerate(type_names):
        pct = 50 + (i * 40 // len(type_names))
        progress("Searching for '%s'" % type_name, pct)

        # Search in defined strings
        memory = currentProgram.getMemory()
        listing = currentProgram.getListing()

        # Search for the string in memory
        search_bytes = type_name.encode('ascii') + b'\x00'
        addr = memory.findBytes(toAddr(0x100000000), search_bytes, None, True, monitor)

        if addr:
            log("Found '%s' at 0x%x" % (type_name, addr.getOffset()))

            # Look for XREFs to this string
            refs = getReferencesTo(addr)
            log("  %d references to this string" % len(list(refs)))
            for ref in getReferencesTo(addr):
                log("    From 0x%x (%s)" % (ref.getFromAddress().getOffset(), ref.getReferenceType()))

    log("\n=== Analysis complete ===")
    finish_progress()

if __name__ == "__main__":
    main()
