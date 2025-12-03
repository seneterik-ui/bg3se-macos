# Ghidra Python script to analyze Osiris function structures
# Run with: analyzeHeadless ... -postScript analyze_osiris_functions.py
# Note: Uses Python 2.7 syntax for Jython compatibility

from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolTable
from ghidra.app.decompiler import DecompInterface

def demangle(name):
    """Attempt to demangle a C++ name"""
    from ghidra.app.util.demangler import DemanglerUtil
    try:
        result = DemanglerUtil.demangle(currentProgram, name)
        if result:
            return result.getSignature()
    except:
        pass
    return name

def analyze_pFunctionData():
    """Analyze COsiFunctionMan::pFunctionData to understand return struct"""
    print("=" * 60)
    print("Analyzing pFunctionData...")
    print("=" * 60)

    # Known symbol address from nm
    # __ZN15COsiFunctionMan13pFunctionDataEj at 0x2a04c
    pFunctionData_addr = currentProgram.getAddressFactory().getAddress("0x2a04c")

    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(pFunctionData_addr)

    if func:
        print("Found pFunctionData at %s" % func.getEntryPoint())
        print("Name: %s" % func.getName())
        print("Signature: %s" % func.getSignature())
        print("Return type: %s" % func.getReturnType())

        # Decompile to see implementation
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, 60, None)

        if result.decompileCompleted():
            print("\nDecompiled code:")
            print("-" * 40)
            print(result.getDecompiledFunction().getC())
    else:
        print("Function not found at %s" % pFunctionData_addr)
        # Try searching
        for f in fm.getFunctions(True):
            if "pFunctionData" in f.getName():
                print("Found: %s at %s" % (f.getName(), f.getEntryPoint()))

def analyze_OsiFunctionDef():
    """Find and analyze COsiFunctionDef structure"""
    print("\n" + "=" * 60)
    print("Analyzing COsiFunctionDef structure...")
    print("=" * 60)

    # Look for constructor at known address
    # __ZN15COsiFunctionDefC1EPKcP18COsipParameterList at 0x26dc4
    constructor_addr = currentProgram.getAddressFactory().getAddress("0x26dc4")

    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(constructor_addr)

    if func:
        print("Found COsiFunctionDef constructor at %s" % func.getEntryPoint())

        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, 60, None)

        if result.decompileCompleted():
            print("\nConstructor code (shows field assignments):")
            print("-" * 40)
            print(result.getDecompiledFunction().getC())

def find_function_strings():
    """Search for known Osiris function names in strings"""
    print("\n" + "=" * 60)
    print("Searching for known function strings...")
    print("=" * 60)

    known_funcs = [
        "AutomatedDialogStarted",
        "PROC_CharacterEnteredCombat",
        "TurnStarted",
        "TurnEnded",
        "CombatStarted",
        "CombatEnded",
        "CharacterCreationFinished",
    ]

    memory = currentProgram.getMemory()

    for func_name in known_funcs:
        # Search for string in memory
        addr = memory.findBytes(
            currentProgram.getMinAddress(),
            func_name.encode('utf-8'),
            None,  # mask
            True,  # forward
            None   # monitor
        )

        if addr:
            print("\nFound '%s' at %s" % (func_name, addr))

            # Get XREFs to this string
            from ghidra.program.model.symbol import ReferenceManager
            refs = currentProgram.getReferenceManager().getReferencesTo(addr)
            for ref in refs:
                print("  XREF from: %s" % ref.getFromAddress())
        else:
            print("'%s' not found in strings" % func_name)

def analyze_FunctionDb():
    """Look for FunctionDb hash table pattern (0x3FF)"""
    print("\n" + "=" * 60)
    print("Searching for FunctionDb hash table...")
    print("=" * 60)

    listing = currentProgram.getListing()
    found = []

    # Look for AND with 0x3FF which is used for hash bucket lookup
    for instr in listing.getInstructions(True):
        mnemonic = instr.getMnemonicString()
        if "AND" in mnemonic.upper():
            for i in range(instr.getNumOperands()):
                op_str = str(instr.getDefaultOperandRepresentation(i))
                if "0x3ff" in op_str.lower() or "1023" in op_str:
                    found.append((instr.getAddress(), str(instr)))
                    if len(found) < 10:
                        print("Found hash pattern at %s: %s" % (instr.getAddress(), instr))

    print("\nTotal hash patterns found: %d" % len(found))

def main():
    print("=" * 60)
    print("Osiris Function Analysis Script")
    print("Program: %s" % currentProgram.getName())
    print("=" * 60)

    analyze_pFunctionData()
    analyze_OsiFunctionDef()
    find_function_strings()
    analyze_FunctionDb()

    print("\n" + "=" * 60)
    print("Analysis complete")
    print("=" * 60)

main()
