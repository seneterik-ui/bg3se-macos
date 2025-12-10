# @category BG3SE
# @description Decompile a function at the given address and print its code

import sys
from ghidra.program.model.address import AddressFactory
from ghidra.app.decompiler import DecompInterface

def main():
    # Get address from script arguments
    args = getScriptArgs()
    if not args or len(args) < 1:
        print("Usage: decompile_function.py <address>")
        print("Example: decompile_function.py 0x10636b27c")
        return

    addr_str = args[0]

    # Parse address
    try:
        if addr_str.startswith("0x"):
            addr_val = int(addr_str, 16)
        else:
            addr_val = int(addr_str)
    except ValueError:
        print("Invalid address: " + addr_str)
        return

    # Get address object
    addr = toAddr(addr_val)

    print("\n" + "=" * 60)
    print("Analyzing function at: " + str(addr))
    print("=" * 60 + "\n")

    # Get function at address
    fn = getFunctionAt(addr)
    if not fn:
        # Try to get function containing address
        fn = getFunctionContaining(addr)

    if not fn:
        print("No function found at address: " + str(addr))
        # Print disassembly instead
        print("\nDisassembly at address:")
        listing = currentProgram.getListing()
        cur_addr = addr
        for i in range(50):
            instr = listing.getInstructionAt(cur_addr)
            if instr:
                print("  " + str(cur_addr) + ": " + str(instr))
                cur_addr = cur_addr.add(instr.getLength())
            else:
                break
        return

    print("Function: " + fn.getName())
    print("Entry point: " + str(fn.getEntryPoint()))
    print("Size: " + str(fn.getBody().getNumAddresses()) + " bytes")
    print("")

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    # Decompile with timeout
    result = decompiler.decompileFunction(fn, 60, monitor)

    if result.decompileCompleted():
        print("=== DECOMPILED CODE ===")
        print(result.getDecompiledFunction().getC())
        print("========================")
    else:
        print("Decompilation failed or incomplete")
        print("Error: " + str(result.getErrorMessage()))

    # Also print disassembly for reference
    print("\n=== DISASSEMBLY ===")
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(fn.getBody(), True)

    count = 0
    for instr in instructions:
        print("  " + str(instr.getAddress()) + ": " + str(instr))
        count += 1
        if count > 100:
            print("  ... (truncated)")
            break

    print("==================")

    # Look for specific patterns
    print("\n=== ARRAY ACCESS PATTERNS ===")
    print("Looking for LDR with LSL #3 (pointer array indexing)...")

    instructions = listing.getInstructions(fn.getBody(), True)
    for instr in instructions:
        mnemonic = str(instr.getMnemonicString()).lower()
        operands = str(instr)
        if "lsl" in operands.lower() and "#3" in operands:
            print("  FOUND: " + str(instr.getAddress()) + ": " + str(instr))
        if "0x" in operands:
            print("  OFFSET: " + str(instr.getAddress()) + ": " + str(instr))

if __name__ == "__main__":
    main()
