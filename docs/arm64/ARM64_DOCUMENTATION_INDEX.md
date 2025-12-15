# ARM64 Reverse Engineering Documentation Index

**Purpose:** Quick navigation to ARM64-specific guidance for BG3SE-macOS development

**Last Updated:** December 2025
**Status:** Complete documentation suite

## Core Documents

### 1. Prevention Strategies (START HERE!)
**File:** `arm64-hooking-prevention.md`

**What it covers:**
- Key learnings from BG3SE-macOS crashes and data corruption
- How Dobby inline hooks corrupt ADRP+LDR patterns
- Why TypeContext metadata != actual runtime data
- const& calling convention on ARM64
- Frida Interceptor vs Dobby comparison
- Best practices by task (discovering singletons, mapping components, etc.)

**When to read:**
- Before writing any hooking code
- When encountering mysterious failures
- To understand why certain patterns are recommended

---

### 2. Testing Strategies
**File:** `arm64-testing-strategies.md`

**What it covers:**
- 4-tier testing hierarchy (memory safety → robustness)
- Null pointer validation, bounds checking
- Round-trip verification patterns
- State transition testing across different game phases
- Hook validation checklist
- Automated testing framework

**When to read:**
- Before deploying hooks to production
- When a feature fails unpredictably
- To set up comprehensive test coverage

---

### 3. Troubleshooting Guide
**File:** `arm64-troubleshooting-guide.md`

**What it covers:**
- Quick diagnosis reference for common crashes
- Mistake/Fix table for ARM64-specific pitfalls
- Performance debugging techniques
- Crash investigation workflow
- Recovery strategies
- Symptoms → Causes → Fixes mapping

**When to read:**
- When something breaks
- To diagnose crashes
- To understand error patterns

---

## Reference Documents (Existing)

### ARM64 Patterns Reference
**File:** `/tools/skills/bg3se-macos-ghidra/references/arm64-patterns.md`

**Contains:**
- AAPCS64 calling convention (register usage, argument passing)
- Large struct return via x8 register (critical for ls::Result)
- Global pointer access (ADRP+LDR patterns)
- Inline assembly patterns
- Hardened runtime constraints
- Common ARM64 instructions
- Debugging ARM64 issues

---

### Frida Component Discovery Tools
**File:** `/tools/frida/README.md`

**Contains:**
- Frida scripts for runtime component discovery
- How to find singletons via hooking
- Interactive RPC exports for debugging
- Integration with BG3SE

---

## When to Use Each Document

### Working on a New Feature

1. **Read:** Prevention Strategies - understand the architecture
2. **Design:** What will you discover vs modify?
3. **Read:** Testing Strategies - plan your validation
4. **Implement:** Follow the patterns in Prevention Strategies
5. **Validate:** Use Testing Strategies checklist
6. **Deploy:** Check all boxes in Testing Strategies

### Feature Fails

1. **Read:** Quick Diagnosis section of Troubleshooting Guide
2. **Check:** Symptoms → Causes → Fixes table
3. **Debug:** Follow Crash Investigation Workflow
4. **Understand:** Read relevant section of Prevention Strategies

### Fixing Crashes

1. **Start:** Quick Diagnosis Reference in Troubleshooting Guide
2. **Isolate:** Common Mistakes and Fixes table
3. **Recover:** Recovery Strategies section
4. **Learn:** Document the issue in this guide for future reference

---

## Quick Reference: Prevention Patterns

### Discovering Information (Safe)
```
✅ Use: Frida Interceptor with onEnter only
✅ Use: Direct memory reads with Ext.Memory.*
✅ Use: dlsym to resolve exported symbols
✅ Use: Lua probing with Ext.Debug.*
```

### Modifying Behavior (Limited)
```
✅ Use: Dobby hooks on libOsiris.dylib only
✅ Use: Lua layer modifications
⚠️  Use Cautiously: Non-critical function testing
❌ Never: Dobby on main binary
❌ Never: Assume Windows layout on ARM64
❌ Never: Forget const& = pointer on ARM64
```

### Verifying Offsets
```
1. Ghidra disassembly analysis
2. Runtime probing (Ext.Debug.ProbeStruct)
3. Comparison with known-good values
4. Consistency checks (size <= capacity)
5. Document verification method in code
```

---

## Key Discoveries Documented

### Dobby Hooking Issues
- **Problem:** Dobby corrupts PC-relative ADRP+LDR instructions
- **Evidence:** Offset calculations fail after hooking
- **Solution:** Use Frida or direct memory reads instead

### TypeContext Mismatch
- **Problem:** C++ metadata doesn't match ARM64 memory layout
- **Evidence:** Headers show offset X, but probe finds data at offset Y
- **Example:** RPGStats::Objects at +0xC0 (not +0x08 from Windows)
- **Solution:** Always verify with runtime probing

### const& Semantics
- **Problem:** C++ references are passed as pointers on ARM64
- **Evidence:** Hook receives address, not value
- **Impact:** Reading argument directly causes garbage values
- **Solution:** Cast to pointer, dereference before using

### x8 Indirect Return
- **Problem:** Large struct returns (>16 bytes) require x8 buffer pointer
- **Evidence:** Struct fields contain garbage after function call
- **Impact:** Uninitialized buffer pointer leads to memory corruption
- **Solution:** Use x8 wrapper functions provided by arm64_call.c

---

## Version History

### v1.0 (December 2025)
- Initial complete documentation suite
- 3 production-tested documents
- Quick diagnosis reference
- All major ARM64 patterns documented
- Testing hierarchy and validation checklist

---

## Contributing

When adding new discoveries:

1. **Document in the appropriate file:**
   - Prevention Strategies - architectural understanding
   - Testing Strategies - validation approach
   - Troubleshooting Guide - symptom mapping

2. **Include:**
   - Concrete example code
   - Why the pattern works
   - When to use vs when to avoid
   - Verification method

3. **Link related sections:**
   - Similar problems
   - Dependencies
   - Prerequisite knowledge

4. **Update this index** with new patterns

---

## Related Resources

### In This Repository
- `/agent_docs/architecture.md` - System architecture overview
- `/agent_docs/ghidra.md` - Ghidra analysis workflows
- `/ghidra/offsets/STATS.md` - Verified offset discoveries
- `/src/entity/arm64_call.c` - ARM64 calling convention implementations

### External Resources
- [ARM64 ABI Specification](https://developer.arm.com/documentation/den0024/a/)
- [Dobby Hooking Framework](https://github.com/jmpews/Dobby)
- [Frida Dynamic Instrumentation](https://frida.re/)
- [Ghidra Reverse Engineering Framework](https://ghidra-sre.org/)

---

## Quick Links

| Topic | File | Section |
|-------|------|---------|
| **Getting Started** | Prevention Strategies | Top |
| **First Hook** | Prevention Strategies | "When Discovering Singletons" |
| **Crash Analysis** | Troubleshooting | "Quick Diagnosis Reference" |
| **Test Before Deploy** | Testing Strategies | "Hook Validation Checklist" |
| **const& Issue** | Prevention Strategies | "const& Parameters on ARM64" |
| **ADRP+LDR Corruption** | Prevention Strategies | "Dobby Corrupts PC-Relative" |
| **Performance Debug** | Troubleshooting | "Performance Troubleshooting" |
| **Memory Safety** | Testing Strategies | "Tier 1: Memory Safety Testing" |

---

## Summary

This documentation provides:

1. **Prevention** - Know what works and what doesn't before coding
2. **Validation** - Comprehensive testing checklist to catch issues early
3. **Recovery** - Quick diagnosis and fixes when something breaks
4. **Learning** - Understanding why ARM64 reverse engineering is different

The patterns documented here are based on real experience in BG3SE-macOS development, where crashes led to understanding the constraints of ARM64, macOS, and reverse engineering a 1GB+ game binary.

By following these guides, you can avoid the 3000+ lines of debugging that went into discovering these patterns.
