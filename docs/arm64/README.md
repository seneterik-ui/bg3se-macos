# ARM64 Development Documentation

Documentation for ARM64-specific development patterns, hooking strategies, and troubleshooting for BG3SE-macOS.

## Quick Start

| Document | When to Read |
|----------|--------------|
| [Executive Summary](ARM64_EXECUTIVE_SUMMARY.md) | High-level overview of ARM64 challenges |
| [Hooking Prevention](arm64-hooking-prevention.md) | Before implementing any hooks |
| [Testing Strategies](arm64-testing-strategies.md) | When validating implementations |
| [Troubleshooting Guide](arm64-troubleshooting-guide.md) | When debugging crashes |
| [Documentation Index](ARM64_DOCUMENTATION_INDEX.md) | Full navigation guide |

## The 4 Core ARM64 Challenges

1. **Dobby Hook Corruption** - ADRP+LDR patterns corrupted by inline hooks
2. **TypeContext Mismatch** - Metadata offsets differ from actual data structures
3. **const& Calling Convention** - Passed as pointers, not values
4. **x8 Indirect Return** - Structs >16 bytes require x8 buffer setup

## Key Patterns

### Safe: Frida Interceptor (onEnter only)
```javascript
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        // Capture without replacing function
    }
});
```

### Safe: Direct Memory Reads
```c
void* ptr = dlsym(handle, "RPGStats::m_ptr");
RPGStats* stats = *(RPGStats**)ptr;
```

### Dangerous: Dobby on Main Binary
```c
// AVOID - corrupts PC-relative instructions
DobbyHook(mainBinaryFunc, replacement, &original);
```

## Related Documentation

- [Reverse Engineering Guide](../reverse-engineering.md)
- [Ghidra Offsets](../../ghidra/offsets/)
- [Frida Scripts](../../tools/frida/)
