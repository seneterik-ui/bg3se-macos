---
title: "StaticData FeatManager Discovery"
date: 2025-12-14
category: reverse-engineering
component: Ext.StaticData
issue: "#40"
severity: architecture
tags:
  - arm64
  - hooking
  - memory-layout
  - typecontext
  - featmanager
---

# StaticData FeatManager Discovery

## Problem

Initial attempt to extract FeatManager data via `Ext.StaticData` TypeContext API yielded only metadata counts (37 feats), not actual feat data structures (names, GUIDs, descriptions).

**Symptoms:**
- `Ext.StaticData.GetCount("Feat")` returned 37
- `Ext.StaticData.GetAll("Feat")` returned metadata, not feat objects
- TypeContext traversal captured manager registration info only

## Root Cause

**TypeContext gives registration metadata structures, NOT actual manager instances.**

| Source | Count Offset | What It Contains |
|--------|--------------|------------------|
| TypeContext metadata | +0x00 | Registration count (metadata only) |
| Real FeatManager | +0x7C | Actual feat count with full data |

The ImmutableDataHeadmaster's TypeContext stores a linked list of TypeInfo entries for type registration, but these point to metadata structures, not the real manager instances used at runtime.

## Investigation Steps

### 1. Initial TypeContext Analysis
- Traversed `ImmutableDataHeadmaster.m_State` linked list
- Found TypeInfo entries with `manager_ptr` and `type_name`
- Captured metadata showing count=37 at offset +0x00
- **Result:** Metadata only, not usable feat data

### 2. Ghidra Decompilation
Decompiled `GetFeats` at `0x101b752b4`:
```c
// x1 = FeatManager* (real instance)
count = *(int*)(x1 + 0x7C);   // Feat count at +0x7C
array = *(Feat**)(x1 + 0x80); // Feat array at +0x80
```

### 3. Call Site Analysis
Found in `ApplyAndValidateLevelUp` at `0x1011f344c`:
```asm
1011f4c84: ldr x1,[x22, #0x130]    ; Load FeatManager from Environment+0x130
1011f4c88: add x0,sp,#0x3e0        ; Output buffer
1011f4c8c: bl 0x101b752b4          ; Call GetFeats
```

**Key Discovery:** FeatManager is at `Environment+0x130`, not from TypeContext.

### 4. Frida Verification
Created `tools/frida/capture_environment_featmgr.js` to verify:
- Hooked `ApplyAndValidateLevelUp` - captures Environment*
- Hooked `GetFeats` - captures FeatManager* in x1
- Confirmed count at +0x7C, array at +0x80

## Solution

### Working Approaches

**1. Direct Singleton Access**
- TypeInfo pointer at `0x1083f5528`
- Read directly without hooking

**2. Frida Interceptor (Recommended)**
```javascript
Interceptor.attach(getFeatsAddr, {
    onEnter: function(args) {
        var featMgr = args[1];  // x1 = FeatManager*
        var count = featMgr.add(0x7C).readU32();
        var array = featMgr.add(0x80).readPointer();
        // Process feat data...
    }
    // NO onLeave - function executes normally
});
```

**3. Environment Capture**
```javascript
Interceptor.attach(applyLevelUpAddr, {
    onEnter: function(args) {
        var env = args[0];  // x0 = Environment*
        var featMgr = env.add(0x130).readPointer();
        // Extract FeatManager from Environment
    }
});
```

### Why Dobby Hooks Failed

Dobby inline hooks corrupt ARM64 PC-relative instructions (ADRP+LDR patterns). When GetFeats was hooked with Dobby, the feat selection UI broke completely because:
- ADRP calculates page address relative to PC
- Trampoline moves code to different address
- Page offset no longer matches, causing wrong memory access

**Solution:** Use Frida Interceptor with onEnter-only (doesn't replace function).

## Data Structures

```
ImmutableDataHeadmaster (singleton via TypeContext)
  └─ m_State (+0x083c4a68): TypeInfo linked list head
       └─ TypeInfo for each manager type:
            +0x00: metadata_ptr (NOT real manager)
            +0x08: type_name_ptr
            +0x18: next TypeInfo*

Environment (passed as parameter)
  +0x130: FeatManager* (REAL instance)
           +0x7C: int32 count
           +0x80: Feat* array
                  Each Feat: 0x128 bytes (296 bytes)
                    +0x08: GUID part 1 (8 bytes)
                    +0x10: GUID part 2 (8 bytes)
```

## Function Addresses

| Function | Address | Purpose |
|----------|---------|---------|
| `FeatManager::GetFeats` | `0x101b752b4` | Receives FeatManager* in x1 |
| `GetAllFeats` | `0x10120b3e8` | Called during respec UI |
| `ApplyAndValidateLevelUp` | `0x1011f344c` | Loads FeatManager from env+0x130 |
| `RegisterType<FeatManager>` | `0x100c64b14` | TypeContext registration |

## Prevention

1. **Always verify offset assumptions** - TypeContext metadata != runtime data
2. **Use Frida for discovery** - Non-invasive, doesn't break game functions
3. **Document distinction** - Metadata structures vs real data structures
4. **Test hooks on non-critical functions first** - Avoid breaking core UI

## Related Documentation

- [ghidra/offsets/STATICDATA_MANAGERS.md](../../../ghidra/offsets/STATICDATA_MANAGERS.md)
- [tools/frida/capture_environment_featmgr.js](../../../tools/frida/capture_environment_featmgr.js)
- [docs/arm64/arm64-hooking-prevention.md](../../arm64/arm64-hooking-prevention.md)
- [GitHub Issue #40](https://github.com/tdimino/bg3se-macos/issues/40)

## Outcome

- **Issue #40:** ~60% complete - API surface works, returns metadata
- **Full data access:** Requires Environment capture implementation
- **Documentation:** Comprehensive offset and structure documentation created
- **Frida scripts:** Working capture scripts for runtime verification
