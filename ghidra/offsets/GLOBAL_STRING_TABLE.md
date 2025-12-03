# GlobalStringTable Offset Discovery

## Current Status: PENDING DISCOVERY

The `GlobalStringTable` offset has NOT been found yet. This document tracks the investigation.

## What GlobalStringTable Does

On macOS ARM64, `FixedString` is a 32-bit index into GlobalStringTable (not a direct pointer as on Windows x86-64).

**FixedString Index Encoding:**
```
subTableIdx = id & 0x0F                    // SubTable index (0-10)
bucketIdx   = (id >> 4) & 0xFFFF           // Bucket index within SubTable
entryIdx    = id >> 20                     // Entry index within Bucket
```

**Example:** `0x20200011` decodes as:
- `subTableIdx = 1` (11 SubTables total)
- `bucketIdx = 512`
- `entryIdx = 514`

## GlobalStringTable Structure (from Windows bg3se)

From `BG3Extender/CoreLib/Base/BaseString.h`:

```cpp
struct GlobalStringTable {
    SubTable SubTables[11];   // 11 SubTables, ~0x1200 bytes each
    MainTable Main;           // At offset 0xC600
};

struct SubTable {
    Element field_0[64];           // +0x0000: 4096 bytes
    // ... padding ...
    int32_t TableIndex;            // +0x1080
    uint64_t EntrySize;            // +0x1088
    uint32_t EntriesPerBucket;     // +0x1090
    // ... padding ...
    uint32_t NumBuckets;           // +0x10C0
    // ... padding ...
    uint8_t** Buckets;             // +0x1140  ← Key offset!
};

struct StringEntry {
    uint64_t Hash;                 // +0x00
    int32_t RefCount;              // +0x08
    int32_t Length;                // +0x0C
    uint32_t Id;                   // +0x10
    uint32_t NextFreeIndex;        // +0x14
    char Str[];                    // +0x18 (24 bytes after start)
};
```

## Key Offsets

| Offset | Description | Notes |
|--------|-------------|-------|
| `0x1088` | SubTable.EntrySize | Entry stride in bytes |
| `0x1090` | SubTable.EntriesPerBucket | Entries per bucket |
| `0x10C0` | SubTable.NumBuckets | Number of buckets |
| `0x1140` | SubTable.Buckets | Pointer array to bucket data |
| `0xC600` | MainTable offset | 50688 bytes from start |
| `0x18` (24) | StringEntry header size | Bytes before string data |

## How Windows BG3SE Finds GlobalStringTable

From `BinaryMappings.xml`:
```xml
<!-- Pattern for x86-64 -->
48 8b 0d ?? ?? ?? ?? // mov rcx, cs:ls__gGlobalStringTable
48 81 c1 00 c6 00 00 // add rcx, 0C600h  (MainTable offset)
```

The symbol `ls__gGlobalStringTable` is a **double pointer** (`GlobalStringTable**`).

## ARM64 Differences

On ARM64, large immediates (like 0xC600) cannot be used directly in ADD instructions. Instead:
1. ADRP loads page-aligned address
2. LDR/ADD adds offset to get exact address
3. LDR dereferences the pointer

**Pattern to find:** Look for functions using offset `0x1140` (Buckets) that also:
1. Load a global pointer via ADRP+LDR
2. Dereference it to get SubTable
3. Access Buckets at +0x1140

## Ghidra Analysis Findings

### Functions Using 0x1140 Offset (Buckets)

These functions access `SubTable.Buckets`, confirming the offset is correct:
```
__ZN3gui17ViewModelProvider22UpdateDamageBoostsFlagEN3ecs9EntityRefE
  - ldr x24,[x23, #0x1140] at 102988878

__ZN3gui17ViewModelProvider21AddToShowActiveSearchE...
  - ldr x28,[x22, #0x1140] at 102999bb4
```

### Memory Layout

```
__DATA section: 0x108970000 - 0x108af7fff (1.5MB)
RPGStats::m_ptr offset: 0x89c5730 from base
GlobalStringTable: UNKNOWN (likely in same __DATA region)
```

### String References Found

| Address | String | Notes |
|---------|--------|-------|
| `0x107d59a26` | `FixedString` | RTTI type info |
| `0x107b7126c` | `FIXEDSTRING` | Osiris type marker |
| `0x107d325c3` | `ls::StringView ls::GetTypeName() [T = ls::FixedString]` | Template instantiation |
| `0x108e15b6a` | `StaticFixedStringRegistry` | Registry for static FixedStrings |

### No Direct 0xC600 Found

Searched 21,945,844 instructions - no `add` with `0xC600` found. ARM64 uses different patterns.

## Next Steps

1. **Trace from 0x1140 accesses**: Find what global pointer is loaded before 0x1140 is used
2. **Analyze StaticFixedStringRegistry**: Functions using this may reveal GST location
3. **Runtime probing**: Probe memory near RPGStats (0x89c5730) for GlobalStringTable signature
4. **String XREF analysis**: Find code referencing "FixedString" string, trace globals

## Runtime Discovery Alternative

If Ghidra analysis fails, we can probe at runtime:
1. Scan __DATA section for structures with:
   - Size ~0xC600 + sizeof(MainTable)
   - Valid pointer at offset 0x1140 in first SubTable
   - NumBuckets at offset 0x10C0 in range [100, 10000]

2. Validate by:
   - Using known FixedString index (e.g., 0x20200011 from first stat)
   - Checking if resolved string makes sense

## Related Files

- `/src/strings/fixed_string.c` - Current implementation (awaiting offset)
- `/src/strings/fixed_string.h` - Header with resolution functions
- `/ghidra/scripts/find_arm64_global_string_table.py` - Search script
- `/ghidra/scripts/find_c600_offset.py` - MainTable offset search
- `/ghidra/scripts/trace_global_string_table.py` - Register tracing script
