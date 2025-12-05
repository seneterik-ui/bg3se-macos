# GlobalStringTable Discovery - ARM64 macOS

## Current Status: Incomplete

The GlobalStringTable is needed to resolve FixedString indices (like `0x20200011`) to actual string values (like `"Strength"`).

## What We Know

### FixedString Encoding (ARM64)
On macOS ARM64, FixedString is a 32-bit index, not a pointer:
```
uint32_t index = 0x20200011
subTableIdx = index & 0x0F          = 1  (0-10 for 11 subtables)
bucketIdx   = (index >> 4) & 0xFFFF = 0x2001
entryIdx    = index >> 20           = 0x20
```

### StringEntry Structure (Windows Reference)
From BG3SE Windows code, StringEntry layout is:
```c
struct StringEntry {
    uint32_t Hash;          // +0x00
    uint32_t RefCount;      // +0x04
    uint32_t Length;        // +0x08
    uint32_t Id;            // +0x0C (FixedString index)
    uint32_t NextFreeIndex; // +0x10
    uint32_t Reserved;      // +0x14
    char     String[];      // +0x18 (24 bytes header)
};
```

### SubTable Structure (Windows Reference)
```c
struct SubTable {
    uint32_t NumBuckets;        // +0x00 on Windows
    uint32_t EntriesPerBucket;  // +0x04 on Windows
    uint64_t EntrySize;         // +0x08 on Windows
    void*    Buckets;           // +0x10 on Windows
    // ... other fields
};
```

**Note:** ARM64 offsets may differ due to alignment.

## Discovery Attempts

### 1. dlsym Lookup - FAILED
Symbol `_ZN8GlobalStringTable5m_ptrE` is not exported.

### 2. Reference-Based Discovery - PARTIALLY SUCCESSFUL
Searched for known strings ("Strength", "Dexterity", etc.) in `__DATA` section:
- Found "Strength" at `0x10cd3f34b`
- Found "Weapon" at `0x10d6e3348`

However, header validation failed. These strings are **literal string constants** in the binary, NOT GlobalStringTable entries.

**Key Insight:** GlobalStringTable entries are in **heap memory**, not the binary `__DATA` section.

### 3. Exhaustive __DATA Probe - FAILED
Scanned 64MB of `__DATA` section looking for SubTable structure signatures. Found 0 candidates.

## Next Steps

### Option A: Heap Memory Scanning
The GlobalStringTable is allocated on the heap. We need to:
1. Find a pointer TO the GlobalStringTable (likely in a singleton pattern)
2. Possible locations:
   - A static global pointer in `__DATA` that points to heap
   - Referenced from RPGStats or another known singleton
   - Passed to a known function we can hook

### Option B: Function Hooking
Hook a function that uses FixedString resolution:
- `FixedString::GetString()`
- `FixedString::CreateFromRaw()`
- Capture the GlobalStringTable pointer when the function is called

### Option C: Ghidra Analysis
Find the GlobalStringTable via static analysis:
1. Search for XREF to "Strength" string
2. Find the code that creates FixedString("Strength")
3. Trace the GlobalStringTable access pattern

## Related Files
- `src/strings/fixed_string.c` - Current implementation
- `src/strings/fixed_string.h` - API declarations
- `src/stats/stats_manager.c` - Uses `fixed_string_resolve()`

## RPGStats Integration Status
- RPGStats pointer: FOUND at offset `0x89c5730`
- Stats Objects count: 15,774 entries
- Stats names: Showing as `<FSIdx:0x...>` (FixedString not resolved)
- `Ext.Stats.GetAll()`: Returns empty because type comparison fails without string resolution
