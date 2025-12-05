# feat: Implement FixedString Resolution for Stats System

## Overview

The macOS BG3 build uses **string interning** where FixedString is a 32-bit index into a GlobalStringTable, not a direct pointer. This is blocking the Stats API from retrieving stat names.

**Current State:**
- Stats array correctly found at RPGStats+0xC0 with 15,774 entries
- Element structures accessible with valid pointers
- FixedString Name at elem+0x20 = `0x20200011` (an INDEX, not a pointer)

**Goal:** Resolve FixedString indices to actual string values.

## Problem Statement

The FixedString index `0x20200011` decodes to:
```
subTableIdx = (id & 0x0F)        = 1      // bits 0-3: sub-table selector
bucketIdx   = (id >> 4) & 0xFFFF = 1      // bits 4-19: bucket index
entryIdx    = (id >> 20)         = 514    // bits 20+: entry within bucket
```

To resolve this to a string, we need access to `gGlobalStringTable`.

## Technical Approach

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GlobalStringTable Structure                   │
├─────────────────────────────────────────────────────────────────┤
│  GlobalStringTable** gGlobalStringTable (global pointer)         │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ GlobalStringTable                                        │    │
│  │   SubTable SubTables[11]  ◄── 11 sub-tables (idx 0-10)  │    │
│  │   MainTable Main                                         │    │
│  └─────────────────────────────────────────────────────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ SubTable                                                 │    │
│  │   uint8_t** Buckets      ◄── array of bucket pointers   │    │
│  │   uint32_t NumBuckets                                    │    │
│  │   uint32_t EntriesPerBucket                              │    │
│  │   uint64_t EntrySize     ◄── size of each entry         │    │
│  └─────────────────────────────────────────────────────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ StringEntry (at Buckets[bucketIdx] + entryIdx*EntrySize)│    │
│  │   +0x00: uint32_t Hash                                   │    │
│  │   +0x04: uint32_t RefCount                               │    │
│  │   +0x08: uint32_t Length                                 │    │
│  │   +0x0C: uint32_t Id                                     │    │
│  │   +0x10: uint64_t NextFreeIndex                          │    │
│  │   +0x18: char Str[]       ◄── actual string data        │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Phases

#### Phase 1: Find gGlobalStringTable via Ghidra

**Tasks:**
1. Search for string references to known stat names ("Longsword", "Weapon", etc.)
2. Find code that accesses these strings and trace back to GlobalStringTable
3. Identify the global pointer address (like we did for RPGStats at 0x89c5730)

**Ghidra Script Approach:**
```python
# ghidra/scripts/find_global_string_table.py
# Search for ADRP/LDR patterns that access a large table structure
# Look for code patterns similar to:
#   adrp x0, :pg_hi21:gGlobalStringTable
#   ldr  x0, [x0, :lo12:gGlobalStringTable]
#   ldr  x1, [x0, #subtable_offset]
```

**Alternative: Runtime Discovery:**
```c
// Scan for SubTable signature:
// - NumBuckets typically 0x1000-0x10000
// - EntriesPerBucket typically 0x100-0x1000
// - EntrySize typically 0x40-0x100
```

#### Phase 2: Implement SubTable Structure

**File: `src/strings/fixed_string.h`**
```c
#ifndef FIXED_STRING_H
#define FIXED_STRING_H

#include <stdint.h>
#include <stdbool.h>

// FixedString index decoding
#define FS_SUBTABLE_MASK     0x0F
#define FS_BUCKET_MASK       0xFFFF
#define FS_BUCKET_SHIFT      4
#define FS_ENTRY_SHIFT       20
#define FS_NULL_INDEX        0xFFFFFFFF

// StringEntry header (24 bytes before string data)
typedef struct {
    uint32_t Hash;
    uint32_t RefCount;
    uint32_t Length;
    uint32_t Id;
    uint64_t NextFreeIndex;
    // char Str[] follows
} StringEntryHeader;

#define STRING_ENTRY_HEADER_SIZE 0x18

// SubTable structure (offsets from BG3SE research)
typedef struct {
    uint8_t  _pad0[0x200];        // Element field_0[64]
    uint64_t LockCounter;          // +0x200
    uint8_t  _pad1[0x38];
    int32_t  TableIndex;           // +0x240 approx
    uint64_t EntrySize;            // +0x248 approx
    uint32_t EntriesPerBucket;     // +0x250 approx
    uint8_t  _pad2[0x28];
    uint32_t NumBuckets;           // +0x27C approx
    uint8_t  _pad3[0x38];
    uint8_t** Buckets;             // +0x2B8 approx - KEY FIELD
} SubTable;

// GlobalStringTable structure
typedef struct {
    SubTable SubTables[11];        // 11 sub-tables
    // MainTable follows
} GlobalStringTable;

// API
void fixed_string_init(void);
const char* fixed_string_resolve(uint32_t index);
bool fixed_string_is_valid(uint32_t index);

#endif
```

#### Phase 3: Implement Resolution Logic

**File: `src/strings/fixed_string.c`**
```c
#include "fixed_string.h"
#include "logging.h"
#include <mach/mach.h>

static GlobalStringTable** g_pGlobalStringTable = NULL;
static bool g_Initialized = false;

// Ghidra offset for gGlobalStringTable (TBD from analysis)
#define GHIDRA_OFFSET_GLOBAL_STRING_TABLE 0x????????ULL

void fixed_string_init(void) {
    // Similar pattern to stats_manager_init()
    // Find main binary base, add offset
    // Store pointer to g_pGlobalStringTable
}

const char* fixed_string_resolve(uint32_t index) {
    if (index == FS_NULL_INDEX) return NULL;
    if (!g_pGlobalStringTable || !*g_pGlobalStringTable) return NULL;

    GlobalStringTable* gst = *g_pGlobalStringTable;

    // Decode index
    uint32_t subTableIdx = index & FS_SUBTABLE_MASK;
    uint32_t bucketIdx = (index >> FS_BUCKET_SHIFT) & FS_BUCKET_MASK;
    uint32_t entryIdx = index >> FS_ENTRY_SHIFT;

    // Bounds check
    if (subTableIdx >= 11) return NULL;

    SubTable* subTable = &gst->SubTables[subTableIdx];

    // Read SubTable fields safely
    uint32_t numBuckets = 0, entriesPerBucket = 0;
    uint64_t entrySize = 0;
    uint8_t** buckets = NULL;

    safe_read_u32(&subTable->NumBuckets, &numBuckets);
    safe_read_u32(&subTable->EntriesPerBucket, &entriesPerBucket);
    safe_read_u64(&subTable->EntrySize, &entrySize);
    safe_read_ptr(&subTable->Buckets, (void**)&buckets);

    if (bucketIdx >= numBuckets || entryIdx >= entriesPerBucket) {
        return NULL;
    }

    // Calculate entry address
    uint8_t* bucket = NULL;
    safe_read_ptr(&buckets[bucketIdx], (void**)&bucket);
    if (!bucket) return NULL;

    uint8_t* entry = bucket + (entryIdx * entrySize);

    // String is at entry + 0x18 (after header)
    return (const char*)(entry + STRING_ENTRY_HEADER_SIZE);
}
```

#### Phase 4: Integrate with Stats Manager

**Update `src/stats/stats_manager.c`:**
```c
#include "strings/fixed_string.h"

const char* stats_get_object_name(void* object) {
    if (!object) return NULL;

    uint32_t name_index = 0;
    if (!safe_read_u32((char*)object + OBJECT_OFFSET_NAME, &name_index)) {
        return NULL;
    }

    return fixed_string_resolve(name_index);
}
```

#### Phase 5: Update Lua Bindings

**Update `src/lua/lua_stats.c`:**
```c
static int lua_stats_get_all_stats(lua_State *L) {
    // ... existing code to get objects array ...

    for (int i = 0; i < count; i++) {
        void* obj = objects[i];
        const char* name = stats_get_object_name(obj);
        if (name) {
            lua_pushstring(L, name);
            lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        }
    }

    return 1;
}
```

## Alternative Approaches Considered

### 1. Hook ls__FixedString__GetString
**Pros:** Uses game's own resolution logic, guaranteed correct
**Cons:** Requires finding function address via pattern scanning, ARM64 patterns differ from x64

### 2. Direct GlobalStringTable Access (Chosen)
**Pros:** No function hooking, simpler once structure is understood
**Cons:** Requires finding global pointer and SubTable field offsets

### 3. Memory Scanning for Known Strings
**Pros:** Could find strings without understanding full structure
**Cons:** Unreliable, wouldn't work for all strings

## Acceptance Criteria

### Functional Requirements
- [ ] Find gGlobalStringTable offset via Ghidra analysis
- [ ] Implement SubTable structure with correct ARM64 offsets
- [ ] `fixed_string_resolve(0x20200011)` returns actual stat name
- [ ] `Ext.Stats.GetAllStats()` returns array of stat names
- [ ] `Ext.Stats.Get("Longsword")` finds stat by name

### Non-Functional Requirements
- [ ] Resolution is fast (<1ms per lookup)
- [ ] Safe memory access (no crashes on bad indices)
- [ ] Thread-safe reads (no locking needed for read-only)

### Quality Gates
- [ ] All existing stats tests pass
- [ ] No crashes on save load with stats access
- [ ] Code follows existing module patterns

## Files to Create/Modify

### New Files
- `src/strings/fixed_string.h` - FixedString API header
- `src/strings/fixed_string.c` - Resolution implementation
- `ghidra/scripts/find_global_string_table.py` - Ghidra search script
- `ghidra/offsets/STRINGS.md` - Document findings

### Modified Files
- `src/stats/stats_manager.c` - Add name resolution
- `src/stats/stats_manager.h` - Export name function
- `src/lua/lua_stats.c` - Use names in Lua API
- `CMakeLists.txt` - Add new source files
- `src/injector/main.c` - Initialize fixed_string module

## Dependencies

- Ghidra analysis to find gGlobalStringTable offset
- Verification of SubTable field offsets on ARM64 (may differ from x64)
- Testing with multiple FixedString indices to validate

## Risk Analysis

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| SubTable offsets differ on ARM64 | High | High | Probe multiple offsets at runtime |
| gGlobalStringTable not exported | Medium | High | Pattern scan for ADRP/LDR sequences |
| Entry size varies per sub-table | Low | Medium | Read EntrySize dynamically |

## References

### Internal
- `src/stats/stats_manager.c:297-330` - Current probing code showing FixedString issue
- `/Users/tomdimino/Desktop/Programming/bg3se/CoreLib/Base/BaseString.h:319-371` - GlobalStringTable structure
- `/Users/tomdimino/Desktop/Programming/bg3se/CoreLib/Base/BaseString.inl:109-131` - FindEntry algorithm

### External
- BG3SE Windows implementation uses pattern scanning via BinaryMappings.xml
- ARM64 uses ADRP+LDR for global pointer access (vs x64 RIP-relative MOV)
