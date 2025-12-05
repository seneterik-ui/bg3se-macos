# feat: Implement FixedString Resolution via Runtime Discovery

## Overview

The macOS BG3 build uses **string interning** where FixedString is a 32-bit index into a GlobalStringTable, not a direct pointer. Runtime probing confirmed:
- Stats array at RPGStats+0xC0 has 15,774 valid entries
- Element Name at elem+0x20 = `0x20200011` (an INDEX, not a pointer)

This plan implements runtime discovery of GlobalStringTable to resolve FixedString indices to actual string values.

## Problem Statement

**Current State:**
- `stats_manager.c` successfully finds the Objects array at offset 0xC0 with size=15774
- Element structures are accessible with valid pointers
- FixedString Name at elem+0x20 = `0x20200011` - this is an INDEX into GlobalStringTable

**Root Cause:**
FixedString is NOT a `const char*` pointer. It's a 32-bit index that encodes:
```
subTableIdx = (id & 0x0F)        = 1      // bits 0-3: sub-table selector (0-10)
bucketIdx   = (id >> 4) & 0xFFFF = 1      // bits 4-19: bucket index
entryIdx    = (id >> 20)         = 514    // bits 20+: entry within bucket
```

## Technical Approach

### Architecture: GlobalStringTable Structure

From BG3SE reference (`CoreLib/Base/BaseString.h:319-371`):

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
│  │   MainTable Main          ◄── at offset 0xC600          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### SubTable Structure (Windows x64 offsets from BG3SE)

```c
struct SubTable {
    Element field_0[64];        // +0x000: 64 elements × 64 bytes = 4096 bytes
    uint64_t LockCounter;       // +0x1000
    uint64_t _Pad1[7];          // +0x1008
    uint64_t LockEvent;         // +0x1040
    uint64_t _Pad2[7];          // +0x1048
    int32_t TableIndex;         // +0x1080
    uint64_t EntrySize;         // +0x1088 ◄── Size of each entry
    uint32_t EntriesPerBucket;  // +0x1090 ◄── Max entries per bucket
    uint64_t _Pad3[5];          // +0x1094
    uint32_t NumBuckets;        // +0x10C0 ◄── Number of buckets
    uint64_t _Pad4[7];          // +0x10C4
    uint32_t field_1100;        // +0x1100
    uint64_t _Pad5[7];          // +0x1104
    uint8_t** Buckets;          // +0x1140 ◄── KEY: Pointer to bucket array
    uint64_t _Pad6[7];          // +0x1148
    // ... more fields
};
// Total per SubTable: ~0x1200 bytes (4.5 KB)
```

### StringEntry Header (from `BaseString.h:111-118`)

```c
struct Header {
    uint32_t Hash;           // +0x00
    uint32_t RefCount;       // +0x04
    uint32_t Length;         // +0x08
    uint32_t Id;             // +0x0C
    uint64_t NextFreeIndex;  // +0x10
    // char Str[] follows at +0x18
};
#define HEADER_SIZE 0x18  // 24 bytes
```

### Resolution Algorithm (from `BaseString.inl:109-131`)

```c
const char* resolve_fixed_string(uint32_t id) {
    if (id == 0xFFFFFFFF) return NULL;  // NullIndex

    GlobalStringTable* gst = *gGlobalStringTable;
    if (!gst) return NULL;

    // Decode index
    uint32_t subTableIdx = id & 0x0F;
    uint32_t bucketIdx = (id >> 4) & 0xFFFF;
    uint32_t entryIdx = id >> 20;

    // Bounds check
    if (subTableIdx >= 11) return NULL;

    SubTable* subTable = &gst->SubTables[subTableIdx];

    if (bucketIdx >= subTable->NumBuckets) return NULL;
    if (entryIdx >= subTable->EntriesPerBucket) return NULL;

    // Calculate entry address
    uint8_t* entry = subTable->Buckets[bucketIdx] + (entryIdx * subTable->EntrySize);

    // String is at entry + 0x18 (after header)
    return (const char*)(entry + HEADER_SIZE);
}
```

## Implementation Phases

### Phase 1: Runtime Discovery of gGlobalStringTable

**Challenge:** The `ls__gGlobalStringTable` symbol is NOT exported on macOS.

**Approach: Pattern Scanning via String References**

On Windows x64 (from `BinaryMappings.xml`):
```asm
mov rcx, cs:ls__gGlobalStringTable
add rcx, 0xC600h  ; MainTable offset
```

On ARM64 macOS, this becomes ADRP + LDR:
```asm
adrp x0, :pg_hi21:gGlobalStringTable
ldr  x0, [x0, :lo12:gGlobalStringTable]
```

**Discovery Strategy:**

1. **Search for known stat name in memory** (e.g., "Longsword")
2. **Scan backwards** from the string to find the Header structure
3. **Validate Header** by checking RefCount < 0x1000000, Length < EntrySize
4. **Calculate SubTable base** from entry address and EntrySize
5. **Walk back** to find GlobalStringTable start (11 SubTables before MainTable)

**Alternative: dlsym attempt**
```c
void* handle = dlopen(NULL, RTLD_NOW);
void** gst = dlsym(handle, "_ZN2ls19gGlobalStringTableE");
// Or try pattern: "_ZN2ls*GlobalStringTable*"
```

### Phase 2: Create Fixed String Module

**File: `src/strings/fixed_string.h`**

```c
#ifndef FIXED_STRING_H
#define FIXED_STRING_H

#include <stdint.h>
#include <stdbool.h>

// FixedString index constants
#define FS_NULL_INDEX        0xFFFFFFFF
#define FS_SUBTABLE_MASK     0x0F
#define FS_BUCKET_MASK       0xFFFF
#define FS_BUCKET_SHIFT      4
#define FS_ENTRY_SHIFT       20

// StringEntry header (24 bytes before string data)
#define STRING_ENTRY_HEADER_SIZE 0x18

// SubTable field offsets (Windows x64 - may need adjustment for ARM64)
#define SUBTABLE_OFFSET_ENTRY_SIZE       0x1088
#define SUBTABLE_OFFSET_ENTRIES_PER_BKT  0x1090
#define SUBTABLE_OFFSET_NUM_BUCKETS      0x10C0
#define SUBTABLE_OFFSET_BUCKETS          0x1140
#define SUBTABLE_SIZE                    0x1200

// GlobalStringTable layout
#define GST_NUM_SUBTABLES                11
#define GST_OFFSET_MAINTABLE             0xC600

// API
void fixed_string_init(void* main_binary_base);
const char* fixed_string_resolve(uint32_t index);
bool fixed_string_is_valid(uint32_t index);
bool fixed_string_is_ready(void);

// Debug
void fixed_string_dump_subtable_info(int subtable_idx);

#endif
```

**File: `src/strings/fixed_string.c`**

```c
#include "fixed_string.h"
#include "logging.h"
#include <mach/mach.h>
#include <dlfcn.h>

static void** g_pGlobalStringTable = NULL;
static void* g_MainBinaryBase = NULL;
static bool g_Initialized = false;

// Safe memory reading (from stats_manager.c pattern)
static bool safe_read_ptr(void* addr, void** out) { /* ... */ }
static bool safe_read_u32(void* addr, uint32_t* out) { /* ... */ }
static bool safe_read_u64(void* addr, uint64_t* out) { /* ... */ }

void fixed_string_init(void* main_binary_base) {
    g_MainBinaryBase = main_binary_base;

    // Try dlsym first
    void* handle = dlopen(NULL, RTLD_NOW);
    if (handle) {
        // Try mangled C++ name
        g_pGlobalStringTable = dlsym(handle, "_ZN2ls19gGlobalStringTableE");
        if (!g_pGlobalStringTable) {
            // Try alternate patterns
            g_pGlobalStringTable = dlsym(handle, "__ZN2ls19gGlobalStringTableE");
        }
    }

    if (g_pGlobalStringTable) {
        log_message("[FixedString] Found via dlsym: %p", g_pGlobalStringTable);
    } else {
        log_message("[FixedString] dlsym failed, will use runtime discovery");
    }

    g_Initialized = true;
}

const char* fixed_string_resolve(uint32_t index) {
    if (index == FS_NULL_INDEX) return NULL;
    if (!g_pGlobalStringTable || !*g_pGlobalStringTable) return NULL;

    void* gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) return NULL;

    // Decode index
    uint32_t subTableIdx = index & FS_SUBTABLE_MASK;
    uint32_t bucketIdx = (index >> FS_BUCKET_SHIFT) & FS_BUCKET_MASK;
    uint32_t entryIdx = index >> FS_ENTRY_SHIFT;

    // Bounds check
    if (subTableIdx >= GST_NUM_SUBTABLES) return NULL;

    // Calculate SubTable address
    void* subTable = (char*)gst + (subTableIdx * SUBTABLE_SIZE);

    // Read SubTable fields
    uint32_t numBuckets = 0, entriesPerBucket = 0;
    uint64_t entrySize = 0;
    void* buckets = NULL;

    safe_read_u32((char*)subTable + SUBTABLE_OFFSET_NUM_BUCKETS, &numBuckets);
    safe_read_u32((char*)subTable + SUBTABLE_OFFSET_ENTRIES_PER_BKT, &entriesPerBucket);
    safe_read_u64((char*)subTable + SUBTABLE_OFFSET_ENTRY_SIZE, &entrySize);
    safe_read_ptr((char*)subTable + SUBTABLE_OFFSET_BUCKETS, &buckets);

    if (!buckets || bucketIdx >= numBuckets || entryIdx >= entriesPerBucket) {
        return NULL;
    }

    // Get bucket pointer
    void* bucket = NULL;
    safe_read_ptr((char*)buckets + bucketIdx * sizeof(void*), &bucket);
    if (!bucket) return NULL;

    // Calculate entry address
    void* entry = (char*)bucket + (entryIdx * entrySize);

    // String is at entry + 0x18
    return (const char*)((char*)entry + STRING_ENTRY_HEADER_SIZE);
}
```

### Phase 3: Runtime SubTable Offset Discovery

**Problem:** SubTable offsets may differ on ARM64 due to alignment.

**Solution:** Probe at runtime by:
1. Finding a known valid FixedString (e.g., from stats "Longsword")
2. Searching for the string in memory
3. Working backwards to determine actual SubTable field positions

**Probing Code:**

```c
void probe_subtable_offsets(void* subtable_base) {
    // Try different offsets for Buckets pointer
    int bucket_offsets[] = {0x1140, 0x1180, 0x11C0, 0x2B8};

    for (int i = 0; i < sizeof(bucket_offsets)/sizeof(int); i++) {
        void* buckets = NULL;
        if (safe_read_ptr((char*)subtable_base + bucket_offsets[i], &buckets)) {
            // Check if this looks like a valid bucket array
            void* first_bucket = NULL;
            if (safe_read_ptr(buckets, &first_bucket) && first_bucket) {
                // Try to read a string at first_bucket + 0x18
                // If valid, we found the Buckets offset
            }
        }
    }
}
```

### Phase 4: Integrate with Stats Manager

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

### Phase 5: Update Lua Bindings

**Update `src/lua/lua_stats.c`:**

```c
static int lua_stats_get_all_stats(lua_State *L) {
    // Get Objects manager
    void* mgr = get_objects_manager();
    if (!mgr) {
        lua_newtable(L);
        return 1;
    }

    int count = get_manager_count(mgr);
    lua_createtable(L, count, 0);

    int result_idx = 1;
    for (int i = 0; i < count; i++) {
        void* obj = get_manager_element(mgr, i);
        if (obj) {
            const char* name = stats_get_object_name(obj);
            if (name && name[0]) {
                lua_pushstring(L, name);
                lua_rawseti(L, -2, result_idx++);
            }
        }
    }

    return 1;
}
```

## Acceptance Criteria

### Functional Requirements
- [ ] `fixed_string_resolve(0x20200011)` returns actual stat name string
- [ ] `Ext.Stats.GetAllStats()` returns array of 15,774 stat names
- [ ] `Ext.Stats.Get("Longsword")` finds stat by name lookup
- [ ] Works across game updates (runtime discovery, not hardcoded offsets)

### Non-Functional Requirements
- [ ] Resolution is fast (<1ms per lookup)
- [ ] Safe memory access (no crashes on invalid indices)
- [ ] Thread-safe reads (no locking needed for read-only access)
- [ ] Graceful degradation if GlobalStringTable not found

### Quality Gates
- [ ] No crashes on save load with stats access
- [ ] All existing stats tests pass
- [ ] Works on both Intel (Rosetta) and Apple Silicon

## Files to Create/Modify

### New Files
- `src/strings/fixed_string.h` - FixedString API header
- `src/strings/fixed_string.c` - Resolution implementation

### Modified Files
- `src/stats/stats_manager.c` - Integrate fixed_string_resolve()
- `src/stats/stats_manager.h` - Export stats_get_object_name()
- `src/lua/lua_stats.c` - Use names in Lua API
- `CMakeLists.txt` - Add new source files
- `src/injector/main.c` - Initialize fixed_string module

## Risk Analysis

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| SubTable offsets differ on ARM64 | High | High | Runtime probing with multiple offset candidates |
| gGlobalStringTable not exported | High | High | Pattern scan or search from known strings |
| Entry size varies per sub-table | Low | Medium | Read EntrySize dynamically per SubTable |
| Alignment differs from Windows | Medium | Medium | Probe structure at runtime |

## References

### Internal (BG3SE Windows Reference)
- `CoreLib/Base/BaseString.h:111-118` - Header structure (24 bytes)
- `CoreLib/Base/BaseString.h:326-352` - SubTable structure
- `CoreLib/Base/BaseString.h:319-371` - GlobalStringTable layout
- `CoreLib/Base/BaseString.inl:109-131` - FindEntry algorithm
- `BinaryMappings.xml:40-46` - Pattern for ls__gGlobalStringTable + offset 0xC600

### External Research
- ARM64 ADRP+LDR patterns for global variable access
- macOS Mach-O memory scanning techniques
- dlsym for C++ mangled symbol lookup
