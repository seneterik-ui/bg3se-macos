# Stats System Offsets

## RPGStats Singleton

**Symbol:** `RPGStats::m_ptr` (not exported, use dlsym or Ghidra offset)
**Offset from binary base:** `0x89c5730`

```c
// Runtime address calculation
void *rpgstats_ptr = (void*)((uintptr_t)binary_base + 0x89c5730);
RPGStats *stats = *(RPGStats **)rpgstats_ptr;
```

## RPGStats Internal Structure

Based on runtime probing (2025-12-03):

| Offset | Type | Description | Status |
|--------|------|-------------|--------|
| `0x030` | DynamicArray | buf=0x..., cap=128, size=112 | Unknown |
| `0x058` | DynamicArray | buf=0x..., cap=12843136, size=24576 | Unknown |
| `0x090` | CNamedElementManager | ModifierLists (estimated) | Needs verification |
| `0x0C0` | CNamedElementManager | **Objects** - 15,774 stat entries | ✅ VERIFIED |
| `0x0E0` | DynamicArray | cap=16384, size=15774 | Parallel array |
| `0x0F0` | DynamicArray | cap=16384, size=15774 | Parallel array |
| `0x120` | DynamicArray | buf=0x..., cap=2048, size=1688 | Unknown |
| `0x140` | DynamicArray | cap=2048, size=1688 | Unknown |
| `0x150` | DynamicArray | cap=2048, size=1688 | Unknown |
| `0x180` | DynamicArray | buf=0x..., cap=2048, size=1512 | Unknown |

**Key Finding:** Objects manager is at offset `0xC0` (not `0x88` as previously thought).

## CNamedElementManager Structure

```c
// Template: CNamedElementManager<T>
struct CNamedElementManager {
    void *vtable;           // +0x00
    DynamicArray Values;    // +0x08: buf_[8] + capacity_[4] + size_[4]
    // ...
};

struct DynamicArray {
    void *buf_;             // +0x00: Pointer to element array
    uint32_t capacity_;     // +0x08: Maximum elements
    uint32_t size_;         // +0x0C: Current count
};
```

## Stats Object Structure

Each stat object (element in Objects array) has this layout:

| Offset | Type | Description | Notes |
|--------|------|-------------|-------|
| `+0x00` | void* | Unknown pointer | Points to data |
| `+0x08` | void* | Unknown pointer | |
| `+0x10` | void* | Unknown pointer | |
| `+0x18` | void* | Unknown pointer | |
| `+0x20` | uint32_t | **Name** (FixedString index) | e.g., 0x20200011 |
| `+0x28` | void* | Unknown pointer | |
| `+0x30` | uint64_t | Unknown value | e.g., 5 |
| `+0x38` | void* | Unknown pointer | |

**The Name at +0x20 is a FixedString index** that needs GlobalStringTable for resolution.

## Verified Log Output

```
[Stats] Using Objects manager at: 0x11c023ac0 (RPGStats+0xc0)
[Stats]   Values.buf_: 0x530208000
[Stats]   Values.capacity_: 16384, Values.size_: 15774
[Stats] Stats Objects count: 15774
[Stats] First stat: "<FSIdx:0x20200011>"  ← Needs GlobalStringTable
[Stats] Stats system READY with 15774 entries
```

## Implementation Notes

1. **Objects at 0xC0** was discovered by probing all CNamedElementManager candidates and finding the one with 15,774 entries (matching expected stat count).

2. **FixedString Resolution Pending**: The Name field contains a FixedString index. Until GlobalStringTable is found, we display as `<FSIdx:0xXXXXXXXX>`.

3. **Expected FixedString values** after resolution:
   - First stat (0x20200011) should be a weapon name like "Longsword"
   - Index decodes to: SubTable[1], Bucket[512], Entry[514]

## Related Files

- `/src/stats/stats_manager.c` - Stats system implementation
- `/src/stats/stats_manager.h` - Header file
- `/src/strings/fixed_string.c` - FixedString resolution (awaiting GlobalStringTable)
