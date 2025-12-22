# Pattern: Metadata vs Runtime Data Structures

**Category:** reverse-engineering
**Discovered:** 2025-12-20
**Issue:** #40 (Ext.StaticData.GetAll returning 1 instead of 41)

## The Pattern

When reverse engineering game systems that manage large datasets, you often encounter **two distinct structures** accessible from the same entry point:

| Layer | Purpose | Availability | Contains |
|-------|---------|--------------|----------|
| **Metadata Layer** | Type registration, system bookkeeping | Always available | Counts, type names, registration info |
| **Runtime Layer** | Actual user-facing data | Session-scoped | Real entries for iteration/access |

Both may share the same offset patterns but have **completely different semantics**.

## Case Study: Issue #40

### The Bug

`Ext.StaticData.GetAll("Feat")` returned only 1 item instead of 41 feats.

### Root Cause

Two structures both had fields at +0x7C (count) and +0x80 (array):

| Structure | Count at +0x7C | Array at +0x80 | Semantics |
|-----------|----------------|----------------|-----------|
| **TypeContext Metadata** | Keys.size_ (37) | Values.buf_ (pointer array) | HashMap registration |
| **Session FeatManager** | int32 count (41) | Feat* (flat array, 0x128 each) | Actual feat data |

The code probed TypeContext metadata looking for the Session FeatManager pattern, finding an unrelated structure with count=1.

### The Fix

1. Recognize TypeContext provides **metadata only**
2. Capture real FeatManager via **GetFeats hook** when feat window opens
3. Use real manager for iteration, metadata for type queries

## Detection Checklist

Use this when you suspect a metadata/data split:

```
□ Found a manager with unexpectedly few entries?
□ Count field matches documentation, but iteration yields fewer?
□ Same offsets appear in multiple contexts with different values?
□ Structure has self-referential pointers or duplicated counts?
□ Data only appears during specific game states (character creation, etc.)?
```

If multiple boxes checked → likely metadata/data split.

## Structural Signatures

### Metadata Characteristics

- Count duplicated at multiple offsets (+0x00 AND +0x90)
- Self-referential pointers (ptr at +0x80 points back to +0x60)
- Type name strings embedded
- Non-contiguous memory layout (heap pointers scattered)
- Available before session starts

### Runtime Data Characteristics

- Single count field for array bounds
- Flat contiguous array layout
- Entry size describes individual elements
- Direct iteration without pointer chasing
- Only available during active session

## Validation Test

```c
// Quick test to distinguish metadata from data
bool is_flat_array(void* ptr, int count, int entry_size) {
    // If count * entry_size roughly matches memory span, it's a flat array
    void* first = *(void**)(ptr + ARRAY_OFFSET);
    void* computed_end = first + (count * entry_size);

    // Try reading last entry - if valid, likely flat array
    return safe_memory_read(computed_end - entry_size, entry_size);
}

bool is_pointer_array(void* ptr, int count) {
    // Each entry is a pointer to elsewhere
    void** array = *(void***)(ptr + ARRAY_OFFSET);
    for (int i = 0; i < min(count, 3); i++) {
        if (!is_valid_heap_pointer(array[i])) return false;
    }
    return true;
}
```

## Code Pattern: Dual-Source Arrays

When you need both metadata and runtime access:

```c
static struct {
    void* managers[TYPE_COUNT];        // Metadata (always available)
    void* real_managers[TYPE_COUNT];   // Runtime (session-scoped)
} g_state;

// For type queries → use managers[]
bool has_type(int type) {
    return g_state.managers[type] != NULL;
}

// For data iteration → prefer real_managers[], fall back to managers[]
void* get_manager_for_iteration(int type) {
    if (g_state.real_managers[type])
        return g_state.real_managers[type];
    return g_state.managers[type];
}
```

## Code Pattern: Config Table

Centralize offsets for easy verification:

```c
typedef struct {
    int count_offset;    // Where count lives
    int array_offset;    // Where array pointer lives
    int entry_size;      // Size of each entry (0 if pointer array)
    int name_offset;     // Name field within entry
    bool is_pointer_array;  // true = array of pointers, false = flat
} ManagerConfig;

static const ManagerConfig configs[] = {
    [TYPE_FEAT] = { 0x7C, 0x80, 0x128, 0x18, false },
    [TYPE_RACE] = { 0x7C, 0x80, 0x98,  0x10, false },
    // ...
};
```

## Prevention: Confusion Test

Add this to catch metadata/data mismatches early:

```c
void validate_manager(int type, void* manager) {
    int meta_count = get_metadata_count(type);
    int iter_count = 0;

    void** entries = get_all_entries(type, manager);
    while (entries && entries[iter_count]) iter_count++;

    if (meta_count != iter_count) {
        log_warning("Type %d: metadata=%d, iteration=%d - possible split!",
                    type, meta_count, iter_count);
    }
}
```

## Related Files

- `src/staticdata/staticdata_manager.c` - Dual-source implementation
- `ghidra/offsets/STATICDATA.md` - Full offset documentation
- `docs/solutions/reverse-engineering/staticdata-featmanager-discovery.md` - Initial discovery

## Key Insight

> Just because two structures have the same field offsets doesn't mean they contain the same data. Always verify which layer you're accessing.
