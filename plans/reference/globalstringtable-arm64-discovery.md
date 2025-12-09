# GlobalStringTable ARM64 Discovery Plan

## Problem Summary

We need to find the GlobalStringTable to resolve FixedString indices (e.g., `0x20200011`) to actual stat names (e.g., "Strength"). The current runtime probing found **0 candidates** despite scanning 64MB of the __DATA section.

**Root Cause**: The ARM64 macOS SubTable structure has different offsets than Windows x64 due to:
- No `CRITICAL_SECTION` (replaced by `pthread_mutex_t` - 64 bytes vs ~40 bytes)
- No cache-line padding (`_Pad` arrays removed by compiler)
- Potential different Element[64] array alignment

## Current State

### What Works
- RPGStats at offset `0x89c5730` - finds **15,774 stat entries**
- FixedString index encoding understood: `subTableIdx = id & 0x0F`, `bucketIdx = (id >> 4) & 0xFFFF`, `entryIdx = id >> 20`
- Safe memory probing via `mach_vm_read`

### What Doesn't Work
- Windows x64 offsets (Buckets=0x1140, NumBuckets=0x10C0, EntrySize=0x1088)
- __DATA section scanning with multiple offset guesses
- dlsym for GlobalStringTable symbol (stripped)

## User Pain Point

> "It's not efficient for me to continuously open this damn game over and over and over again."

The iteration cycle is:
1. Edit C code
2. Rebuild dylib
3. Fully quit game
4. Relaunch game
5. Wait for mod to load
6. Check logs
7. Repeat

**Goal**: Fast feedback without game restarts.

---

## Recommended Approaches (Priority Order)

### Approach 1: Reference-Based Discovery (HIGHEST PROBABILITY)

Instead of guessing SubTable offsets, find a **known string** in memory and backtrack to its SubTable.

**Strategy**:
1. Search game memory for a known stat name (e.g., "Strength\0")
2. String is at offset +24 from StringEntry header
3. Backtrack 24 bytes to find the StringEntry
4. The StringEntry contains its `Id` field (the FixedString index)
5. From the Id, calculate which SubTable it belongs to (`id & 0x0F`)
6. Search nearby memory for the Buckets pointer that points to this region

**Implementation** (add to fixed_string.c):
```c
static bool find_string_in_memory(const char *needle, uintptr_t *found_addr) {
    // Search __DATA section for exact string match
    // Use memmem-style search with safe_read_bytes
}

static bool discover_offsets_from_known_string(void) {
    uintptr_t str_addr;
    if (!find_string_in_memory("Strength", &str_addr)) {
        log_message("[FixedString] Could not find 'Strength' string");
        return false;
    }

    // StringEntry header is 24 bytes before string data
    uintptr_t entry_addr = str_addr - 24;

    // Read the Id field at offset +16
    uint32_t fixed_string_id;
    safe_read_u32((void*)(entry_addr + 16), &fixed_string_id);

    log_message("[FixedString] Found 'Strength' at %p, entry at %p, id=0x%08x",
                (void*)str_addr, (void*)entry_addr, fixed_string_id);

    // Now search for SubTable that contains this entry
    // ...
}
```

**Pros**: Works regardless of ARM64 structure differences
**Cons**: Need to find the right search string, slower initial probe

---

### Approach 2: Frida-Based Live Iteration (FASTEST FEEDBACK)

Use Frida for live memory inspection while game is running.

**Setup**:
```bash
# Install Frida
pip3 install frida-tools

# Attach to running game
frida -n "Baldur's Gate 3" -l search_gst.js
```

**search_gst.js**:
```javascript
// Search for "Strength" string in memory
var pattern = "53 74 72 65 6e 67 74 68 00"; // "Strength\0"
var ranges = Process.enumerateRanges('r--');

for (var range of ranges) {
    if (range.size > 0x100000) { // Only search large regions
        Memory.scan(range.base, range.size, pattern, {
            onMatch: function(address, size) {
                console.log("Found 'Strength' at: " + address);
                // Dump surrounding memory
                console.log(hexdump(address.sub(32), { length: 64 }));
            },
            onComplete: function() {}
        });
    }
}
```

**Workflow**:
1. Launch game normally (no dylib changes needed)
2. Attach Frida
3. Run scripts interactively
4. Find offsets
5. Hardcode into fixed_string.c
6. One final rebuild + test

**Pros**: No game restarts during discovery, interactive exploration
**Cons**: Requires Frida setup, different tool than existing workflow

---

### Approach 3: Ghidra Batch Script (AUTOMATED VALIDATION)

Create a Ghidra script to find all GlobalStringTable candidates and dump their offsets.

**Script**: `ghidra/scripts/find_globalstringtable.py`
```python
# find_globalstringtable.py
# Searches for GlobalStringTable structure patterns in ARM64 binary

from ghidra.program.model.symbol import SymbolType

def find_gst_candidates():
    """Find potential GlobalStringTable locations"""

    # Strategy 1: Search for string references
    # Look for "Strength", "Constitution", etc. in .rodata

    # Strategy 2: Find SubTable vtable patterns
    # SubTable has virtual destructor, look for vtable refs

    # Strategy 3: Find pthread_mutex_init calls
    # Each SubTable has a mutex, trace back from init calls

    results = []

    # Search for string "Strength" in data sections
    memory = currentProgram.getMemory()
    data_blocks = [b for b in memory.getBlocks() if b.getName().startswith("__DATA")]

    for block in data_blocks:
        start = block.getStart()
        end = block.getEnd()
        # Search for pattern...

    return results
```

**Pros**: Offline analysis, can validate all candidates before runtime
**Cons**: Still need runtime validation, Ghidra analysis is slow

---

### Approach 4: Lua-Based Inspection (LIMITED USE)

Lua scripts CAN be reloaded at runtime, but they cannot directly probe C memory.

**Useful for**:
- Testing Ext.Stats.Get() once FixedString works
- Verifying stat names resolve correctly
- Reloading test scripts without game restart

**NOT useful for**:
- Finding GlobalStringTable (needs native code)
- Probing raw memory addresses

**Hot-reload workflow**:
```lua
-- In BootstrapServer.lua
Ext.Require("TestScript.lua")  -- Can edit and reload this file

-- Reload command (if implemented)
Ext.Events.ResetCompleted:Subscribe(function()
    Ext.Require("TestScript.lua")  -- Reloads on game reset
end)
```

---

## Recommended Action Plan

### Phase 1: Quick Win with Frida (1 hour)

1. **Install Frida**: `pip3 install frida-tools`
2. **Create search script**: Search for "Strength" string
3. **Map structure**: Once found, dump 256 bytes before string to see StringEntry
4. **Find SubTable**: Search for pointers to the entry's memory region
5. **Calculate offsets**: Determine ARM64-specific Buckets/NumBuckets/EntrySize offsets

### Phase 2: Hardcode Discovered Offsets (30 min)

Once Frida reveals the actual offsets:
```c
// In fixed_string.h - replace Windows defaults
#define SUBTABLE_OFFSET_BUCKETS     0x????  // ARM64 value
#define SUBTABLE_OFFSET_NUM_BUCKETS 0x????  // ARM64 value
#define SUBTABLE_OFFSET_ENTRY_SIZE  0x????  // ARM64 value
```

### Phase 3: Validate with Full Test (30 min)

1. Rebuild dylib with hardcoded offsets
2. One final game restart
3. Verify `Ext.Stats.GetAll()` returns actual names
4. Test `Ext.Stats.Get("Strength")` works

---

## Alternative: Pure C Reference Discovery

If Frida is not preferred, implement reference-based discovery in C:

```c
// In fixed_string.c - add to try_runtime_probe()

// Known strings that MUST exist in GlobalStringTable
static const char *known_strings[] = {
    "Strength",
    "Dexterity",
    "Constitution",
    "Intelligence",
    "Wisdom",
    "Charisma",
    NULL
};

// Search __DATA section for these strings
// When found, backtrack to StringEntry header
// Extract FixedString Id from header
// Use Id to determine which SubTable contains this string
// Search for pointers to this memory region to find SubTable.Buckets
```

This is more complex than Frida but stays within the existing toolchain.

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/strings/fixed_string.c` | Add reference-based discovery |
| `src/strings/fixed_string.h` | Update offsets once discovered |
| `ghidra/scripts/find_globalstringtable.py` | New Ghidra script |
| `tools/frida/search_gst.js` | New Frida script (optional) |

---

## Decision Point

**Question**: Which approach do you prefer?

1. **Frida** - Fastest iteration, interactive, but requires setup
2. **Pure C** - Stays in existing workflow, but more code, still needs restart to test
3. **Ghidra first** - Offline analysis, then single runtime validation

My recommendation: **Start with Frida** for the discovery phase, then hardcode the results for production. This minimizes game restarts during the exploration phase.

---

---

## Multi-Agent Review Summary

Three specialized agents reviewed this plan:

### Architecture Strategist (8.5/10)
- **Endorsed**: Reference-based discovery as architecturally sound
- **Concern**: Frida introduces toolchain fragmentation; only use if runtime fails
- **Recommendation**: Extract duplicate `safe_read_*` functions to `src/core/safe_memory.c`
- **Key insight**: "Reference-based discovery is portable, self-validating, and aligns with existing patterns"

### Security Sentinel (SHIP IT)
- **Verdict**: No blocking security issues
- **Validated**: `mach_vm_read` usage is safe and follows macOS best practices
- **Optional hardening**: Add scan timeout, integer overflow checks, circuit breaker for failures
- **Frida**: Safe for development use

### Performance Oracle (CRITICAL)
- **Root cause**: 64MB nested loop scan = **600M+ memory operations** at startup
- **User pain point confirmed**: "takes a little longer to load now" is measurable delay
- **Priority 1 (IMMEDIATE)**:
  1. **Lazy discovery** - Move scan from init to first resolve call (10 min)
  2. **Offset caching** - Cache to `/tmp/bg3se_gst_offsets.cache` (30 min)
- **Priority 2**: Reference-based discovery = **150x faster** than current approach
- **Resolution-time caching NOT needed**: O(1) pointer lookup already optimal

### Consensus Action Plan

1. **Immediate** (fix load time): Implement lazy discovery + offset caching
2. **Next**: Reference-based discovery (search for "Strength" → backtrack)
3. **Defer**: Frida only if runtime discovery fails

---

## Appendix: Known Structure Offsets

### Windows x64 (from BaseString.h)
```
SubTable size: 0x1200 (4608 bytes)
  +0x0000: Element[64] (string entry pointers, padding)
  +0x1000: Lock (CRITICAL_SECTION ~40 bytes + padding)
  +0x1088: EntrySize
  +0x1090: EntriesPerBucket
  +0x10C0: NumBuckets
  +0x10C8: NumEntries
  +0x1140: Buckets (pointer to bucket array)
```

### ARM64 macOS (ESTIMATED - needs validation)
```
SubTable size: ~0x1100 (estimate)
  +0x0000: Element[64] (512 bytes, no padding)
  +0x0200: Lock (pthread_mutex_t, 64 bytes)
  +0x0240: EntrySize?
  +0x0248: EntriesPerBucket?
  +0x0278: NumBuckets?
  +0x0280: NumEntries?
  +0x02A0: Buckets?
```

These ARM64 estimates need validation via Frida or reference discovery.
