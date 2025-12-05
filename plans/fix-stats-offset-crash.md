# Fix Stats System Offset - 0xC0 Crash Investigation

## Problem Statement

The Ext.Stats API implementation for bg3se-macos is reading garbage data at the current offset (0x88), while runtime probing found valid data at offset 0xC0 (size=15774 matches expected stat count). However, **using offset 0xC0 causes a crash**.

### Current State
- **Offset 0x88**: `buf=0x900000010` (garbage), `size=24576` (wrong)
- **Offset 0xC0**: `buf=valid`, `cap=16384`, `size=15774` (correct!) but crashes
- **Three managers with size=15774**: +0xC0, +0xE0, +0xF0 (32-byte spacing)

### Key Insight from Research
From Windows BG3SE (`Stats.h:306-381`, `Common.h:15-172`):
- `CNamedElementManager<T>` layout: VMT(8) + Array(16) + HashMap(~48) + NextHandle(4) = ~80 bytes
- On ARM64, this may be ~96-104 bytes due to alignment differences
- The three managers at 0xC0/0xE0/0xF0 with identical sizes are suspicious - they might be:
  - Objects manager's internal components (Values array, NameToHandle data, etc.)
  - Or different views of the same data

## Root Cause Analysis

The crash likely occurs because:
1. **Reading Array.buf_ at wrong offset within manager** - The `+0x08` assumption may be wrong on ARM64
2. **Element structure differs** - Object's Name field may not be at +0x20
3. **Memory protection** - The buf pointer may point to protected memory

## Implementation Plan

### Phase 1: Enhanced Diagnostic Probing

Add detailed probing at offset 0xC0 to understand the structure:

```c
// src/stats/stats_manager.c - Enhanced probing for 0xC0
void probe_manager_structure(void *mgr, int offset) {
    log_stats("=== Detailed probe at +0x%03x ===", offset);

    // Dump first 128 bytes as hex to see raw structure
    for (int i = 0; i < 128; i += 8) {
        void *val = NULL;
        if (safe_read_ptr((char*)mgr + i, &val)) {
            log_stats("  +0x%02x: %p", i, val);
        }
    }

    // Try reading buf at different sub-offsets (0x00, 0x08, 0x10)
    for (int sub = 0x00; sub <= 0x18; sub += 0x08) {
        void *buf = NULL;
        if (safe_read_ptr((char*)mgr + sub, &buf) && buf &&
            (uintptr_t)buf > 0x100000000ULL) {

            // Try to read first element
            void *elem = NULL;
            if (safe_read_ptr(buf, &elem) && elem) {
                log_stats("  Sub-offset +0x%02x: buf=%p, elem[0]=%p", sub, buf, elem);

                // Try reading name at various offsets within element
                for (int name_off = 0x18; name_off <= 0x30; name_off += 0x08) {
                    void *name_ptr = NULL;
                    if (safe_read_ptr((char*)elem + name_off, &name_ptr) && name_ptr) {
                        char name[64] = {0};
                        // Safe read of name string...
                        log_stats("    elem+0x%02x: %s", name_off, name);
                    }
                }
            }
        }
    }
}
```

### Phase 2: Identify Correct Sub-Offsets

Based on probing results, determine:
1. Where Array.buf_ actually is within CNamedElementManager (may not be +0x08)
2. Where Object.Name actually is within stats::Object (may not be +0x20)
3. Whether the crash is in probing code or in subsequent stats access

### Phase 3: Fix Offset Constants

Update `stats_manager.c`:
```c
// After probing confirms correct values
#define RPGSTATS_OFFSET_OBJECTS             0xC0   // Confirmed via probing
#define CNEM_OFFSET_VALUES_BUF              0x??   // TBD from probing
#define OBJECT_OFFSET_NAME                  0x??   // TBD from probing
```

### Phase 4: Safe Stats Access

Ensure all stats access goes through safe memory reads:
- Never dereference pointers directly
- Always use `safe_read_ptr()` / `vm_read()`
- Add null checks at every step

## Acceptance Criteria

- [ ] Probing successfully reads stat names at offset 0xC0
- [ ] No crash when using 0xC0 as Objects manager offset
- [ ] `Ext.Stats.GetAllStats()` returns 15774 entries
- [ ] `Ext.Stats.Get("Longsword")` returns valid stat object
- [ ] Game loads and runs stably with stats system active

## Files to Modify

- `src/stats/stats_manager.c:273-330` - Enhanced probing code
- `src/stats/stats_manager.c:131-134` - Offset constants after verification

## References

- Windows BG3SE Stats.h: `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Stats/Stats.h`
- Windows BG3SE Common.h: `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Stats/Common.h`
- macOS implementation: `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/stats/stats_manager.c`
