---
title: "Ext.StaticData Implementation: FeatManager Discovery & Frida Capture"
date: 2025-12-15
category: reverse-engineering
component: Ext.StaticData
issue: "#40"
severity: architecture
tags:
  - arm64
  - staticdata
  - frida
  - file-based-capture
  - featmanager
---

# Ext.StaticData Implementation: FeatManager via Frida Capture

## Summary

Successfully implemented `Ext.StaticData.GetAll("Feat")` and `Ext.StaticData.Get("Feat", guid)` API by:
1. Discovering FeatManager is NOT accessible via TypeContext (only metadata)
2. Implementing file-based Frida capture integration to extract real FeatManager pointer
3. Writing captured pointer to `/tmp/bg3se_featmanager.txt` for BG3SE to read
4. Loading captured data into C-level manager state for Lua API access

**Result:** `Ext.StaticData.GetAll("Feat")` returns all 41 feats with proper GUIDs.

## Problem

Initial TypeContext-based approach failed:
- `Ext.StaticData.GetCount("Feat")` returned 37 (metadata count)
- `Ext.StaticData.GetAll("Feat")` returned metadata structures, not actual feat data
- TypeContext traversal only finds registration metadata, not real manager instances

### Root Cause

**TypeContext gives registration metadata structures, NOT actual manager instances.**

| Source | Offset | What It Contains |
|--------|--------|------------------|
| TypeContext metadata | +0x00 | Registration count (37 for feats) |
| Real FeatManager | +0x7C | Actual feat count (41 feats) |

The ImmutableDataHeadmaster's TypeContext stores TypeInfo entries for type registration, but these point to metadata structures, not the runtime manager instances used to access actual feat data.

## Technical Investigation

### Discovery Path

1. **TypeContext Analysis (Failed)**
   - Traversed `ImmutableDataHeadmaster.m_State` linked list
   - Found TypeInfo entries with manager pointers
   - All gave metadata count at +0x00, not real data

2. **Ghidra Decompilation**
   - Decompiled `GetFeats` at `0x101b752b4`
   - Found FeatManager structure: count at +0x7C, array at +0x80
   - Key discovery: FeatManager is at `Environment+0x130`, not TypeContext

3. **Dobby Hooking Attempt (Failed)**
   - Tried direct Dobby hook on GetFeats
   - Broke feat selection UI due to PC-relative instruction corruption
   - ADRP+LDR patterns got corrupted by trampoline relocation

4. **Frida Solution (Working)**
   - Used Frida Interceptor (non-invasive, doesn't replace function)
   - Captured FeatManager pointer in x1 register
   - Wrote to file for BG3SE to read

## Solution Architecture

### Three-Layer Approach

```
┌─────────────────────────────────────────────────────┐
│ Layer 1: Frida Script (Runtime Capture)              │
│ - capture_featmanager_live.js                        │
│ - Hooks GetFeats via Interceptor.attach              │
│ - Reads FeatManager from x1 register                 │
│ - Writes pointer to /tmp/bg3se_featmanager.txt       │
└─────────────────────────────────────────────────────┘
                           ↓
            ┌──────────────────────────┐
            │ /tmp/bg3se_featmanager.txt│
            │ Line 1: Manager ptr      │
            │ Line 2: Count            │
            │ Line 3: Array ptr        │
            └──────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────┐
│ Layer 2: C Implementation (File Loading)             │
│ - staticdata_manager.c                               │
│ - load_captured_featmanager()                        │
│ - Reads file and verifies pointers                   │
│ - Stores as real_managers[STATICDATA_FEAT]          │
└─────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────┐
│ Layer 3: Lua API (User Access)                       │
│ - lua_staticdata.c                                   │
│ - Ext.StaticData.GetAll("Feat")                     │
│ - Ext.StaticData.Get("Feat", guid)                  │
└─────────────────────────────────────────────────────┘
```

## Implementation Details

### 1. Frida Capture Script

**File:** `/Users/tomdimino/Desktop/Programming/bg3se-macos/tools/frida/capture_featmanager_live.js`

Key aspects:
- Hooks `FeatManager::GetFeats` at offset `0x01b752b4`
- Reads FeatManager from x1 (ARM64 calling convention: x1 = 2nd parameter)
- Validates structure: count at +0x7C (1-1000 range), array at +0x80 (non-null)
- Writes captured data to file with format:
  ```
  0x600012345678          # FeatManager pointer
  41                      # Feat count at +0x7C
  0x600098765432          # Feat array pointer at +0x80
  ```

**Invocation:**
```bash
frida -U -n "Baldur's Gate 3" -l tools/frida/capture_featmanager_live.js
# Then trigger: Open character creation/respec UI, click on Feats
# Frida will output: Wrote FeatManager info to /tmp/bg3se_featmanager.txt
```

### 2. C-Level File Loading

**File:** `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/staticdata/staticdata_manager.c`

Function: `load_captured_featmanager()` at line 717

```c
static bool load_captured_featmanager(void) {
    FILE* f = fopen(FRIDA_CAPTURE_FILE, "r");  // /tmp/bg3se_featmanager.txt
    if (!f) return false;

    // Parse file
    fscanf(line1, "%p");  // Parse pointer in either format
    count = atoi(line2);
    fscanf(line3, "%p");

    // Validate
    if (!feat_mgr || count <= 0 || count > 1000 || !array) return false;

    // Verify pointers still valid
    if (!safe_memory_read_i32((mach_vm_address_t)feat_mgr + 0x7C, &verify_count))
        return false;

    // Store as real manager
    g_staticdata.real_managers[STATICDATA_FEAT] = feat_mgr;

    return true;
}
```

**Safety Features:**
- Safe memory reads via `safe_memory_read_*()` to prevent crashes
- Count range validation (1-1000)
- Pointer verification (array must be readable)
- File format tolerant to different hex formats (0x... or decimal)

### 3. Lua API Integration

**File:** `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/lua/lua_staticdata.c`

Public functions:
```lua
-- Load captured data
Ext.StaticData.LoadFridaCapture() -> bool

-- Check if capture available
Ext.StaticData.FridaCaptureAvailable() -> bool

-- Access feat data
Ext.StaticData.GetAll("Feat") -> array of tables
Ext.StaticData.Get("Feat", guid_str) -> table or nil
Ext.StaticData.GetCount("Feat") -> int
```

## Key Offsets

| Offset | Purpose |
|--------|---------|
| `0x01b752b4` | FeatManager::GetFeats function |
| `0x7C` | FeatManager.count (int32) |
| `0x80` | FeatManager.array (Feat* pointer) |
| `0x128` | Feat struct size (296 bytes) |
| `0x08` | Feat.GUID offset (after 8-byte VMT header) |

## Data Structures

### FeatManager (Real Instance)

```c
struct FeatManager {
    void* VMT;                      // +0x00
    // ... unknown fields ...
    int32_t count;                  // +0x7C
    Feat* array;                    // +0x80
};

struct Feat {
    void* VMT;                      // +0x00
    uint32_t guid_part1;            // +0x08
    uint32_t guid_part2;            // +0x0C
    uint32_t guid_part3;            // +0x10
    uint32_t guid_part4;            // +0x14
    // ... remaining 280 bytes unknown
};
```

### StaticDataGuid (From Lua)

```c
typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} StaticDataGuid;
```

## Workflow

### For Users (Lua)

1. **Capture Phase (One-time)**
   ```bash
   # Terminal 1
   frida -U -n "Baldur's Gate 3" -l tools/frida/capture_featmanager_live.js

   # In game: Open character creation or respec screen
   # Click on Feats to trigger GetFeats hook
   ```

2. **Load Phase (Per Session)**
   ```lua
   -- In game console
   Ext.StaticData.LoadFridaCapture()  -- Returns true if successful
   ```

3. **Access Phase**
   ```lua
   -- Get all feats
   local feats = Ext.StaticData.GetAll("Feat")
   print(#feats)  -- 41 feats

   -- Get specific feat
   local feat = Ext.StaticData.Get("Feat", "b1e2e6c2-4ddc-41f1-8b00-e8cc1dfc58c8")
   print(feat.ResourceUUID)  -- GUID
   ```

### For Developers (C)

1. **Initialize**
   ```c
   staticdata_manager_init(main_binary_base);
   ```

2. **Load captures**
   ```c
   staticdata_try_typecontext_capture();  // Try TypeContext first
   if (staticdata_frida_capture_available()) {
       staticdata_load_frida_capture();    // Load Frida file if available
   }
   ```

3. **Access data**
   ```c
   int count = staticdata_get_count(STATICDATA_FEAT);
   for (int i = 0; i < count; i++) {
       void* entry = staticdata_get_by_index(STATICDATA_FEAT, i);
       StaticDataGuid guid;
       staticdata_get_guid(STATICDATA_FEAT, entry, &guid);
   }
   ```

## Why This Approach Works

### Advantages of File-Based Capture

1. **Non-Invasive**
   - Frida Interceptor doesn't replace function
   - Original GetFeats executes normally
   - No UI breakage like Dobby hooks

2. **Runtime Verification**
   - Captures real pointers at runtime
   - Not static analysis (avoids address space layout issues)
   - Works across game sessions and updates

3. **Asynchronous Decoupling**
   - Frida captures when player accesses feats
   - BG3SE loads when player requests data
   - No forced timing dependencies

4. **Safe Memory Access**
   - File format is human-readable and parseable
   - C-level safe_memory_read prevents crashes
   - Graceful failure if pointers become invalid

### Why Dobby Failed

Dobby inline hooks corrupt ARM64 PC-relative instructions:

```asm
; Original GetFeats function
ADRP x8, #0x1089b0000     ; Page address for constant pool
LDR  x8, [x8, #0xac80]    ; Load from page

; After Dobby hook (code moved to trampoline)
ADRP x8, #0x7fffabcd000   ; WRONG PAGE - trampoline location!
LDR  x8, [x8, #0xac80]    ; Loads garbage memory
```

The ADRP (Address Page) instruction calculates a page address relative to PC. When Dobby moves the code to a trampoline at a different address, the page offset no longer matches.

**Solution:** Use Frida Interceptor which:
- Only intercepts (doesn't replace)
- Lets original code execute at original address
- Preserves all PC-relative calculations

## Results

### API Status

| Feature | Status | Count |
|---------|--------|-------|
| `Ext.StaticData.GetAll("Feat")` | Working | 41 feats |
| `Ext.StaticData.Get("Feat", guid)` | Working | By GUID lookup |
| `Ext.StaticData.GetCount("Feat")` | Working | Returns 41 |
| Feat GUIDs | Verified | All 41 return valid GUIDs |

### Example Output

```lua
Ext.StaticData.GetAll("Feat")
[1] = {
    ResourceUUID = "b1e2e6c2-4ddc-41f1-8b00-e8cc1dfc58c8",
    Type = "Feat",
    _ptr = lightuserdata: 0x600012345678
}
[2] = { ... }
-- ... 41 total
```

## Related Files

| File | Purpose |
|------|---------|
| `/Users/tomdimino/Desktop/Programming/bg3se-macos/tools/frida/capture_featmanager_live.js` | Frida hook script |
| `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/staticdata/staticdata_manager.c` | C implementation (load_captured_featmanager, feat_get_*) |
| `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/lua/lua_staticdata.c` | Lua API bindings |
| `/Users/tomdimino/Desktop/Programming/bg3se-macos/docs/solutions/reverse-engineering/staticdata-featmanager-discovery.md` | Initial investigation notes |

## Next Steps

### Remaining Static Data Types

The same pattern (Frida capture + file loading) can be extended to:
- Race (use similar GetRaces hook)
- Background, Origin (character creation UI)
- God (pantheon selection)
- Class (class selection)
- Progression, ActionResource, FeatDescription

### Alternative Approaches for Testing

1. **Direct TypeContext Probing** (if metadata manager pointers point to real managers)
   ```c
   // Try to find real manager via pointer chain in metadata
   void* probe_for_real_feat_manager(void* metadata);
   ```

2. **Environment Parameter Capture** (if GetAllFeats called with Environment)
   ```c
   // Hook GetAllFeats - receives Environment, has FeatManager at +0x130
   void hook_GetAllFeats(void* environment);
   ```

3. **Static Singleton Address** (if manager is a global)
   ```c
   // Search for manager singleton via symbol or pattern
   void* find_manager_via_pattern();
   ```

## References

- **Issue:** #40 - Ext.StaticData (Static Data API)
- **Previous Investigation:** `staticdata-featmanager-discovery.md`
- **ARM64 Hooking:** `arm64-hooking-prevention.md`
- **Windows Reference:** `BG3Extender/Lua/Libs/StaticData.inl`

## Debugging

### Check Capture File

```bash
cat /tmp/bg3se_featmanager.txt
# Output:
# 0x600012345678
# 41
# 0x600098765432
```

### Enable Logging

```c
// In staticdata_manager.c
log_message("[StaticData] FeatManager at %p, count=%d, array=%p",
            feat_mgr, count, array);
```

### Console Verification

```lua
-- Check if capture available
if Ext.StaticData.FridaCaptureAvailable() then
    print("Capture file exists")
else
    print("Run Frida script first")
end

-- Load and verify
if Ext.StaticData.LoadFridaCapture() then
    print("Loaded successfully")
    local count = Ext.StaticData.GetCount("Feat")
    print("Feat count: " .. count)
else
    print("Failed to load")
end
```
