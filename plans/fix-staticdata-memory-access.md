# Plan: Fix StaticData Memory Access Issue

**Issue:** #45 (StaticData type expansion)
**Date:** Dec 21, 2025
**Updated:** Dec 22, 2025
**Status:** ✅ COMPLETE

## Resolution Summary (Dec 22, 2025)

All 9 StaticData types now working via `Ext.StaticData.ForceCapture()`:

| Type | Count | Method |
|------|-------|--------|
| Background | 22 | Get<T> hook |
| Class | 70 | Get<T> hook |
| Origin | 27 | Get<T> hook |
| Progression | 1004 | Get<T> hook |
| ActionResource | 87 | Get<T> hook |
| Feat | 41 | Hash lookup |
| Race | 156 | Hash lookup |
| God | 24 | Hash lookup |
| FeatDescription | 41 | Hash lookup |

**Solution:** Dual capture strategy:
1. **Get<T> hooks** - Hook ImmutableDataHeadmaster::Get<T>() for 5 types
2. **Hash lookup** - Use type index from TypeContext to lookup in ImmutableDataHeadmaster hash table for 4 types

## Problem Summary

After fixing manager names, all 9 StaticData managers are correctly matched during TypeContext traversal. However, `GetAll()` and `Get()` APIs return garbage data:

- Background: Returns 259 items but 214 are null with garbage GUIDs
- Race, Class, etc.: Similar issues with invalid counts/pointers

## ROOT CAUSE (Dec 22, 2025)

**TypeContext stores TYPE REGISTRATION METADATA, not actual manager instances.**

The TypeInfo.manager_ptr field does NOT point to ModdableFilesLoader manager instances.
It points to a **TYPE INDEX SLOT** containing small integers (type indices) and
pointers to ASCII type name strings.

### Evidence from Runtime Probing

Probing BackgroundManager's "slot_ptr" at 0x10d156968 revealed:

```text
SLOT: +0x00: ptr=0x7 u32=7/0           <- TYPE INDEX (not vtable!)
SLOT: +0x08: ptr=0x1 u32=1/0           <- Small integer pattern
SLOT: +0x10: ptr=0x27 u32=39/0
SLOT: +0x38: ptr=0x60000082c940        <- Heap pointer to ASCII type names
```

**The value at +0x00 is 7** (a small integer), NOT a vtable pointer like 0x100xxxxxx.

### Why Our Code Fails

1. TypeContext traversal captures slot_ptr (metadata), not manager pointer
2. Reading count at slot_ptr + 0x7C reads garbage (slot is only ~0x40 bytes)
3. Reading array at slot_ptr + 0x80 reads garbage
4. Result: Crashes or invalid GUIDs like `00000001-0000-0000-0700-000000000000`

## Key Discoveries

### 1. Manager Inheritance (Confirmed via Ghidra)

BackgroundManager **directly inherits** from `ModdableFilesLoader<ls::Guid, eoc::Background>`:
```cpp
~BackgroundManager() { ~ModdableFilesLoader(this); }
```

### 2. ModdableFilesLoader Structure (From Destructor Analysis)

```c
struct ModdableFilesLoader {
    void*    vtable;              // +0x00
    // ... FixedString fields at +0x08, +0x0C
    // HashMap at +0x10
    // HashTable at +0x50
    int32_t  count;               // +0x7C: Entry count
    void*    values_array;        // +0x80: Pointer to entry array
    // ... more fields
};
```

**Critical finding from destructor loop:**
- Count is at +0x7C ✓
- Array is at +0x80 ✓
- Each entry is **0x60 bytes** (not our assumed 0x80)
- Entries have vtable at index [0]

### 3. TypeInfo Structure (Actual, NOT Assumed)

```c
struct TypeInfo {
    void*    slot_ptr;        // +0x00: Pointer to TYPE INDEX SLOT (not manager!)
    char*    type_name;       // +0x08: C string like "eoc::BackgroundManager"
    uint32_t name_length;     // +0x10: String length
    uint32_t padding;         // +0x14
    void*    next_typeinfo;   // +0x18: Next in linked list
};
```

### 4. ImmutableDataHeadmaster Hash Table

Real managers are accessed via `ImmutableDataHeadmaster::Get<T>()`:
- Uses hash table at m_State
- Managers in array at some offset (NOT at m_State+0x30, which = 0x8)
- Additional structure analysis required

## Investigation Plan

### Step 1: Add Debug Probe Function

Add `Ext.StaticData.ProbeRaw(type)` to expose captured manager pointer for runtime investigation.

```lua
-- Returns: {ptr=0x..., count=N, array_ptr=0x...}
local info = Ext.StaticData.ProbeRaw("Background")
```

### Step 2: Runtime Memory Probe

Using the exposed pointer, probe the structure:

```lua
local info = Ext.StaticData.ProbeRaw("Background")
local mgr = info.ptr

-- Probe +0x70 to +0x90
for off = 0x70, 0x90, 4 do
    local u32 = Ext.Debug.ReadU32(mgr + off)
    local ptr = Ext.Debug.ReadPtr(mgr + off)
    print(string.format("+0x%02x: u32=%d ptr=0x%x", off, u32 or 0, ptr or 0))
end

-- Check first entry
local array = Ext.Debug.ReadPtr(mgr + 0x80)
local first = Ext.Debug.ReadPtr(array)  -- If array of pointers
-- or
local first = array  -- If flat array

-- Probe entry structure
for off = 0, 0x60, 8 do
    local val = Ext.Debug.ReadPtr(first + off)
    print(string.format("  entry+0x%02x: 0x%x", off, val or 0))
end
```

### Step 3: Determine Array Type

Test whether +0x80 is:
- **Array of pointers**: `entry = ((void**)array)[index]`
- **Flat array**: `entry = array + (index * 0x60)`

The destructor shows: `*(long *)(this + 0x80) + lVar2` where lVar2 increases by 0x60.
This is: `array_ptr + (index * 0x60)` = **flat array interpretation**.

But it then does: `**(undefined8 **)(...)` which is double-deref, suggesting the entries themselves have a pointer at [0] (the vtable).

### Step 4: Locate GUID Within Entry

For GuidResource-derived types, GUID should be at:
- +0x00: vtable (8 bytes)
- +0x08: ResourceUUID (16 bytes)

Validate by reading bytes at entry+0x08 and checking if they form valid GUIDs.

### Step 5: Update Code

Once offsets are confirmed:

1. Update `g_manager_configs[]` with correct entry sizes
2. Verify flat array interpretation works
3. Update GUID extraction offset if needed
4. Test all 9 types

## Implementation Tasks

**Phase 1: Investigation (COMPLETED)**
1. [x] Add `Ext.StaticData.ProbeRaw(type)` Lua function
2. [x] Run runtime probe on Background, Race, Class managers
3. [x] Document actual structure layout discovered
4. [x] Identify ROOT CAUSE: TypeContext stores metadata, not managers

**Phase 2: Fix Implementation (PENDING)**
1. [ ] Choose fix approach (Option A, B, or C below)
2. [ ] Implement proper manager pointer acquisition
3. [ ] Verify ModdableFilesLoader offsets (+0x7C count, +0x80 array)
4. [ ] Verify entry structure (0x60 bytes per destructor, GUID at +0x08)
5. [ ] Test GetAll/Get for all 9 types
6. [ ] Update STATICDATA.md with final solution

## Fix Options

### Option A: ImmutableDataHeadmaster Hash Table Lookup (Correct but Complex)
- Reverse engineer the hash structure at m_State
- Implement `Get<T>()` equivalent in C
- Requires understanding hash function and bucket structure
- Highest correctness, most RE effort

### Option B: Hook Get<T> Functions (SELECTED - Dec 22, 2025)
- Hook the game's `Get<T>` functions for each manager type
- Capture both `this` (ImmutableDataHeadmaster) and return value (real manager)
- Proven pattern - similar to FeatManager hook

**Get<T> Function Addresses Found:**

| Manager | Get<T> Address | Notes |
|---------|----------------|-------|
| Feat | N/A | Working via GetFeats hook @ 0x01b752b4 |
| Race | Not found | Need alternative approach |
| Background | 0x102994834 | `Get<eoc::BackgroundManager>` |
| Origin | 0x10341c42c | `Get<eoc::OriginManager>` |
| God | Not found | Need alternative approach |
| Class | 0x10262f184 | `Get<eoc::ClassDescriptions>` |
| Progression | 0x103697f0c | `Get<eoc::ProgressionManager>` |
| ActionResource | 0x1011a4494 | `Get<eoc::ActionResourceTypes>` |
| FeatDescription | Not found | Need alternative approach |

**For managers without Get<T>:**
- Race, God, FeatDescription may use different accessor patterns
- Can search for functions that receive these managers as parameters
- Or implement hash lookup using type index from RegisterType

### Option C: Environment Chain Discovery (Session-Dependent)
- Find offsets in Environment structure for each manager
- Already know: Environment+0x130 → FeatManager
- Need to discover offsets for other 8 managers
- Requires character creation/respec session

## Files to Modify

- `src/staticdata/staticdata_manager.c` - Implement proper manager acquisition
- `src/lua/lua_staticdata.c` - (Already has ProbeRaw)
- `ghidra/offsets/STATICDATA.md` - Document final solution

## Success Criteria

```lua
-- All 9 types should return valid data
for _, type in ipairs({"Feat", "Race", "Background", "Origin", "God", "Class", "Progression", "ActionResource", "FeatDescription"}) do
    local items = Ext.StaticData.GetAll(type)
    print(type .. ": " .. #items .. " items")
    if #items > 0 then
        local first = items[1]
        print("  First: " .. (first.Name or first.ResourceUUID))
    end
end
```

## Fallback Options

If TypeContext approach doesn't work for non-Feat types:

1. **Session hooks**: Hook type-specific functions like `BackgroundManager::GetBackground`
2. **Global search**: Pattern scan for manager vtables in memory
3. **Environment chain**: Capture via Environment structure during session
