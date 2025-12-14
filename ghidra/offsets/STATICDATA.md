# StaticData System Offsets (macOS ARM64)

## Overview

The StaticData system manages immutable game data loaded from game files, including
Feats, Races, Backgrounds, Origins, Gods, Classes, and related character creation data.

Unlike Windows BG3SE which uses `eoc__gGuidResourceManager`, macOS BG3 uses the
`ImmutableDataHeadmaster` TypeContext pattern for static data manager access.

## Key Discoveries (Dec 2025)

### Access Pattern

Static data managers are NOT accessed via simple static globals. Instead:

1. **TypeContext Pattern**: Managers registered with `TypeContext<ImmutableDataHeadmaster>`
2. **Context Chain**: `DefinitionView.field_0x80 → Context → Manager`
3. **Linked List**: TypeInfo structs linked via m_State+8

### Manager Registration

Each manager is registered via `TypeContext<ImmutableDataHeadmaster>::RegisterType<T>`:

| Manager | TypeInfo Address (ptr-to) | Notes |
|---------|---------------------------|-------|
| `FeatManager` | `0x1083f5528` | Contains feat definitions |
| `RaceManager` | `0x1083f5538` | Race definitions |

### TypeInfo Structure

```c
struct TypeInfo {
    void*    manager_ptr;     // +0x00: Pointer to manager instance
    void*    type_name;       // +0x08: FixedString type name pointer
    uint32_t name_length;     // +0x10: Type name length
    void*    padding;         // +0x14: Padding
    void*    next_typeinfo;   // +0x18: Next TypeInfo in list
};
```

### ImmutableDataHeadmaster m_State

| Field | Offset | Notes |
|-------|--------|-------|
| (unknown) | +0x00 | State data |
| TypeInfo* head | +0x08 | Head of linked list of registered types |

Address: `PTR_m_State_1083c4a68` (pointer to m_State address)

## FeatManager

### Discovery via GetAvailableFeatsForProgression

Function at `0x10339fab4` (ecl::character_creation::DefinitionView::GetAvailableFeatsForProgression):

```asm
10339fd40: ldr x8,[x20, #0x80]     ; x8 = context->field_0x80 (Environment)
10339fd44: ldr x1,[x8, #0x130]     ; x1 = Environment->field_0x130 (FeatManager!)
10339fd48: mov x0,x19              ; x0 = output buffer
10339fd5c: b 0x10120b3e8           ; tail call to GetAllFeats
```

### Access Chain

```
DefinitionView.field_0x80 → Context object
    Context.field_0x130 → FeatManager pointer
```

### FeatManager Structure (from GetFeats @ 0x101b752b4)

```c
struct FeatManager {
    // ... base class fields (ModdableFilesLoader<Guid, Feat>)
    int32_t  count;       // +0x7C: Number of feats
    void*    feats;       // +0x80: Pointer to feat array
};
```

### Feat Structure

Each feat is **0x128 bytes** (296 bytes).

Structure layout (needs runtime verification):
```c
struct Feat {
    // GUID at start (16 bytes)
    uint8_t  guid[16];           // +0x00-0x0F
    // ... name, description, prerequisites, etc.
    // Total size: 0x128 bytes
};
```

### GetFeats Function (0x101b752b4)

```asm
; FeatManager::GetFeats(output_array*, FeatManager* this)
101b752b4: stp x20,x19,[sp, #-0x20]!
...
101b752d0: ldr w1,[x1, #0x7c]      ; count = this->field_0x7C
...
101b752e8: ldr x20,[x20, #0x80]    ; feats_array = this->field_0x80
...
101b752f4: mov x8,#0x128           ; feat size = 0x128 bytes
101b752f8: mul x8,x8,x22           ; offset = size * index
```

### GetAllFeats Function (0x10120b3e8)

Signature: `void eoc::character_creation::GetAllFeats(Environment *param_1)`

Calls `FeatManager::GetFeats()` without explicitly loading x1 - FeatManager is passed
through register from caller.

## Other Manager Offsets in Context Object

Based on GetAvailableFeatsForProgression analysis:

| Field Offset | Contents | Notes |
|--------------|----------|-------|
| +0x78 | Lookup interface | Virtual table call |
| +0xC0 | ProgressionManager lookup | Used for progression |
| +0x130 | FeatManager | Confirmed via GetAllFeats call |

## Related Functions

| Function | Address | Notes |
|----------|---------|-------|
| `GetAvailableFeatsForProgression` | `0x10339fab4` | Main discovery function |
| `GetAllFeats` | `0x10120b3e8` | Calls FeatManager::GetFeats |
| `FeatManager::GetFeats` | `0x101b752b4` | Core feat retrieval |
| `GetFeatTitleAndDescription` | `0x101b7902c` | Uses same offsets |
| `RegisterType<FeatManager>` | `0x100c64b14` | TypeContext registration |
| `RegisterType<RaceManager>` | `0x100c63044` | TypeContext registration |

## Implementation Strategy

### Option 1: Hook-Based Capture (Recommended)

Hook `FeatManager::GetFeats` at `0x101b752b4` to capture the FeatManager pointer from x1:

```c
static void* g_feat_manager = NULL;

void feat_manager_hook(void* output, void* feat_manager) {
    g_feat_manager = feat_manager;  // Capture FeatManager pointer
    return original_GetFeats(output, feat_manager);
}
```

### Option 2: TypeContext Traversal

Walk the TypeInfo linked list from ImmutableDataHeadmaster::m_State+8:

```c
void* find_manager_by_name(const char* type_name) {
    void* m_state = *PTR_m_State;
    void* typeinfo = *(void**)(m_state + 8);  // head of list
    while (typeinfo) {
        const char* name = *(const char**)(typeinfo + 8);
        if (strcmp(name, type_name) == 0) {
            return *(void**)typeinfo;  // manager_ptr at offset 0
        }
        typeinfo = *(void**)(typeinfo + 0x18);  // next
    }
    return NULL;
}
```

### Option 3: Context Capture

Hook a function that receives the Context object and read managers from known offsets.

## Lua API Design

```lua
-- Get all feats
local feats = Ext.StaticData.GetAll("Feat")

-- Get specific feat by GUID
local feat = Ext.StaticData.Get("Feat", "e7ab823e-32b2-49f8-b7b3-7f9c2d4c1f5e")

-- Get feat by name (if supported)
local feat = Ext.StaticData.Get("Feat", "Athlete")
```

## Related Windows BG3SE Code

- `BG3Extender/Lua/Libs/StaticData.inl` - StaticData Lua bindings
- `BG3Extender/GameDefinitions/Resources.h` - Resource type definitions
- `BG3Extender/GameDefinitions/EntitySystem.cpp` - GetRawResourceManager

Note: Windows uses `eoc__gGuidResourceManager` which is NOT exported on macOS.
Different approach required.

## Runtime Verification (Dec 14, 2025)

### TypeContext Traversal - WORKING

Successfully traversed the ImmutableDataHeadmaster TypeContext linked list:

```text
m_State at: 0x10ac4bba0 (captured at runtime)
TypeInfo count: 100+ entries (hit safety limit)
```

**Sample TypeInfo entries discovered:**

```text
TypeInfo[0]: mgr=0x10ab9cf28, name_ptr=0x6000024d1120
TypeInfo[1]: mgr=0x10ab9cf08, name_ptr=0x6000024d1100
TypeInfo[2]: mgr=0x10ab94b50, name_ptr=0x600002accd50
...
TypeInfo[22]: mgr=0x10ac46558, name_ptr=0x10ac86b08  (static string!)
...
```

**Key observation:** Most name_ptr values are heap addresses (0x600002...) indicating FixedString objects.
One entry (TypeInfo[22]) has a static address, possibly a raw C string.

### Hook Status

| Hook | Offset | Status | Notes |
|------|--------|--------|-------|
| `FeatManager::GetFeats` | `0x01b752b4` | Installed, not triggered | May not be called during respec |
| `GetAllFeats` | `0x0120b3e8` | Installed (v0.32.5+) | Environment+0x130 → FeatManager |

**Finding:** The `FeatManager::GetFeats` hook does NOT trigger during character respec at Withers.
Added second hook on `GetAllFeats` which receives the Environment context object.

### Implementation Files

| File | Purpose |
|------|---------|
| `src/staticdata/staticdata_manager.c` | Hook-based capture, TypeContext traversal |
| `src/staticdata/staticdata_manager.h` | Public API declarations |
| `src/lua/lua_staticdata.c` | Lua bindings (GetAll, Get, TryTypeContext) |

### Lua API (v0.32.5)

```lua
-- Check if manager captured
Ext.StaticData.IsReady("Feat")  -- returns boolean

-- Get supported types
Ext.StaticData.GetTypes()  -- {"Feat", "Race", "Background", ...}

-- Debug: Try TypeContext traversal
Ext.StaticData.TryTypeContext()  -- Logs all TypeInfo entries

-- Once captured:
Ext.StaticData.GetAll("Feat")    -- Array of feat tables
Ext.StaticData.Get("Feat", guid) -- Single feat by GUID
Ext.StaticData.GetCount("Feat")  -- Number of feats
```

### Next Steps

1. **Verify GetAllFeats hook** - Restart game, trigger respec, check if FeatManager captured
2. **Identify manager type names** - Read FixedString values from name_ptr to match managers
3. **Probe FeatManager structure** - Verify +0x7C count and +0x80 array offsets at runtime

## Version History

| Version | Date | Notes |
|---------|------|-------|
| Initial | Dec 2025 | FeatManager discovery via Ghidra MCP |
| v0.32.5 | Dec 14, 2025 | TypeContext traversal working, GetAllFeats hook added |
