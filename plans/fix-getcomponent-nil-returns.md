# Plan: Fix GetComponent Returning Nil

## Overview

GetComponent calls return nil despite successful entity lookup and TypeId discovery. Root cause analysis reveals **three distinct problems** that need to be addressed.

## Problem Statement

**Current State:**
- TypeId discovery works (11 component indices found)
- Entity GUID lookup works (handles found via HashMap)
- Template calls are attempted but return nil
- Components never marked as "discovered"

**Expected State:**
- `entity:GetComponent("ecl::Character")` returns component data
- Component data accessible for manipulation by mods

## Root Cause Analysis

### Problem 1: Template Addresses Aren't Callable (PRIMARY)

The addresses in `component_templates.h` (0x100cc20a8 for `ecl::Character`, etc.) are **NOT standalone callable functions**.

**Evidence:**
- macOS ARM64 compiler inlines template instantiations
- Addresses point to code embedded within other functions
- Calling them directly returns NULL
- Logs show "Trying template call" then immediately fail

**Windows BG3SE Comparison:**
Windows uses a **dispatcher pattern** with `GetRawComponent()`:
```cpp
void* EntityWorld::GetRawComponent(EntityHandle entityHandle,
                                   ComponentTypeIndex type,
                                   std::size_t componentSize,
                                   bool isProxy)
```

macOS should use the same approach, NOT direct template calls.

### Problem 2: TypeId Discovery Not Triggering Component Discovery

Components are pre-registered with `COMPONENT_INDEX_UNDEFINED` but never get marked as `discovered = true`.

**Evidence:**
- `component_lookup_by_index()` only called if `component->discovered == true`
- Discovery flag only set when `index != COMPONENT_INDEX_UNDEFINED`
- TypeId discovery reads indices successfully but doesn't update the registry properly
- Code falls back to template calls (which fail)

**Call Path:**
```
entity:GetComponent("ecl::Character")
  → component_get_by_name("ecl::Character")
    → info->discovered == false (BUG: should be true)
      → Falls through to template call
        → Returns NULL
```

### Problem 3: Data Structure Traversal Has Latent Bug

The fallback data structure traversal in `component_lookup.c` has wrong memory layout assumptions:

**Evidence:**
- ComponentTypeToIndex HashMap's size reads garbage: `68719476752` = `0x1000000010`
- ArrayHeader structure assumes wrong offsets
- Works by accident for index 0 entities

## Proposed Solution

### Phase 1: Fix TypeId → Registry Connection (Quick Win)

**Goal:** Make TypeId discovery properly update component registry

**Changes to `component_typeid.c`:**
```c
// In component_typeid_discover(), after reading index:
if (component_typeid_read(entry->ghidraAddr, &typeIndex)) {
    // This already calls component_registry_register() but...
    // Verify the registration actually marks discovered = true
}
```

**Changes to `component_registry.c`:**
```c
bool component_registry_register(const char *name, uint16_t index,
                                  uint16_t size, bool isProxy) {
    // Ensure discovered flag is set when index is valid
    if (index != COMPONENT_INDEX_UNDEFINED) {
        info->discovered = true;  // <-- Verify this happens
    }
}
```

**Verification:** Add logging to confirm `discovered = true` after registration.

### Phase 2: Implement Dispatcher Pattern (Core Fix)

**Goal:** Replace template calls with Windows-style GetRawComponent dispatcher

**New approach:**
1. Find `EntityWorld::GetRawComponent` or equivalent in macOS binary via Ghidra
2. Implement dispatcher that takes (handle, typeIndex, size, isProxy)
3. Remove reliance on per-component template addresses

**Files to modify:**
- `src/entity/component_lookup.c` - New dispatcher implementation
- `src/entity/entity_storage.h` - Add GetRawComponent address
- `ghidra/offsets/COMPONENTS.md` - Document dispatcher address

**Windows Signature to Match:**
```cpp
void* GetRawComponent(EntityWorld* world, EntityHandle handle,
                      ComponentTypeIndex type, size_t componentSize,
                      bool isProxy)
```

### Phase 3: Fix Data Structure Offsets (Robustness)

**Goal:** Correct ArrayHeader and HashMap structure definitions

**Changes to `src/entity/entity_storage.h`:**
```c
// Verify these offsets match actual memory layout
typedef struct {
    uint64_t unknown_0;     // Verify offset
    uint64_t size;          // Currently reading garbage
    uint64_t capacity;
    void *data;
} ArrayHeader;
```

**Discovery Method:**
- Use Frida to dump actual memory at HashMap address
- Compare with Windows structure definitions
- Adjust offsets accordingly

## Implementation Order

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| **P1** | Fix TypeId→Registry discovered flag | 30 min | Enables existing code path |
| **P2** | Find GetRawComponent dispatcher address | 2 hours | Correct approach |
| **P3** | Implement dispatcher pattern | 2 hours | Replaces broken template calls |
| **P4** | Fix ArrayHeader offsets | 1 hour | Robustness |

## Acceptance Criteria

### Functional Requirements
- [ ] `Ext.Entity.Get(guid):GetComponent("ecl::Character")` returns non-nil for character entities
- [ ] Component data is accessible (even if just as raw pointer initially)
- [ ] Works for at least 3 component types (ecl::Character, ecl::Item, ls::TransformComponent)

### Technical Requirements
- [ ] No crashes when accessing components
- [ ] Proper error messages when component not found (vs. nil)
- [ ] Logging shows dispatcher pattern being used

### Quality Gates
- [ ] EntityTest mod successfully retrieves component data
- [ ] No memory leaks from component access
- [ ] Works across game reload

## Technical Details

### Windows GetRawComponent Flow (Reference)

```
EntitySystemHelpersBase::GetRawComponent(handle, ExtComponentType)
  → Lookup ComponentTypeIndex from metadata
  → EntityWorld::GetRawComponent(handle, index, size, isProxy)
    → GetEntityStorage(handle)
      → Extract ThreadIndex, EntityIndex, Salt from handle
      → Validate salt
      → Return EntityStorageData*
    → EntityStorageData::GetComponent(handle, type, size, isProxy)
      → InstanceToPageMap.try_get(handle) → storage index
      → ComponentTypeToIndex.try_get(type) → slot index
      → Components[pageIndex]->Components[slot] → buffer
      → Calculate offset: buf + componentSize * entryIndex
```

### macOS Equivalent Discovery

Need to find in Ghidra:
1. `EntityWorld::GetRawComponent` or equivalent dispatcher
2. `EntityStorageContainer::GetEntityStorage`
3. `EntityStorageData::GetComponent`

**Search patterns:**
- Functions that take EntityHandle (64-bit) + uint16_t type index
- Functions that access `+0x2d0` offset (Storage field in EntityWorld)
- Functions with SparseHashMap access patterns

## Files to Modify

| File | Changes |
|------|---------|
| `src/entity/component_registry.c` | Fix discovered flag setting |
| `src/entity/component_typeid.c` | Add debug logging for registration |
| `src/entity/component_lookup.c` | Implement dispatcher pattern |
| `src/entity/entity_storage.h` | Add dispatcher address, fix ArrayHeader |
| `ghidra/offsets/COMPONENTS.md` | Document dispatcher address |

## Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| GetRawComponent doesn't exist on macOS | Medium | High | Fall back to EntityStorageData direct access |
| Structure offsets vary by game version | High | Medium | Add version detection, make offsets configurable |
| ARM64 calling convention issues | Low | Medium | Already have working arm64_call.c patterns |

## Success Metrics

- GetComponent returns non-nil for valid entities
- EntityTest mod outputs actual component data
- No crashes during 10-minute gameplay session with mod active

## References

### Internal
- `src/entity/component_registry.c:component_get_by_name()` - Current lookup logic
- `src/entity/component_typeid.c:component_typeid_discover()` - TypeId reading
- `ghidra/offsets/COMPONENTS.md` - Template addresses (to be deprecated)

### External
- Windows BG3SE: `BG3Extender/GameDefinitions/EntitySystem.cpp:457-484` - GetRawComponent
- Windows BG3SE: `BG3Extender/GameDefinitions/EntitySystem.cpp:235-276` - Storage access
