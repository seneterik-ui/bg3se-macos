# Complete eoc:: Component Discovery and Safe Function Caching

## Overview

This plan addresses GitHub Issue #2 (eoc:: component discovery) and the recent crash fix that disabled `osi_func_cache_from_event()`. The goal is to:

1. **Discover and enable eoc:: namespace components** (StatsComponent, HealthComponent, ArmorComponent, InventoryComponent, SpellBookComponent, StatusContainerComponent)
2. **Re-enable function name caching safely** using memory protection APIs instead of raw pointer dereferencing

## Problem Statement

### Current State

**Working (ls:: components):**
- Transform, Level, Physics, Visual - addresses known and functional

**Broken (eoc:: components):**
- StatsComponent, HealthComponent, ArmorComponent, etc. - need TypeId discovery
- Component strings found at known addresses but GetComponent addresses unknown

**Disabled (function caching):**
- `osi_func_cache_from_event()` disabled because `pFunctionData()` returns pointers that:
  - Pass address range validation (0x100000000 - 0x800000000000)
  - But point to GPU reserved memory (e.g., 0x49000004a6)
  - Cause SIGBUS when dereferenced

### Root Cause Analysis

**macOS ARM64 Specifics:**
- NO `GetRawComponent` dispatcher like Windows - templates are completely inlined
- Must use data structure traversal instead of calling template addresses
- TypeId globals exist but need runtime reading with ASLR slide calculation

**Pointer Validation Failure:**
- Simple range check insufficient for macOS address space
- GPU carveout region (0x1000000000-0x7000000000) overlaps "valid" userspace
- Need mach_vm_region or signal handlers for true validation

## Technical Approach

### Phase 1: Safe Memory Reading Infrastructure

**Chosen Approach: mach_vm_read + Address Validation**

Rationale: Signal handlers are process-global and may conflict with game's handlers. `mach_vm_read` is slower but safer and more predictable.

```c
// src/core/safe_memory.h
#ifndef SAFE_MEMORY_H
#define SAFE_MEMORY_H

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool is_valid;
    bool is_readable;
    mach_vm_address_t region_start;
    mach_vm_size_t region_size;
} AddressInfo;

// Check if address is in valid, readable memory region
AddressInfo safe_memory_check_address(mach_vm_address_t address);

// Safely read memory, returns false on failure
bool safe_memory_read(mach_vm_address_t source, void *dest, size_t size);

// Safely read a pointer value
bool safe_memory_read_pointer(mach_vm_address_t address, void **out_ptr);

// Safely read a string (up to max_len chars)
bool safe_memory_read_string(mach_vm_address_t address, char *buffer, size_t max_len);

#endif
```

```c
// src/core/safe_memory.c
#include "safe_memory.h"
#include <mach/mach_vm.h>

AddressInfo safe_memory_check_address(mach_vm_address_t address) {
    AddressInfo info = {0};

    mach_port_t task = mach_task_self();
    mach_vm_address_t region_addr = address;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t region_info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = mach_vm_region(
        task, &region_addr, &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&region_info,
        &info_count, &object_name
    );

    if (kr != KERN_SUCCESS) {
        return info;  // Invalid address
    }

    // Check if address falls within returned region
    if (address < region_addr || address >= region_addr + region_size) {
        return info;  // Address is in a gap
    }

    info.is_valid = true;
    info.is_readable = (region_info.protection & VM_PROT_READ) != 0;
    info.region_start = region_addr;
    info.region_size = region_size;

    return info;
}

bool safe_memory_read(mach_vm_address_t source, void *dest, size_t size) {
    mach_vm_size_t bytes_read = size;

    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        source, size,
        (mach_vm_address_t)dest,
        &bytes_read
    );

    return kr == KERN_SUCCESS && bytes_read == size;
}

bool safe_memory_read_pointer(mach_vm_address_t address, void **out_ptr) {
    return safe_memory_read(address, out_ptr, sizeof(void *));
}

bool safe_memory_read_string(mach_vm_address_t address, char *buffer, size_t max_len) {
    // Read one byte at a time until null or max_len
    for (size_t i = 0; i < max_len - 1; i++) {
        char c;
        if (!safe_memory_read(address + i, &c, 1)) {
            return false;
        }
        buffer[i] = c;
        if (c == '\0') {
            return true;
        }
    }
    buffer[max_len - 1] = '\0';
    return true;
}
```

### Phase 2: Fix Function Caching

**File: `src/osiris/osiris_functions.c`**

Replace disabled `osi_func_cache_from_event()` with safe version:

```c
void osi_func_cache_from_event(uint32_t funcId) {
    // Skip if already cached
    if (osi_func_get_name(funcId) != NULL) {
        return;
    }

    // Check runtime pointers are available
    if (!s_pfn_pFunctionData || !s_ppOsiFunctionMan) {
        return;
    }

    // Safely read OsiFunctionMan instance
    void *funcMan = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)s_ppOsiFunctionMan, &funcMan)) {
        return;
    }
    if (!funcMan) {
        return;
    }

    // Call pFunctionData to get function definition
    void *funcDef = s_pfn_pFunctionData(funcMan, funcId);
    if (!funcDef) {
        return;
    }

    // Validate funcDef pointer before dereferencing
    AddressInfo info = safe_memory_check_address((mach_vm_address_t)funcDef);
    if (!info.is_valid || !info.is_readable) {
        log_message("[FuncCache] funcDef %p is not readable (funcId=0x%08x)", funcDef, funcId);
        return;
    }

    // Safely read name pointer from funcDef + 0x08
    void *namePtr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)funcDef + 8, &namePtr)) {
        return;
    }

    // Validate name pointer
    info = safe_memory_check_address((mach_vm_address_t)namePtr);
    if (!info.is_valid || !info.is_readable) {
        return;
    }

    // Safely read name string
    char name[128];
    if (!safe_memory_read_string((mach_vm_address_t)namePtr, name, sizeof(name))) {
        return;
    }

    // Validate name format
    if (!is_valid_name_start(name[0])) {
        return;
    }

    // Safely read arity from funcDef + 0x20
    uint32_t paramCount = 0;
    if (!safe_memory_read((mach_vm_address_t)funcDef + 0x20, &paramCount, sizeof(paramCount))) {
        return;
    }

    uint8_t arity = (paramCount <= 20) ? (uint8_t)paramCount : 0;

    // Cache the function
    osi_func_cache(name, funcId, arity, 0);
}
```

### Phase 3: TypeId Discovery for eoc:: Components

**Strategy:** Read TypeId globals at known addresses with ASLR slide calculation.

**File: `src/entity/component_discovery.c`**

```c
#include "component_discovery.h"
#include "safe_memory.h"
#include "logging.h"
#include <mach-o/dyld.h>

// Known TypeId global addresses (from Ghidra analysis)
// These are offsets from BG3 binary base
typedef struct {
    const char *name;
    uint64_t ghidra_address;  // Address in Ghidra (base 0x100000000)
} ComponentTypeIdInfo;

static const ComponentTypeIdInfo g_eoc_components[] = {
    {"eoc::StatsComponent",           0x10890b058},
    {"eoc::HealthComponent",          0x10890a360},
    {"eoc::ArmorComponent",           0x108912e40},
    {"eoc::BaseHpComponent",          0x108907888},
    {"eoc::DataComponent",            0x10890b088},
    // Add more as discovered
    {NULL, 0}
};

#define GHIDRA_BASE 0x100000000

static intptr_t get_bg3_slide(void) {
    static intptr_t cached_slide = 0;
    static bool slide_cached = false;

    if (slide_cached) {
        return cached_slide;
    }

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "Baldur's Gate 3") != NULL) {
            cached_slide = _dyld_get_image_vmaddr_slide(i);
            slide_cached = true;
            return cached_slide;
        }
    }

    return 0;
}

int discover_eoc_component_typeids(void) {
    intptr_t slide = get_bg3_slide();
    if (slide == 0) {
        log_message("[ComponentDiscovery] Could not find BG3 binary slide");
        return 0;
    }

    int discovered = 0;

    for (int i = 0; g_eoc_components[i].name != NULL; i++) {
        const ComponentTypeIdInfo *comp = &g_eoc_components[i];

        // Calculate runtime address
        uint64_t offset = comp->ghidra_address - GHIDRA_BASE;
        mach_vm_address_t runtime_addr = (mach_vm_address_t)(offset + slide);

        // Validate address
        AddressInfo info = safe_memory_check_address(runtime_addr);
        if (!info.is_valid || !info.is_readable) {
            log_message("[ComponentDiscovery] %s: address 0x%llx not readable",
                       comp->name, runtime_addr);
            continue;
        }

        // Read TypeId value (int32_t)
        int32_t typeId = -1;
        if (!safe_memory_read(runtime_addr, &typeId, sizeof(typeId))) {
            log_message("[ComponentDiscovery] %s: failed to read TypeId",
                       comp->name);
            continue;
        }

        if (typeId < 0 || typeId > 1000) {
            log_message("[ComponentDiscovery] %s: invalid TypeId %d",
                       comp->name, typeId);
            continue;
        }

        // Register in component registry
        component_registry_set_index(comp->name, (uint16_t)typeId);
        discovered++;

        log_message("[ComponentDiscovery] %s: TypeId=%d (from 0x%llx)",
                   comp->name, typeId, runtime_addr);
    }

    return discovered;
}
```

### Phase 4: Component Registry Integration

**File: `src/entity/entity_system.c`**

Add discovered eoc:: components to the existing registry:

```c
// In entity_init() or similar initialization function
void entity_discover_components(void) {
    // Existing ls:: component discovery...

    // Add eoc:: component discovery
    int eoc_count = discover_eoc_component_typeids();
    log_message("[Entity] Discovered %d eoc:: component TypeIds", eoc_count);
}
```

### Phase 5: Update GetComponent to Use Registry

Ensure `entity_get_component()` uses the discovered TypeIds from registry:

```c
void *entity_get_component(void *entity, const char *component_name) {
    // Normalize name (strip "eoc::" or "ls::" prefix if present)
    const char *normalized = normalize_component_name(component_name);

    // Look up in registry
    ComponentInfo *info = component_registry_get(normalized);
    if (!info || info->typeIndex == 0xFFFF) {
        log_message("[Entity] Component '%s' not in registry", component_name);
        return NULL;
    }

    // Use data structure traversal with discovered TypeId
    return entity_get_component_by_index(entity, info->typeIndex);
}
```

## Acceptance Criteria

### Functional Requirements

- [ ] `safe_memory_read()` correctly returns false for GPU reserved memory
- [ ] `osi_func_cache_from_event()` no longer causes SIGBUS crashes
- [ ] Function names are cached at runtime for observed Osiris events
- [ ] At least 4 of 6 eoc:: components have TypeIds discovered
- [ ] `Ext.Entity.GetComponent("StatsComponent")` returns valid data for player entities
- [ ] `Ext.Entity.GetComponent("HealthComponent")` returns valid data

### Non-Functional Requirements

- [ ] Memory validation overhead < 1ms per call (acceptable for event handlers)
- [ ] TypeId discovery completes during initialization (< 100ms)
- [ ] No crashes during 30-minute gameplay session
- [ ] Logs clearly indicate which components were/weren't discovered

### Quality Gates

- [ ] Build completes without warnings
- [ ] Manual test: load save, play 5 minutes, no crashes
- [ ] Manual test: Lua mod can read StatsComponent values
- [ ] Code review: safe_memory.c follows mach API best practices

## Implementation Phases

### Phase 1: Foundation (safe_memory.c)
- Create `src/core/safe_memory.h` and `src/core/safe_memory.c`
- Add to CMakeLists.txt
- Unit test with known valid/invalid addresses
- **Estimated effort:** 1-2 hours

### Phase 2: Fix Function Caching
- Update `osi_func_cache_from_event()` to use safe_memory APIs
- Remove `#if 0` disabled code
- Test with game running
- **Estimated effort:** 1 hour

### Phase 3: TypeId Discovery
- Create `src/entity/component_discovery.c`
- Find TypeId addresses for remaining eoc:: components via Ghidra
- Integrate with entity_init()
- **Estimated effort:** 2-3 hours (includes Ghidra work)

### Phase 4: Integration & Testing
- Update GetComponent path to use discovered TypeIds
- Test with EntityTest mod
- Verify StatsComponent/HealthComponent access
- **Estimated effort:** 1-2 hours

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| mach_vm_read too slow | Low | Medium | Cache validation results per-page |
| TypeId addresses wrong post-patch | High | High | Document update process, signature scan fallback |
| Some components have different structure | Medium | Medium | Validate returned data, graceful degradation |
| Multi-threading issues | Medium | High | Document thread constraints, add warnings |

## Dependencies & Prerequisites

- Ghidra analysis for remaining TypeId addresses
- Understanding of BG3 game state transitions (save/load)
- Test save file with accessible player entities

## Future Considerations

1. **Signature Scanning:** Instead of hardcoded addresses, scan for patterns
2. **Component Validation:** Verify component data structure matches expected layout
3. **Cache Invalidation:** Hook save/load events to clear component caches
4. **Thread Safety:** Add mutex if multi-threaded access becomes necessary

## References

### Internal References
- `ghidra/offsets/COMPONENTS.md` - Known component addresses
- `ghidra/offsets/ENTITY_SYSTEM.md` - ECS architecture
- `docs/COMPONENT_NIL_ROOT_CAUSE.md` - Why templates don't work

### External References
- [Apple mach_vm documentation](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/vm/vm.html)
- [Windows BG3SE EntitySystem.cpp](https://github.com/Norbyte/bg3se) - Reference patterns

### Related Issues
- #1 - GUID to EntityHandle lookup (resolved)
- #2 - eoc:: component discovery (this plan)
