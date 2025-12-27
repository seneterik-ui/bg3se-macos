# Plan: Client EntityWorld Discovery

## Status: ✅ COMPLETE (Dec 27, 2025)

**Result:** `ecl::EocClient::m_ptr` discovered at address `0x10898c968`

## Problem Statement

We need to find `ecl::EocClient::m_ptr` - the static global pointer to the client singleton - to enable:
1. Access to `ecl::` components from Lua
2. Proper client/server context separation
3. Client-side event detection via OneFrame components

## Discovery Results

### Found Addresses
| Symbol | Address | Notes |
|--------|---------|-------|
| `ecl::EocClient::m_ptr` | `0x10898c968` | Global pointer to client singleton |
| `EoCClient + 0x1B0` | - | EntityWorld* (estimated from Windows) |
| `EoCClient + 0x1B8` | - | PermissionsManager* (verified) |

### Discovery Method
Via Ghidra analysis of `gui::DataContextProvider::CreateDataContextClass` at `0x1024f008c`:

```asm
1024f0218: adrp x8,0x10898c000
1024f021c: ldr x25,[x8, #0x968]   ; Load ecl::EocClient::m_ptr
1024f0228: add x26,x25,#0x1b8    ; PermissionsManager at EocClient+0x1b8
```

### Implementation
Updated `src/entity/entity_system.c`:
```c
#define OFFSET_EOCCLIENT_SINGLETON_PTR 0x10898c968
#define OFFSET_ENTITYWORLD_IN_EOCCLIENT 0x1B0
```

## Previous State (Before Discovery)

### What We Had
- **Server singleton**: `0x10898e8b8` (Ghidra) → EoCServer → EntityWorld at +0x288
- **Infrastructure ready**: `g_ClientEntityWorld`, `g_RuntimeClientSingletonAddr`, Lua APIs
- **Heap candidates found**: 0x132224e50, 0x13222de50, 0x132232e50 (structures with EW-like pointers)

### What We Needed
- The **global pointer address** (like `0x10898e8b8` for server) that points to EoCClient singleton
- OR a **hook-based capture** approach if no static global exists

## Discovery Approaches

### Approach 1: Ghidra Static Analysis (High Priority)

**Goal**: Find `ecl::EocClient::m_ptr` symbol or access pattern

**Steps**:
1. Search for `ecl::EocClient` in function names
2. Find `GetEntityWorld` or `GetClientEntityWorld` functions
3. Look for `TryGetSingleton<ecl::EocClient>` patterns
4. Trace `__GLOBAL__sub_I_EocClient.cpp` initializer (at 0x1065be528)
5. Find `MakePtr` functions taking `ecl::EocClient&`

**Key Ghidra Commands**:
```
mcp__ghidra__search_functions_by_name(query="EocClient")
mcp__ghidra__search_functions_by_name(query="ClientEntityWorld")
mcp__ghidra__decompile_function(name="__GLOBAL__sub_I_EocClient.cpp")
```

**Expected Pattern** (based on server):
```asm
adrp x8, #ecl__EocClient_m_ptr@PAGE
ldr  x8, [x8, #ecl__EocClient_m_ptr@PAGEOFF]
; x8 now contains EocClient*
ldr  x0, [x8, #0x1B0]  ; EntityWorld offset (estimated)
```

### Approach 2: Hook-Based Capture (Medium Priority)

**Goal**: Capture EoCClient pointer via function hook

**Candidate Functions**:
1. `ecl::EocClient::StartUp()` - Called during client initialization
2. `ecl::GameStateEventManager::OnGameStateChanged()` - May receive EoCClient
3. `ecl::EocClient::Update()` - Called every frame
4. `ecl::level::LevelManager::GetEntityWorld()` - Returns client EntityWorld

**Implementation**:
```c
// Hook ecl::EocClient::StartUp or similar
static void (*orig_EocClientStartUp)(void* eocClient, void* init);
static void hook_EocClientStartUp(void* eocClient, void* init) {
    g_EoCClient = eocClient;
    g_ClientEntityWorld = *(void**)((char*)eocClient + OFFSET_ENTITYWORLD_IN_EOCCLIENT);
    log_message("Captured EoCClient: %p, EntityWorld: %p", eocClient, g_ClientEntityWorld);
    orig_EocClientStartUp(eocClient, init);
}
```

**Ghidra Tasks**:
1. Find `ecl::EocClient::StartUp` address
2. Verify function signature
3. Find EntityWorld offset within EocClient struct

### Approach 3: Instruction Pattern Scan (Medium Priority)

**Goal**: Find ADRP+LDR patterns that load EoCClient singleton

**Pattern to Search**:
```
ADRP  Xn, <high-bits>
LDR   Xn, [Xn, <low-offset>]
; Followed by access to offset ~0x1B0 for EntityWorld
```

**Implementation**:
```c
// Scan for instruction patterns similar to server singleton access
// 1. Find functions that access both EoCServer and EoCClient
// 2. Look for paired ADRP+LDR with different target addresses
// 3. The one NOT pointing to 0x10898e8b8 is likely client
```

### Approach 4: Windows BG3SE Reference Analysis (Low Priority)

**Goal**: Understand how Windows finds client singleton

**Files to Check**:
- `BG3Extender/GameDefinitions/GameState.h` - EoCClient struct
- `BG3Extender/GameDefinitions/EntitySystem.cpp` - GetClientEntityWorld()
- `BG3Extender/Extender/Client/IMGUI/*` - Client-side code

**Key Code** (from Windows):
```cpp
// GameState.h line ~207
struct EoCClient {
    // ...
    EntityWorld* EntityWorld;  // Offset to find
    // ...
};

// How Windows accesses it:
ecl::EoCClient** ecl__EoCClient;  // Global pointer to pointer
EntityWorld* GetClientEntityWorld() {
    return (*ecl__EoCClient)->EntityWorld;
}
```

### Approach 5: Runtime Memory Scan (Fallback)

**Goal**: Find global pointer by scanning data segment for heap addresses

**Current Implementation** (needs refinement):
```lua
-- Scan data segment for pointers to candidate singletons
local candidates = {0x132224e50, 0x13222de50, 0x132232e50}
for ptr = DATA_START, DATA_END, 8 do
    local val = Ext.Debug.ReadPtr(ptr)
    if table_contains(candidates, val) then
        print(string.format("Found global at 0x%x pointing to 0x%x", ptr, val))
    end
end
```

**Issues**:
- Candidates may not be EoCClient - could be other game objects
- Global pointer may be in different segment
- May need to search wider range

## Verification Strategy

Once candidate address is found:

```lua
-- 1. Set the address
Ext.Entity.SetClientSingleton(DISCOVERED_ADDRESS)

-- 2. Verify client world is captured
local cw = Ext.Entity.GetClientWorld()
print("Client world:", cw)  -- Should not be nil

-- 3. Verify it's different from server world
local sw = Ext.Entity.GetServerWorld()
print("Server world:", sw)
assert(cw ~= sw, "Client and server worlds should be different")

-- 4. Test ecl:: component query
local ecl_entities = Ext.Entity.GetAllEntitiesWithComponent("ecl::Character")
print("ecl::Character count:", #ecl_entities)
```

## Implementation Order

| Priority | Approach | Effort | Success Probability |
|----------|----------|--------|---------------------|
| 1 | Ghidra Static Analysis | Medium | High (if MCP works) |
| 2 | Hook-Based Capture | Medium | High |
| 3 | Instruction Pattern Scan | High | Medium |
| 4 | Windows Reference Analysis | Low | Medium |
| 5 | Runtime Memory Scan | Low | Low |

## Files to Modify

Once address is discovered:

1. **`src/entity/entity_system.c`**:
   - Update `OFFSET_EOCCLIENT_SINGLETON_PTR` from 0x0 to actual address
   - Verify `OFFSET_ENTITYWORLD_IN_EOCCLIENT` (currently 0x1B0, may differ)

2. **`ghidra/offsets/ENTITY_SYSTEM.md`**:
   - Document client singleton address
   - Document EoCClient struct offsets

3. **`docs/CHANGELOG.md`**:
   - Record discovery in next version

## Risk Assessment

| Risk | Probability | Mitigation |
|------|-------------|------------|
| Client singleton doesn't exist as static global | Low | Use hook-based capture instead |
| EntityWorld offset differs from estimate | Medium | Probe multiple offsets at runtime |
| Address varies by game version | High | Add pattern scan as fallback |
| Ghidra MCP continues to timeout | Medium | Use headless scripts or manual analysis |

## Next Actions

1. **When Ghidra is available**: Run the static analysis queries
2. **Without Ghidra**: Implement hook-based capture for `ecl::EocClient::StartUp`
3. **Document findings** in `ghidra/offsets/ENTITY_SYSTEM.md`

## References

- `plans/graceful-meandering-fairy.md` - Original plan with probe results
- `src/entity/entity_system.c` - Current dual world implementation
- `ghidra/offsets/ENTITY_SYSTEM.md` - Server singleton documentation
- Windows BG3SE `BG3Extender/GameDefinitions/GameState.h`
