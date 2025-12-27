# Plan: Fix One-Frame Component Events

## Problem Statement

Engine events (TurnStarted, TurnEnded, SpellCast, etc.) are not firing despite:
- TypeIds being in the registry
- Event handlers being subscribed
- Console showing 0 entities for these components

## Root Cause Analysis

### What Changed (Last 3 Commits)

1. **cec1a5a** - Added guards for `typeIndex == 0xFFFF` (silent return)
2. **ac5127f** - Original one-frame polling implementation
3. **5b23f29** - Decorative commit (no code changes)

The guard changes are correct - they prevent log spam. But they also mean if TypeId discovery fails, we silently get 0 entities.

### Core Issue: Two Separate Problems

**Problem 1: Client vs Server Context**
- We're in Client context (`Ext.IsServer() = false`)
- One-frame components like `esv::TurnStartedEventOneFrameComponent` are SERVER components
- Client EntityWorld doesn't contain server components

**Problem 2: OneFrameComponents Pool**
- Windows BG3SE stores one-frame components in a separate pool (`storage->OneFrameComponents`)
- Our `GetAllEntitiesWithComponent` only checks regular component storage
- Even if we were in server context, we'd need to access the OneFrame pool

## Evidence

```lua
-- These work (regular components)
eoc::HealthComponent: 9215
ls::TransformComponent: 65536

-- These return 0 (one-frame components)
esv::TurnStartedEventOneFrameComponent: 0
esv::TurnEndedEventOneFrameComponent: 0
eoc::spell_cast::CastEventOneFrameComponent: 0
```

## Solutions

### Option A: Osiris Event Bridge (Quick Fix)
Fire Ext.Events from Osiris callbacks instead of polling.

Pros:
- Works immediately
- Uses existing Osiris hooks
- No RE needed

Cons:
- Less granular than Windows BG3SE
- May not capture all events

### Option B: OneFrameComponents Pool Access (Full Fix)
Reverse engineer the OneFrameComponents storage structure.

Requires:
1. Find `OneFrameComponents` pool offset in EntityStorageData
2. Find `IsOneFrame()` flag for component types
3. Implement pool iteration

Pros:
- Full Windows BG3SE parity
- Works for all one-frame events

Cons:
- Significant RE work
- May vary by game version

### Option C: Hybrid Approach (Recommended)
1. Implement Osiris bridge for immediate functionality (Option A)
2. Plan RE work for OneFrameComponents access (Option B)
3. Switch to native access once RE is complete

## Ghidra RE Findings (Dec 26, 2025)

### IsOneFrame Detection
From Windows BG3SE `EntitySystem.h:66`:
```cpp
inline constexpr bool IsOneFrame(ComponentTypeIndex idx)
{
    return (TComponentTypeIndex(idx) & 0x8000) == 0x8000;
}
```
**Key insight: Bit 15 (0x8000) of TypeIndex indicates one-frame component.**

### OneFrameComponents Structure
From Windows BG3SE `EntitySystem.h:526-527`:
```cpp
HashMap<ComponentTypeIndex, HashMap<EntityHandle, void*>> OneFrameComponents;
bool HasOneFrameComponents;
```

### EntityStorageData Offsets (macOS ARM64)
From `EntityStorageClearFrameData` at 0x10636de80:
- `0x200` - HashMap (OneFrameComponents or related)
- `0x240` - HashMap (secondary frame storage)
- `0x280` - DynamicArray (ComponentAddedEntityMap)
- `0x290` - DynamicArray (ComponentRemovedEntityMap)
- `0x2a0` - HashTable<ComponentId>
- `0x2c0` - DynamicArray<ComponentId>
- `0x2d0` - Pointer array
- `0x2e0` - Boolean flag (likely HasOneFrameComponents)
- `0x2f0-0x308` - Bitmasks

### Access Pattern (from Entity.inl:109-116)
```cpp
if (ecs::IsOneFrame(*componentType)) {
    for (auto cls : world->Storage->Entities) {
        if (cls->HasOneFrameComponents) {
            auto pool = cls->OneFrameComponents.try_get(*componentType);
            if (pool) {
                std::copy(pool->keys().begin(), pool->keys().end(), ...);
            }
        }
    }
}
```

## Implementation Plan

### Phase 1: IsOneFrame Detection (Easy)
1. [x] Add IsOneFrame check: `(typeIndex & 0x8000) == 0x8000`
2. [ ] Log when detecting one-frame components

### Phase 2: Osiris Bridge (Quick Fix)
1. [ ] Implement Osiris → Ext.Events bridge for key events:
   - TurnStarted, TurnEnded
   - CombatStarted, CombatEnded
   - CharacterDied, CharacterResurrected

### Phase 3: Native Pool Access (Full Parity)
1. [ ] Verify OneFrameComponents offset (~0x200 in EntityStorageData)
2. [ ] Implement HashMap iteration for one-frame pools
3. [ ] Add to GetAllEntitiesWithComponent

## Testing Results (v0.36.12 - Dec 26, 2025)

### Key Discovery: Osiris Turn Events Work!

**Tested in actual combat:**
```
[Lua] Osiris TurnStarted: S_Player_Astarion_c7c13742-bacd-460a-8f65-f864fe41f255
[Lua] Osiris TurnEnded: S_Player_Astarion_c7c13742-bacd-460a-8f65-f864fe41f255
[Lua] Osiris TurnStarted: S_UND_PlantDuergar_001_be7b7b75-03fb-4040-9d8c-14e1e8d9882c
```

**Important distinction:**
- `TurnStarted`/`TurnEnded` are Osiris events (not just OneFrame components)
- They fire in **actual combat**, not in force turn-based exploration mode
- `EnteredForceTurnBased`/`LeftForceTurnBased` fire for turn-based exploration

### OneFrame Pool Access Status

The infrastructure is in place:
- [x] `get_oneframe_entities()` implemented at offset 0x2A0
- [x] `HasOneFrameComponents` check at offset 0x2E0
- [x] Proper bucket-based HashMap lookup (`hashmap_find_index_u16`)
- [ ] Returns 0 in client context (expected - `esv::` components are server-side)
- [ ] Need server EntityWorld capture for `esv::` component access

### Updated Conclusions

1. **Osiris bridge works for turn events** - No additional RE needed
2. **OneFrame polling infrastructure ready** - Just needs server EntityWorld
3. **Ext.Log API verified** - Module-aware logging working

## Next Steps

1. [x] Document IsOneFrame bit pattern (0x8000)
2. [x] Implement OneFrame pool access code
3. [x] Verify Osiris TurnStarted/TurnEnded work in combat
4. [ ] Capture server EntityWorld for `esv::` components
5. [x] Bridge Osiris events to Ext.Events for turn events (v0.36.13)

## Implementation Details (v0.36.13)

### Osiris → Ext.Events Bridge

Added in `dispatch_event_to_lua` (main.c:2221-2240):
- Detects `TurnStarted` and `TurnEnded` Osiris events
- Extracts character GUID from first argument
- Fires `events_fire_turn_started_from_osiris()` / `events_fire_turn_ended_from_osiris()`

New functions in lua_events.c (858-963):
- `events_fire_turn_started_from_osiris(L, characterGuid)`
- `events_fire_turn_ended_from_osiris(L, characterGuid)`
- Handlers receive `{CharacterGuid = "..."}`

**Usage:**
```lua
Ext.Events.TurnStarted:Subscribe(function(e)
    Ext.Print("Turn started: " .. (e.CharacterGuid or "nil"))
end)
```

## References

- Windows BG3SE: `BG3Extender/Lua/Libs/Entity.inl` lines 96-100
- Windows BG3SE: `BG3Extender/GameDefinitions/EntitySystem.h` lines 66, 526-527
- Ghidra: `EntityStorageClearFrameData` at 0x10636de80
- Issue #51: Event system expansion
