# Plan: Stats Functor System (Issue #53)

## Overview

Implement the Stats Functor system for damage/effect calculations. Functors are the game's execution pipeline for applying damage, healing, status effects, and other combat mechanics.

## Current Status: ✅ Complete (Basic Implementation)

### Completed (2025-12-27)
- **Phase 1**: All 9 context handlers + main dispatcher found via Ghidra MCP
- **Phase 2**: Data structures defined in `src/stats/functor_types.h`
- **Phase 3**: Hooks installed in `src/stats/functor_hooks.c`, integrated in main.c
- **Phase 5**: Events registered in `src/lua/lua_events.h`

### Events Now Available
- `Ext.Events.ExecuteFunctor` - Fires before functor execution
- `Ext.Events.AfterExecuteFunctor` - Fires after functor execution

### Usage
```lua
Ext.Events.ExecuteFunctor:Subscribe(function(e)
    Ext.Print(string.format("Functor executing: context=%d", e.ContextType))
end)
```

### Future Work (Optional)
- Phase 4: Manual `Ext.Stats.ExecuteFunctors()` Lua API
- DealDamage/DealtDamage events (requires ApplyDamage hook)
- Rich parameter wrapping (not just raw pointers)

## Architecture Analysis (from Windows BG3SE)

### What Are Functors?

Functors are a chain of operations that the game executes when something happens (spell cast, attack, status tick, etc.). Each functor type has specific parameters and effects:

- **DealDamage** - Apply damage to target
- **Heal** - Restore HP
- **ApplyStatus** - Apply status effect
- **CreateSurface** - Create ground effects
- **Summon** - Spawn creatures
- **DoTeleport** - Move entities
- ~50+ other functor types

### Key Components

1. **Functor Execution Functions** (9 context types):
   ```
   esv::ExecuteStatsFunctor_AttackTargetContext
   esv::ExecuteStatsFunctor_AttackPositionContext
   esv::ExecuteStatsFunctor_MoveContext
   esv::ExecuteStatsFunctor_TargetContext
   esv::ExecuteStatsFunctor_NearbyAttackedContext
   esv::ExecuteStatsFunctor_NearbyAttackingContext
   esv::ExecuteStatsFunctor_EquipContext
   esv::ExecuteStatsFunctor_SourceContext
   esv::ExecuteStatsFunctor_InterruptContext
   ```

2. **Damage Functions**:
   ```
   stats::DealDamageFunctor::ApplyDamage
   esv::StatsSystem::ThrowDamageEvent
   ```

3. **Context Data Structures**:
   - `ContextData` - Base struct with Type, StoryActionId, PropertyContext, Originator
   - `AttackTargetContextData` - Caster, Target, Position, SpellId, Hit, Attack
   - (8 other context types)

4. **Lua Events**:
   - `ExecuteFunctor` / `AfterExecuteFunctor` - General functor execution
   - `BeforeDealDamage` - Before damage event fires
   - `DealDamage` / `DealtDamage` - During/after damage application

### Lua API

```lua
-- Execute functor chain with parameters
Ext.Stats.ExecuteFunctors(functors, params)

-- Execute single functor
Ext.Stats.ExecuteFunctor(functor, params)

-- Create context parameters
local params = Ext.Stats.PrepareFunctorParams(contextType)
params.Caster = casterEntity
params.Target = targetEntity
-- etc.
```

## Implementation Phases

### Phase 1: Ghidra Function Discovery
**Goal:** Find ARM64 addresses for all 11 key functions

**Functions discovered:**
| Function | macOS Address | Status |
|----------|--------------|--------|
| `ExecuteStatsFunctor` (main) | `0x105783a38` | ✅ Found |
| `ExecuteStatsFunctors` (AttackTarget) | `0x105787918` | ✅ Found |
| `ExecuteStatsFunctors` (AttackPosition) | `0x105787c6c` | ✅ Found |
| `ExecuteStatsFunctors` (Move) | `0x10578975c` | ✅ Found |
| `ExecuteStatsFunctors` (Target) | `0x10578a918` | ✅ Found |
| `ExecuteStatsFunctors` (NearbyAttacked) | `0x10578e4d8` | ✅ Found |
| `ExecuteStatsFunctors` (NearbyAttacking) | `0x10578fba8` | ✅ Found |
| `ExecuteStatsFunctors` (Equip) | `0x105790a28` | ✅ Found |
| `ExecuteStatsFunctors` (Source) | `0x105792a90` | ✅ Found |
| `ExecuteStatsFunctors` (Interrupt) | `0x1057965e4` | ✅ Found |
| `ProcessDealDamageFunctors` | `0x10538f374` | ✅ Found |
| `DealDamageFunctor::ApplyDamage` | - | ❌ Not found |
| `StatsSystem::ThrowDamageEvent` | - | ❌ Not found |

**Ghidra Search Strategy:**
1. Search for "ExecuteStatsFunctor" in function names (may have mangled C++ names)
2. Search for "DealDamage" patterns
3. Trace from known stats/combat functions
4. Look for functor dispatch patterns (switch on FunctorId)

### Phase 2: Data Structure Definitions
**Goal:** Define C structs matching game memory layout

**Files to create:**
- `src/stats/functor_types.h` - Functor type enum, context types
- `src/stats/functor_context.h` - Context data structures
- `src/stats/hit_result.h` - HitResult, HitDesc, AttackDesc

**Key structures (estimated from Windows):**
```c
typedef enum {
    FUNCTOR_CTX_ATTACK_TARGET = 0,
    FUNCTOR_CTX_ATTACK_POSITION = 1,
    FUNCTOR_CTX_MOVE = 2,
    FUNCTOR_CTX_TARGET = 3,
    FUNCTOR_CTX_NEARBY_ATTACKED = 4,
    FUNCTOR_CTX_NEARBY_ATTACKING = 5,
    FUNCTOR_CTX_EQUIP = 6,
    FUNCTOR_CTX_SOURCE = 7,
    FUNCTOR_CTX_INTERRUPT = 8,
} FunctorContextType;

typedef struct {
    void* vtable;
    FunctorContextType Type;
    int32_t StoryActionId;
    uint32_t PropertyContext;
    // ActionOriginator Originator;
    // ... more fields
} ContextData;

typedef struct {
    ContextData base;
    EntityRef Caster;
    EntityRef CasterProxy;
    EntityRef Target;
    EntityRef TargetProxy;
    float Position[3];
    bool IsFromItem;
    // SpellIdWithPrototype SpellId;
    // HitDesc Hit;
    // AttackDesc Attack;
} AttackTargetContextData;
```

### Phase 3: Hook Installation
**Goal:** Intercept functor execution to fire Lua events

**Approach:**
1. Create hook wrappers for each ExecuteStatsFunctor variant
2. Fire `ExecuteFunctor` event before calling original
3. Fire `AfterExecuteFunctor` event after original returns
4. Special handling for DealDamage path

**Files to modify:**
- `src/injector/main.c` - Add hook registrations
- `src/stats/functor_hooks.c` (new) - Hook implementations

### Phase 4: Lua Bindings
**Goal:** Expose functor execution to Lua

**Files to create:**
- `src/lua/lua_functor.c` - Lua bindings

**API:**
```lua
Ext.Stats.ExecuteFunctors(functors, context)
Ext.Stats.ExecuteFunctor(functor, context)
Ext.Stats.PrepareFunctorParams(contextType)
```

### Phase 5: Events Integration
**Goal:** Add functor events to Ext.Events

**Events to add:**
| Event | When | Data |
|-------|------|------|
| `ExecuteFunctor` | Before functor execution | {Functor, Params} |
| `AfterExecuteFunctor` | After functor execution | {Functor, Params, Hit} |
| `BeforeDealDamage` | Before damage calculation | {Hit, Attack} |
| `DealDamage` | During damage application | {Functor, Caster, Target, Hit, ...} |
| `DealtDamage` | After damage applied | {Functor, Caster, Target, Result, ...} |

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Functions not exported | HIGH | Pattern scan, trace from known funcs |
| ARM64 struct layout differs | MEDIUM | Runtime probing to verify offsets |
| Complex HitDesc/AttackDesc | MEDIUM | Start with minimal fields, expand |
| Hook conflicts | LOW | Use consistent hook ordering |

## Effort Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: Ghidra Discovery | 4-8 hours | Ghidra MCP |
| Phase 2: Data Structures | 2-3 hours | Phase 1 |
| Phase 3: Hook Installation | 3-4 hours | Phase 1, 2 |
| Phase 4: Lua Bindings | 2-3 hours | Phase 2, 3 |
| Phase 5: Events | 1-2 hours | Phase 3, 4 |
| **Total** | **12-20 hours** | |

## Next Actions

1. **Start Ghidra session** - Search for ExecuteStatsFunctor functions
2. **Find one context handler** - Verify function signature matches Windows
3. **Trace call graph** - Find related functions
4. **Document offsets** - Add to `ghidra/offsets/FUNCTORS.md`

## References

- Windows BG3SE: `BG3Extender/Lua/Libs/StatFunctors.inl`
- Windows BG3SE: `BG3Extender/Lua/Server/FunctorEvents.inl`
- Windows BG3SE: `BG3Extender/GameDefinitions/Stats/Functors.h`
