# BG3SE-macOS Roadmap

This document tracks the development roadmap for achieving feature parity with Windows BG3SE (Norbyte's Script Extender).

## Current Status: v0.9.9

**Working Features:**
- DYLD injection and Dobby hooking infrastructure
- Osiris event observation (2000+ events captured per session)
- Lua runtime with mod loading (BootstrapServer.lua, BootstrapClient.lua)
- Basic Ext.* API (Print, Require, RegisterListener, Json, IO)
- Osiris listener callbacks (before/after event dispatch)
- Dynamic Osi.* metatable with lazy function lookup
- PAK file extraction and Lua script loading
- Player GUID tracking from observed events

---

## Phase 1: Core Osiris Integration (Current)

### 1.1 Dynamic Osi.* Metatable
**Status:** Implemented (v0.9.9)

Lazy function lookup matching Windows BG3SE's OsirisBinding pattern:
- [x] `__index` metamethod intercepts unknown property accesses
- [x] Creates closures that dispatch via InternalQuery/InternalCall
- [x] Automatic Lua-to-Osiris argument type conversion
- [x] Result caching in Osi table for subsequent accesses
- [ ] **Query output parameters** - Return values from queries (not just bool)
- [ ] **Function type detection** - Distinguish Query vs Call vs Event

### 1.2 Function Discovery
**Status:** Partial

- [x] Event observation captures function IDs at runtime
- [x] Function name extraction from event arguments
- [x] Hash table cache for fast ID→name lookup
- [ ] **Safe enumeration via Ghidra offsets** - Use discovered offsets (0x9f348) without crashes
- [ ] **Pre-populate common functions** - Build initial cache from known function signatures

---

## Phase 2: Entity/Component System

### 2.1 Ext.Entity API
**Status:** Not Started

The entity system is fundamental to BG3 modding. Entities are game objects (characters, items, projectiles) with attached components.

**Target API:**
```lua
-- Get entity by GUID
local entity = Ext.Entity.Get(guid)

-- Access components
local transform = entity.Transform
local health = entity.Health
local stats = entity.Stats

-- Iterate entities
for _, entity in pairs(Ext.Entity.GetAllEntitiesWithComponent("Health")) do
    -- process
end
```

**Implementation approach:**
- Hook entity manager functions in the game binary
- Create Lua userdata proxies for entities
- Lazy component loading via `__index`
- Component type registry mapping C++ types to Lua

### 2.2 Component Access
**Status:** Not Started

Key components to support:
- Transform (position, rotation, scale)
- Health (HP, max HP, temp HP)
- Stats (abilities, skills, proficiencies)
- Inventory (items, equipment)
- StatusContainer (active statuses/buffs/debuffs)
- SpellBook (known spells, spell slots)

---

## Phase 3: Stats System

### 3.1 Ext.Stats API
**Status:** Not Started

Access and modify game statistics, character builds, and item properties.

**Target API:**
```lua
-- Get stat object
local stat = Ext.Stats.Get("Weapon_Longsword")

-- Modify stats
stat.Damage = "1d10"
stat.DamageType = "Slashing"

-- Create new stat
local newStat = Ext.Stats.Create("MyCustomWeapon", "Weapon")
newStat.Damage = "2d6"
```

**Implementation approach:**
- Locate stat manager in game memory via pattern scanning
- Parse stat file formats (.lsx, .lsf)
- Create modification layer that intercepts stat lookups
- Support runtime stat modification

### 3.2 Character Stats
**Status:** Not Started

- Ability scores (STR, DEX, CON, INT, WIS, CHA)
- Skills and proficiencies
- Armor class, saving throws
- Movement speed, initiative

---

## Phase 4: Custom Osiris Functions

### 4.1 Function Registration
**Status:** Not Started

Allow mods to register custom Osiris functions callable from story scripts.

**Target API:**
```lua
-- Register a custom query
Ext.Osiris.RegisterQuery("MyMod_IsPlayerNearby", 2, function(x, y)
    -- Custom logic
    return distance < 10
end)

-- Register a custom call
Ext.Osiris.RegisterCall("MyMod_SpawnEffect", 3, function(effect, x, y)
    -- Spawn visual effect
end)
```

**Implementation approach:**
- Hook Osiris function registration
- Create bridge functions that invoke Lua callbacks
- Handle type marshalling between Osiris and Lua
- Support IN/OUT parameter semantics

### 4.2 Story Script Integration
**Status:** Not Started

- Custom events triggerable from Lua
- Database manipulation (insert/delete/query)
- Goal completion tracking

---

## Phase 5: In-Game Console

### 5.1 Debug Console
**Status:** Not Started

Real-time Lua REPL accessible during gameplay.

**Features:**
- Toggle with hotkey (e.g., ~)
- Command history
- Autocomplete for Ext.* APIs
- Output scrollback
- Variable inspection

**Implementation approach:**
- Hook keyboard input
- Overlay rendering (or redirect to external terminal)
- Sandboxed Lua environment
- Pretty-printing for tables/entities

### 5.2 Debug Tools
**Status:** Not Started

- Entity inspector (click to examine)
- Position display
- Event logger toggle
- Performance profiler

---

## Phase 6: Networking & Co-op Sync

### 6.1 Ext.Net API
**Status:** Not Started

Synchronize mod state between host and clients in multiplayer.

**Target API:**
```lua
-- Host broadcasts to all clients
Ext.Net.BroadcastMessage("MyMod_StateUpdate", Ext.Json.Stringify(state))

-- Register message handler
Ext.Net.RegisterListener("MyMod_StateUpdate", function(channel, payload, userId)
    local state = Ext.Json.Parse(payload)
    -- Apply state
end)
```

**Implementation approach:**
- Hook game's network layer
- Piggyback on existing sync mechanisms
- Message queue with reliable delivery
- User ID tracking for sender identification

### 6.2 State Synchronization
**Status:** Not Started

- Automatic entity state sync
- Conflict resolution
- Bandwidth optimization
- Latency handling

---

## Phase 7: Type System

### 7.1 Full Type Definitions
**Status:** Not Started

Complete Lua type annotations for IDE support and runtime validation.

**Features:**
- LuaLS annotations for all Ext.* APIs
- Entity component type definitions
- Osiris function signatures
- Enum definitions (DamageType, StatusType, etc.)

**Deliverables:**
- `types/` folder with .lua definition files
- Integration with VS Code Lua extension
- Runtime type checking (optional)

### 7.2 IDE Integration
**Status:** Not Started

- Autocomplete for all APIs
- Inline documentation
- Error detection
- Go-to-definition support

---

## Technical Debt & Infrastructure

### Pattern Scanning Improvements
- [ ] Signature database for different game versions
- [ ] Automatic offset recalculation on game updates
- [ ] Fallback mechanisms when patterns fail

### Stability
- [ ] Crash recovery and logging
- [ ] Memory leak detection
- [ ] Thread safety audit
- [ ] Extensive error handling

### Testing
- [ ] Unit tests for Lua bindings
- [ ] Integration tests with mock game state
- [ ] Regression test suite
- [ ] Performance benchmarks

### Documentation
- [ ] API reference (generated from type definitions)
- [ ] Migration guide from Windows BG3SE
- [ ] Mod developer tutorials
- [ ] Architecture documentation

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v0.9.9 | 2025-11-28 | Dynamic Osi.* metatable, lazy function lookup |
| v0.9.5 | 2025-11-28 | Stable event observation, MRC mod support |
| v0.9.0 | 2025-11-27 | Initial Lua runtime, basic Ext.* API |

---

## Contributing

See [README.md](README.md) for build instructions. Key files:
- `src/injector/main.c` - Core injection and hooking logic
- `ghidra/OFFSETS.md` - Reverse-engineered memory offsets
- `ghidra/*.py` - Ghidra analysis scripts

## References

- [Windows BG3SE](https://github.com/Norbyte/bg3se) - Reference implementation
- [BG3 Modding Wiki](https://bg3.wiki/wiki/Modding) - Game mechanics documentation
- [Lua 5.4 Reference](https://www.lua.org/manual/5.4/) - Lua language reference
