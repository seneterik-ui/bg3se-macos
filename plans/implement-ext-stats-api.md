# Plan: Implement Ext.Stats API (Issue #3)

## Overview

Implement the `Ext.Stats` API for accessing and modifying game statistics, character builds, and item properties. This is a core feature required for mod compatibility with Windows BG3SE.

**Priority:** High - Many mods require stat access/modification
**Complexity:** High - Requires reverse engineering, memory safety, type system
**Estimated Phases:** 4 phases

## Problem Statement / Motivation

Currently, bg3se-macos cannot:
- Read game stat definitions (weapons, armor, spells, statuses)
- Modify stat properties at runtime
- Create new stat entries for custom content

This blocks compatibility with mods that:
- Rebalance weapons/spells
- Add custom items
- Modify character progression
- Create new abilities

## Proposed Solution

Implement a stats system following the Windows BG3SE pattern:

```lua
-- Get stat object by name
local stat = Ext.Stats.Get("Weapon_Longsword")

-- Read properties
local damage = stat.Damage
local damageType = stat.DamageType

-- Modify properties
stat.Damage = "2d6"
stat.DamageType = "Fire"

-- Sync to update game
Ext.Stats.Sync("Weapon_Longsword")

-- Create new stat
local newStat = Ext.Stats.Create("MyCustomWeapon", "Weapon", "Weapon_Longsword")
newStat.Damage = "3d8"
Ext.Stats.Sync("MyCustomWeapon")

-- Discovery
local allWeapons = Ext.Stats.GetAll("Weapon")
```

---

## Technical Approach

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Lua API Layer                              │
│  Ext.Stats.Get() / Create() / Sync() / GetAll()                  │
│  StatsObject userdata with __index/__newindex metamethods        │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│                     Stats Manager Module                          │
│  src/stats/stats_manager.c                                       │
│  - Locates RPGStats global pointer                               │
│  - Provides C API: stats_get(), stats_create(), stats_sync()     │
│  - Type validation and property access                           │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│                     Game Memory (RPGStats)                        │
│  - CNamedElementManager<Object> Objects                          │
│  - CNamedElementManager<ModifierList> ModifierLists              │
│  - Property pools (strings, floats, ints, GUIDs)                 │
└──────────────────────────────────────────────────────────────────┘
```

### Windows BG3SE Reference Structures

From `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Stats/`:

```cpp
// Stats.h - RPGStats manager
struct RPGStats : public ProtectedGameObject<RPGStats> {
    CNamedElementManager<Object> Objects;           // All stat objects
    CNamedElementManager<ModifierList> ModifierLists;  // Type definitions
    CNamedElementManager<RPGEnumeration> ModifierValueLists;  // Enums
    // Property pools
    TrackedCompactSet<FixedString> FixedStrings;
    Array<int64_t*> Int64s;
    Array<float> Floats;
    Array<Guid> GUIDs;
};

// StatsObject.inl - Stats Object
struct Object : public Noncopyable<Object> {
    void* VMT{ nullptr };
    Vector<int32_t> IndexedProperties;  // Indices into pools
    FixedString Name;
    uint32_t ModifierListIndex{ 0 };    // Type (Weapon, Armor, etc.)
    uint32_t Level{ 0 };
    // ...
};

// Symbols.h - Global access
stats::RPGStats** gRPGStats{ nullptr };
```

---

## Implementation Phases

### Phase 1: RPGStats Discovery & Core Module

**Goal:** Locate the stats manager in memory and create base infrastructure.

**Tasks:**

1. **Ghidra Analysis for RPGStats**
   - Search for `RPGStats` or `gRPGStats` symbol in main binary
   - Pattern scan for RPGStats::GetStats() function
   - Find global pointer offset similar to EntityWorld discovery
   - Document findings in `ghidra/offsets/STATS.md`

2. **Create stats_manager module**
   - File: `src/stats/stats_manager.c`
   - File: `src/stats/stats_manager.h`
   - Pattern follows `entity_system.c` design

   ```c
   // stats_manager.h
   #ifndef STATS_MANAGER_H
   #define STATS_MANAGER_H

   #include <stdbool.h>
   #include <stdint.h>

   // Opaque handle to stats object
   typedef struct StatsObject StatsObject;

   // Initialization
   void stats_manager_init(void);
   bool stats_manager_is_ready(void);

   // Core operations
   StatsObject* stats_get_object(const char *name);
   StatsObject* stats_create_object(const char *name, const char *type, const char *template_name);
   bool stats_sync_object(const char *name);

   // Property access
   const char* stats_object_get_name(StatsObject *obj);
   const char* stats_object_get_type(StatsObject *obj);
   int stats_object_get_int(StatsObject *obj, const char *prop);
   float stats_object_get_float(StatsObject *obj, const char *prop);
   const char* stats_object_get_string(StatsObject *obj, const char *prop);
   bool stats_object_set_int(StatsObject *obj, const char *prop, int value);
   bool stats_object_set_float(StatsObject *obj, const char *prop, float value);
   bool stats_object_set_string(StatsObject *obj, const char *prop, const char *value);

   // Enumeration
   int stats_get_count(const char *type);  // NULL = all types
   const char* stats_get_name_at(const char *type, int index);

   #endif
   ```

3. **Safe memory access patterns**
   - Use existing `safe_memory_read_*` APIs from `safe_memory.h`
   - Add stats-specific validation for pointer chains

4. **Add to build**
   - Update `CMakeLists.txt` to include new sources

**Deliverables:**
- `src/stats/stats_manager.c` - Core implementation
- `src/stats/stats_manager.h` - Public API
- `ghidra/offsets/STATS.md` - Documented offsets
- Updated `CMakeLists.txt`

**Success Criteria:**
- `stats_manager_init()` successfully locates RPGStats
- `stats_manager_is_ready()` returns true after game loads stats
- Basic `stats_get_object("Weapon_Longsword")` returns non-null

---

### Phase 2: Lua Bindings & Basic Get

**Goal:** Expose stats to Lua with read-only access.

**Tasks:**

1. **Create Lua bindings module**
   - File: `src/lua/lua_stats.c`
   - File: `src/lua/lua_stats.h`

   ```c
   // lua_stats.h
   #ifndef LUA_STATS_H
   #define LUA_STATS_H

   #include <lua.h>

   void lua_stats_register(lua_State *L, int ext_table_index);

   #endif

   // lua_stats.c
   #include "lua_stats.h"
   #include "stats_manager.h"

   // StatsObject userdata with metatable
   static int lua_stats_get(lua_State *L) {
       const char *name = luaL_checkstring(L, 1);
       StatsObject *obj = stats_get_object(name);
       if (!obj) {
           lua_pushnil(L);
           lua_pushstring(L, "Stat not found");
           return 2;
       }

       StatsObject **ud = lua_newuserdata(L, sizeof(StatsObject*));
       *ud = obj;
       luaL_getmetatable(L, "StatsObject");
       lua_setmetatable(L, -2);
       return 1;
   }

   static int lua_stats_object_index(lua_State *L) {
       StatsObject **ud = luaL_checkudata(L, 1, "StatsObject");
       const char *key = luaL_checkstring(L, 2);

       // Special properties
       if (strcmp(key, "Name") == 0) {
           lua_pushstring(L, stats_object_get_name(*ud));
           return 1;
       }

       // Try string first, then int, then float
       const char *str = stats_object_get_string(*ud, key);
       if (str) {
           lua_pushstring(L, str);
           return 1;
       }

       // ... try other types
       lua_pushnil(L);
       return 1;
   }
   ```

2. **Register with main.c**
   - Add `#include "lua_stats.h"`
   - Call `lua_stats_register(L, ext_index)` in `init_lua()`

3. **Implement GetAll enumeration**
   ```lua
   local weapons = Ext.Stats.GetAll("Weapon")
   for _, name in ipairs(weapons) do
       print(name)
   end
   ```

**Deliverables:**
- `src/lua/lua_stats.c` - Lua bindings
- `src/lua/lua_stats.h` - Header
- Updated `main.c` registration

**Success Criteria:**
- `Ext.Stats.Get("Weapon_Longsword")` returns userdata
- Property access works: `stat.Damage`, `stat.Name`
- `Ext.Stats.GetAll("Weapon")` returns array of names

---

### Phase 3: Property Modification & Sync

**Goal:** Enable stats modification with game synchronization.

**Tasks:**

1. **Implement property setters**
   - Add `__newindex` metamethod to StatsObject
   - Type detection and validation
   - Call appropriate `stats_object_set_*` function

   ```c
   static int lua_stats_object_newindex(lua_State *L) {
       StatsObject **ud = luaL_checkudata(L, 1, "StatsObject");
       const char *key = luaL_checkstring(L, 2);

       // Determine value type and set
       if (lua_isstring(L, 3)) {
           const char *value = lua_tostring(L, 3);
           if (!stats_object_set_string(*ud, key, value)) {
               return luaL_error(L, "Failed to set property '%s'", key);
           }
       } else if (lua_isnumber(L, 3)) {
           // Check if int or float
           lua_Number n = lua_tonumber(L, 3);
           if (n == (int)n) {
               stats_object_set_int(*ud, key, (int)n);
           } else {
               stats_object_set_float(*ud, key, (float)n);
           }
       }
       return 0;
   }
   ```

2. **Implement Sync function**
   - Call game's prototype manager update functions
   - Find sync functions via pattern scanning:
     - `SpellPrototypeManager::Sync`
     - `StatusPrototypeManager::Sync`
     - `PassivePrototypeManager::Sync`

   ```c
   bool stats_sync_object(const char *name) {
       StatsObject *obj = stats_get_object(name);
       if (!obj) return false;

       // Get stat type
       const char *type = stats_object_get_type(obj);

       // Call appropriate prototype manager sync
       if (strcmp(type, "SpellData") == 0) {
           // sync_spell_prototype(name);
       } else if (strcmp(type, "StatusData") == 0) {
           // sync_status_prototype(name);
       }
       // ... etc

       return true;
   }
   ```

3. **Add Lua Sync binding**
   ```lua
   Ext.Stats.Sync("Weapon_Longsword")
   -- or
   Ext.Stats.Sync()  -- Sync all modified
   ```

**Deliverables:**
- Updated `lua_stats.c` with `__newindex`
- Sync implementation in `stats_manager.c`
- Pattern scanning for prototype managers

**Success Criteria:**
- `stat.Damage = "2d6"` modifies memory
- `Ext.Stats.Sync()` updates game state
- Changes visible in game after sync

---

### Phase 4: Stat Creation & Polish

**Goal:** Enable creating new stats and finalize API.

**Tasks:**

1. **Implement Create function**
   - Allocate new stats object
   - Copy from template if provided
   - Register in stats manager

   ```c
   StatsObject* stats_create_object(const char *name, const char *type, const char *template_name) {
       // Check if name already exists
       if (stats_get_object(name)) {
           log_message("[Stats] Object '%s' already exists", name);
           return NULL;
       }

       // Allocate and initialize
       // Call game's CreateObject function
       // Copy template properties if template_name provided

       return new_object;
   }
   ```

2. **Add type validation**
   - Validate stat types: Weapon, Armor, Character, SpellData, StatusData, PassiveData, InterruptData
   - Validate property names per type
   - Return meaningful error messages

3. **Add debug/diagnostic APIs**
   ```lua
   Ext.Stats.Dump("Weapon_Longsword")  -- Print all properties
   Ext.Stats.GetPropertyType(stat, "Damage")  -- Returns "string"
   ```

4. **Error handling polish**
   - Consistent nil + error message returns
   - Logging for validation failures
   - Safe handling of invalid references

**Deliverables:**
- Complete `Ext.Stats.Create()` implementation
- Type validation system
- Debug/diagnostic functions
- Comprehensive error handling

**Success Criteria:**
- `Ext.Stats.Create("MyWeapon", "Weapon")` creates new stat
- Invalid type/property errors are meaningful
- `Ext.Stats.Dump()` aids debugging

---

## Alternative Approaches Considered

### Option A: Direct Memory Patching (Rejected)
- Directly patch stat values in memory without using game APIs
- **Rejected because:** Fragile across game updates, may not trigger necessary game callbacks

### Option B: Hooking Stat Loader (Considered)
- Hook the stats loading function to inject custom stats
- **Pros:** Could intercept loading and modify in-flight
- **Cons:** More complex, timing-dependent
- **Status:** May use for advanced features later

### Option C: External Stats Database (Rejected)
- Maintain separate stats database, sync periodically
- **Rejected because:** Adds complexity, synchronization issues

---

## Acceptance Criteria

### Functional Requirements

- [ ] `Ext.Stats.Get(name)` returns stat object or nil+error
- [ ] Property read access via `stat.PropertyName`
- [ ] Property write access via `stat.PropertyName = value`
- [ ] `Ext.Stats.Sync(name)` updates game state
- [ ] `Ext.Stats.Create(name, type, template?)` creates new stat
- [ ] `Ext.Stats.GetAll(type?)` enumerates stats
- [ ] Type validation prevents cross-type property access

### Non-Functional Requirements

- [ ] No crashes during normal operation
- [ ] No crashes when accessing invalid stats
- [ ] Property access is fast enough for per-frame use
- [ ] Memory safe (no leaks, no dangling references)
- [ ] Thread-safe (or documented as main-thread only)

### Quality Gates

- [ ] Manual testing with live game
- [ ] Test stat modification persists through save/load
- [ ] Test multiple mods modifying same stat (last-write-wins)
- [ ] Test during combat (verify no race conditions)
- [ ] Log output is helpful for debugging

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Stats accessible | 100% of base game stats |
| Property read success | >99% for valid properties |
| Sync reliability | 100% changes visible after sync |
| Crash rate | 0 crashes in normal use |
| API response time | <1ms for Get/Set operations |

---

## Dependencies & Prerequisites

| Dependency | Status | Notes |
|------------|--------|-------|
| Safe memory APIs | ✅ Complete | `src/core/safe_memory.c` |
| Lua binding framework | ✅ Complete | `src/lua/lua_ext.c` pattern |
| Pattern scanning | ✅ Complete | `src/osiris/osiris_functions.c` |
| Ghidra analysis workflow | ✅ Complete | `ghidra/scripts/` |
| EntityWorld pattern | ✅ Complete | Similar global pointer capture |

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| RPGStats offset varies by game version | Medium | High | Pattern scan with fallback, version detection |
| ARM64 struct layout differs from Windows | Medium | High | Verify with Ghidra, smoke tests |
| Sync causes game instability | Low | High | Identify safe timing windows, test extensively |
| Property type mismatch | Medium | Medium | Runtime type checking, clear error messages |
| Multi-mod conflicts | Medium | Medium | Document last-write-wins behavior |
| Pattern scan fails on update | Medium | Medium | Graceful degradation, return nil |

---

## Files to Create/Modify

### New Files
| File | Purpose |
|------|---------|
| `src/stats/stats_manager.c` | Core stats manager implementation |
| `src/stats/stats_manager.h` | Public API header |
| `src/lua/lua_stats.c` | Lua bindings |
| `src/lua/lua_stats.h` | Lua bindings header |
| `ghidra/offsets/STATS.md` | Stats system offsets documentation |

### Modified Files
| File | Changes |
|------|---------|
| `CMakeLists.txt` | Add new source files, include directories |
| `src/injector/main.c` | Register lua_stats, initialize stats_manager |
| `README.md` | Document new Ext.Stats API |
| `ROADMAP.md` | Update Phase 3 status |

---

## Documentation Plan

1. **API Reference** - Document all Ext.Stats functions with examples
2. **Property Reference** - List all stat types and their properties
3. **Migration Guide** - Notes for porting Windows mods
4. **Ghidra Guide** - How stats offsets were discovered

---

## References & Research

### Internal References
- Entity system pattern: `src/entity/entity_system.c:1-200`
- Lua binding pattern: `src/lua/lua_ext.c:1-146`
- Safe memory APIs: `src/core/safe_memory.h`
- Pattern scanning: `src/osiris/osiris_functions.c:94-164`

### External References
- Windows BG3SE Stats: `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Stats/`
- BG3SE Lua API: `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Lua/Libs/Stats.inl`
- BG3 Modding Wiki: https://wiki.bg3.community/en/Tutorials/ScriptExtender/GettingStarted

### Related Work
- Issue #10 (completed): Function name caching fix - similar pattern scan approach
- Issue #2 (completed): TypeId discovery - similar Ghidra analysis workflow
