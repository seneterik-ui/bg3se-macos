# Plan: Implement PersistentVars (Issue #12)

## Problem Statement

**Critical mod-breaking issue:** Without PersistentVars, ALL mod state is lost on game reload. This breaks:
- Quest progress tracking
- Custom item inventories
- User settings/preferences
- Achievement counters
- Any mod that needs to remember anything between sessions

Currently, BG3SE-macOS has no savegame persistence mechanism, making it impossible for mods to maintain state across game loads.

## Target API (Windows BG3SE Compatibility)

```lua
-- Per-mod initialization in BootstrapServer.lua
PersistentVars = {}

-- Store data during gameplay
function TrackQuest()
    PersistentVars['QuestProgress'] = 5
    PersistentVars['Inventory'] = { "sword", "shield" }
end

-- Restored BEFORE SessionLoaded event fires
Ext.Events.SessionLoaded:Subscribe(function()
    local progress = PersistentVars['QuestProgress']
    _P("Restored quest progress: " .. tostring(progress))  -- Prints 5
end)
```

## Windows BG3SE Reference Pattern

From `BG3Extender/LuaScripts/BuiltinLibraryServer.lua`:

```lua
_I._GetModPersistentVars = function (modTable)
    local tab = Mods[modTable]
    if tab ~= nil then
        local persistent = tab.PersistentVars
        if persistent ~= nil then
            return Ext.Json.Stringify(persistent)
        end
    end
end

_I._RestoreModPersistentVars = function (modTable, vars)
    local tab = Mods[modTable]
    if tab ~= nil then
        tab.PersistentVars = Ext.Json.Parse(vars)
    end
end
```

On Windows, these functions are called from C++ via `SavegameSerializer.inl` during savegame load/save events.

## macOS Challenge: No Savegame Hooks

**Key difference from Windows:** macOS may not have accessible savegame serialization hooks. The game's save system is internal and hooking it would require significant reverse engineering.

**Solution: File-based persistence** - Save PersistentVars to JSON files in the BG3SE directory, keyed by ModTable name.

## Proposed Architecture

### Storage Location
```
~/Library/Application Support/BG3SE/
├── bg3se.log
├── commands.txt
└── persistentvars/
    ├── GustavDev.json           # One file per mod
    ├── MyCustomMod.json
    └── AnotherMod.json
```

### Data Flow

```
SAVE FLOW:
Ext.Events.Tick → periodic check → dirty flag set?
    ↓ YES
persist_save_all() → for each mod with PersistentVars:
    ↓
Mods[ModTable].PersistentVars → Ext.Json.Stringify()
    ↓
Write atomic: tempfile → rename to {ModTable}.json

LOAD FLOW:
Game startup → SessionLoading event fired
    ↓
persist_restore_all() → for each .json file:
    ↓
Read {ModTable}.json → Ext.Json.Parse()
    ↓
Mods[ModTable].PersistentVars = parsed_table
    ↓
SessionLoaded event fires (mods can access restored data)
```

### Timing Requirements

1. **Restore BEFORE SessionLoaded** - Mods expect PersistentVars available in SessionLoaded callback
2. **Save on explicit request** - `Ext.Vars.SyncPersistentVars()` for immediate save
3. **Auto-save on tick** - Dirty-flag based periodic save (every 30s if changed)
4. **Save on shutdown** - Best-effort save when game exits

## Implementation Plan

### Phase 1: Core Infrastructure (MVP)

#### 1.1 Create persistentvars module
**New files:**
- `src/lua/lua_persistentvars.h`
- `src/lua/lua_persistentvars.c`

**Functions:**
```c
// Public API
void persist_init(void);                    // Create directory, init state
void persist_restore_all(lua_State* L);     // Load all mod vars before SessionLoaded
void persist_save_all(lua_State* L);        // Save all dirty mod vars
void persist_register_api(lua_State* L);    // Register Ext.Vars.* functions

// Internal
static bool persist_load_mod(lua_State* L, const char* mod_table);
static bool persist_save_mod(lua_State* L, const char* mod_table);
static void persist_mark_dirty(const char* mod_table);
```

#### 1.2 Integrate with event system
**Modify `src/injector/main.c`:**

```c
// In session_loading handler (BEFORE SessionLoaded fires):
static void on_session_loading(lua_State* L) {
    persist_restore_all(L);  // NEW: Restore before SessionLoaded
    fire_event(L, EVENT_SESSION_LOADING);
}

// Add tick-based auto-save:
static void on_tick(lua_State* L) {
    static uint64_t last_save = 0;
    uint64_t now = timer_monotonic_ms();
    if (now - last_save > 30000) {  // Every 30 seconds
        persist_save_all(L);
        last_save = now;
    }
}
```

#### 1.3 Lua API bindings
**Register in Ext.Vars namespace:**

```lua
-- Immediate save (for critical moments)
Ext.Vars.SyncPersistentVars()

-- Check if vars loaded
Ext.Vars.IsPersistentVarsLoaded() -> bool

-- Force reload from disk (debugging)
Ext.Vars.ReloadPersistentVars()
```

### Phase 2: Atomic File Operations

#### 2.1 Safe write pattern
```c
static bool persist_atomic_write(const char* path, const char* json) {
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    // Write to temp file
    FILE* f = fopen(temp_path, "w");
    if (!f) return false;

    size_t written = fwrite(json, 1, strlen(json), f);
    fclose(f);

    if (written != strlen(json)) {
        unlink(temp_path);
        return false;
    }

    // Atomic rename
    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return false;
    }

    return true;
}
```

#### 2.2 Error recovery
```c
static bool persist_safe_load(const char* path, char** out_json) {
    // Try primary file first
    if (load_file(path, out_json)) return true;

    // Try backup if primary corrupted
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s.bak", path);
    if (load_file(backup_path, out_json)) {
        log_message("[PersistentVars] Recovered from backup: %s", path);
        return true;
    }

    return false;
}
```

### Phase 3: ModTable Discovery

#### 3.1 Enumerate active mods
The mod_loader already extracts ModTable from Config.json. Need to:

1. Track which mods have initialized `PersistentVars`
2. Only save mods that have set the table (don't create empty files)

```c
// In Lua:
local function enumerate_mods_with_persistentvars()
    local result = {}
    for modTable, mod in pairs(Mods) do
        if mod.PersistentVars ~= nil then
            table.insert(result, modTable)
        end
    end
    return result
end
```

#### 3.2 Handle missing ModTable gracefully
If a mod doesn't have ModTable in Config.json:
- Log warning: "Mod X has PersistentVars but no ModTable - cannot persist"
- Use mod's UUID as fallback key (less human-readable but functional)

### Phase 4: Testing & Edge Cases

#### 4.1 Test scenarios
1. **Basic roundtrip:** Set var → reload save → var restored
2. **Multiple mods:** Two mods with different PersistentVars don't interfere
3. **Large data:** 1MB of nested tables serializes/deserializes correctly
4. **Corruption recovery:** Delete half of JSON file → loads backup
5. **Timing:** PersistentVars available in SessionLoaded callback
6. **New mod:** First load with no existing JSON → empty table, no error

#### 4.2 Console commands
```lua
-- Debug commands for testing
Ext.RegisterConsoleCommand("pv_dump", function()
    for modTable, mod in pairs(Mods) do
        if mod.PersistentVars then
            _P(modTable .. ": " .. Ext.Json.Stringify(mod.PersistentVars))
        end
    end
end)

Ext.RegisterConsoleCommand("pv_set", function(cmd, key, value)
    PersistentVars[key] = value
    _P("Set PersistentVars." .. key .. " = " .. value)
end)

Ext.RegisterConsoleCommand("pv_save", function()
    Ext.Vars.SyncPersistentVars()
    _P("Saved all PersistentVars")
end)
```

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `src/lua/lua_persistentvars.h` | CREATE | Public API declarations |
| `src/lua/lua_persistentvars.c` | CREATE | Core implementation |
| `src/injector/main.c` | MODIFY | Add restore call before SessionLoaded, tick save |
| `CMakeLists.txt` | MODIFY | Add new source files |

## Dependencies

- **Ext.Json** ✅ Already implemented (`src/lua/lua_json.c`)
- **Ext.IO** ✅ Already implemented (`src/lua/lua_ext.c`)
- **Event system** ✅ Already implemented (SessionLoading, SessionLoaded)
- **Mod loader** ✅ Already implemented (`src/mod/mod_loader.c`)
- **Timer API** ✅ Already implemented (for periodic saves)

## Acceptance Criteria

1. [ ] Mods can set `Mods[ModTable].PersistentVars` to any serializable table
2. [ ] PersistentVars survives game restart (load → quit → load)
3. [ ] PersistentVars available in SessionLoaded callback (timing guarantee)
4. [ ] Multiple mods have isolated storage (no cross-contamination)
5. [ ] Atomic writes prevent corruption on crash
6. [ ] Backup recovery works when primary file corrupted
7. [ ] Clear error messages when:
   - JSON serialization fails (unsupported type)
   - Disk write fails (permissions, space)
   - ModTable missing from Config.json
8. [ ] `Ext.Vars.SyncPersistentVars()` forces immediate save

## Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Save timing misses data | Medium | High | Dirty-flag + explicit sync API |
| JSON serialization failure | Low | Medium | Clear error with table path |
| Disk corruption | Low | High | Atomic writes + backups |
| ModTable discovery fails | Low | Medium | Fallback to UUID |
| Performance (large tables) | Low | Low | Async save, size limits |

## Open Questions (Resolved)

1. **Save triggers** - Using tick-based dirty-flag + explicit `SyncPersistentVars()`
2. **Namespace isolation** - Per-mod files keyed by ModTable
3. **Version migration** - Mods handle schema changes (document in API notes)

## Estimated Complexity

- **Phase 1 (MVP):** ~300 lines C, ~50 lines Lua
- **Phase 2 (Atomic ops):** ~100 lines C
- **Phase 3 (ModTable discovery):** ~50 lines C/Lua
- **Phase 4 (Testing):** ~100 lines Lua

**Total: ~600 lines of code**

## References

- Windows BG3SE: `BG3Extender/LuaScripts/BuiltinLibraryServer.lua` (Lua helpers)
- Windows BG3SE: `BG3Extender/Extender/Shared/SavegameSerializer.inl` (C++ hooks)
- Existing: `src/lua/lua_json.c` (JSON serialization)
- Existing: `src/lua/lua_ext.c` (File I/O patterns)
- Issue: https://github.com/tomdimino/bg3se-macos/issues/12
