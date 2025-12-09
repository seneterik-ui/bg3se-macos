# Plan: Implement Ext.Events API Expansion (Issue #11)

**Date:** 2025-12-06
**Version:** v0.13.0 (target)
**Priority:** CRITICAL - Blocks many mods from reacting to game state changes
**Effort:** Medium-High (3 phases)

---

## Overview

Expand the `Ext.Events` API from 3 events to 7+ events with advanced subscription features. This enables mods to react to game lifecycle states, per-frame updates, and data loading completion.

### Current State (v0.12.0)
- **Implemented:** SessionLoading, SessionLoaded, ResetCompleted (3 events)
- **Parity:** 10%
- **Missing:** Tick, StatsLoaded, ModuleLoadStarted, GameStateChanged, OnNextTick, priority system, Once flag, handler IDs

### Target State (v0.13.0)
- **Goal:** 50%+ parity with Windows BG3SE Ext.Events
- **New Events:** Tick, StatsLoaded, ModuleLoadStarted
- **New Features:** Priority ordering, Once flag, handler ID return, Unsubscribe

---

## Target API

### Event Subscription with Options

```lua
-- Subscribe with options
local handlerId = Ext.Events.Tick:Subscribe(function(e)
    -- e.DeltaTime: float (seconds since last tick)
    -- Called ~30 times per second
end, {
    Priority = 50,   -- Lower = called first (default: 100)
    Once = true      -- Auto-unsubscribe after first call
})

-- Unsubscribe by handler ID
Ext.Events.Tick:Unsubscribe(handlerId)
```

### Available Events

| Event | Frequency | Payload | Use Case |
|-------|-----------|---------|----------|
| `SessionLoading` | Once | `{}` | Early initialization |
| `SessionLoaded` | Once | `{}` | PersistentVars available |
| `ResetCompleted` | Once | `{}` | After reset command |
| `Tick` | ~30Hz | `{DeltaTime}` | Frame updates, polling |
| `StatsLoaded` | Once | `{}` | Stat modifications |
| `ModuleLoadStarted` | Once | `{}` | Pre-load setup |
| `GameStateChanged` | Variable | `{FromState, ToState}` | Pause/unpause (Phase 3) |

### Helper Functions

```lua
-- Execute on next tick (convenience for once=true Tick subscription)
Ext.OnNextTick(function()
    -- Runs once on next frame
end)
```

---

## Implementation Phases

### Phase 1: Tick Event + Subscription System Upgrade (Priority: IMMEDIATE)

**Effort:** Low-Medium
**Risk:** Low (uses existing hook)
**Value:** Very High (enables frame-perfect logic)

#### 1.1 Upgrade Event System Architecture

**File:** `src/injector/main.c`

**Current Limitations:**
- No priority ordering (FIFO only)
- No handler ID return
- No Once flag support
- No Unsubscribe capability
- No event payload data

**New Architecture:**

```c
// src/lua/lua_events.h (NEW FILE)
#ifndef LUA_EVENTS_H
#define LUA_EVENTS_H

#include <lua.h>

typedef enum {
    EVENT_SESSION_LOADING = 0,
    EVENT_SESSION_LOADED,
    EVENT_RESET_COMPLETED,
    EVENT_TICK,                    // NEW
    EVENT_STATS_LOADED,            // Phase 2
    EVENT_MODULE_LOAD_STARTED,     // Phase 2
    EVENT_GAME_STATE_CHANGED,      // Phase 3
    EVENT_MAX
} EventType;

typedef struct {
    int callback_ref;       // Lua registry ref
    int priority;           // Lower = first (default 100)
    int once;               // Auto-unsubscribe flag
    uint64_t handler_id;    // Unique ID for unsubscription
} EventHandler;

// Initialize event system
void events_init(void);

// Fire event with optional data table on stack
void events_fire(lua_State *L, EventType event);
void events_fire_with_data(lua_State *L, EventType event);

// Register Lua API
void lua_events_register(lua_State *L, int ext_table_index);

// Subscribe returns handler ID
uint64_t events_subscribe(lua_State *L, EventType event, int callback_idx,
                          int priority, int once);

// Unsubscribe by handler ID
int events_unsubscribe(EventType event, uint64_t handler_id);

#endif
```

**Implementation (`src/lua/lua_events.c`):**

```c
// Key data structures
#define MAX_EVENT_HANDLERS 64

static EventHandler g_handlers[EVENT_MAX][MAX_EVENT_HANDLERS];
static int g_handler_counts[EVENT_MAX] = {0};
static uint64_t g_next_handler_id = 1;  // Global counter, never reuse
static int g_dispatch_depth[EVENT_MAX] = {0};  // Reentrancy tracking

// Deferred operations for dispatch safety
typedef struct {
    EventType event;
    uint64_t handler_id;
} DeferredUnsubscribe;

static DeferredUnsubscribe g_deferred_unsubs[256];
static int g_deferred_unsub_count = 0;
```

**Priority Sorting:**
```c
// Sort handlers by priority (lower first) after each subscription
static void sort_handlers_by_priority(EventType event) {
    int count = g_handler_counts[event];
    // Insertion sort (small N, stable)
    for (int i = 1; i < count; i++) {
        EventHandler key = g_handlers[event][i];
        int j = i - 1;
        while (j >= 0 && g_handlers[event][j].priority > key.priority) {
            g_handlers[event][j + 1] = g_handlers[event][j];
            j--;
        }
        g_handlers[event][j + 1] = key;
    }
}
```

**Dispatch with Deferred Modifications:**
```c
void events_fire(lua_State *L, EventType event) {
    if (!L || event >= EVENT_MAX) return;

    int count = g_handler_counts[event];
    if (count == 0) return;

    g_dispatch_depth[event]++;

    for (int i = 0; i < count; i++) {
        EventHandler *h = &g_handlers[event][i];
        if (h->callback_ref == LUA_NOREF) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            // Push event data table (empty for basic events)
            lua_newtable(L);

            // Protected call to prevent cascade failures
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                log_message("[Events] Error in %s handler: %s",
                           g_event_names[event], err ? err : "unknown");
                lua_pop(L, 1);
            }

            // Handle Once flag
            if (h->once) {
                // Defer removal during dispatch
                if (g_deferred_unsub_count < 256) {
                    g_deferred_unsubs[g_deferred_unsub_count++] =
                        (DeferredUnsubscribe){event, h->handler_id};
                }
            }
        } else {
            lua_pop(L, 1);
        }
    }

    g_dispatch_depth[event]--;

    // Process deferred unsubscriptions
    if (g_dispatch_depth[event] == 0) {
        process_deferred_unsubscribes(event);
    }
}
```

#### 1.2 Add Tick Event

**Location:** Existing `fake_Event` hook in `main.c` (line ~2113)

```c
// Track delta time for Tick event
static uint64_t g_last_tick_time = 0;

static void fake_Event(void *thisPtr, uint32_t funcId, OsiArgumentDesc *args) {
    event_call_count++;

    if (L) {
        console_poll(L);
        timer_update(L);
        persist_tick(L);

        // Fire Tick event with delta time
        uint64_t now = get_monotonic_ms();
        if (g_last_tick_time == 0) g_last_tick_time = now;
        float delta = (now - g_last_tick_time) / 1000.0f;
        g_last_tick_time = now;

        // Push delta time data for Tick event
        events_fire_tick(L, delta);
    }

    // ... rest of hook
}
```

**Tick Event Data:**
```c
void events_fire_tick(lua_State *L, float delta_time) {
    int count = g_handler_counts[EVENT_TICK];
    if (count == 0) return;

    g_dispatch_depth[EVENT_TICK]++;

    for (int i = 0; i < count; i++) {
        EventHandler *h = &g_handlers[EVENT_TICK][i];
        if (h->callback_ref == LUA_NOREF) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            // Event data: {DeltaTime = delta_time}
            lua_newtable(L);
            lua_pushnumber(L, delta_time);
            lua_setfield(L, -2, "DeltaTime");

            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                log_message("[Events] Tick handler error: %s", err ? err : "?");
                lua_pop(L, 1);
            }

            if (h->once) {
                // Queue deferred removal
            }
        } else {
            lua_pop(L, 1);
        }
    }

    g_dispatch_depth[EVENT_TICK]--;
    if (g_dispatch_depth[EVENT_TICK] == 0) {
        process_deferred_unsubscribes(EVENT_TICK);
    }
}
```

#### 1.3 Lua API: Subscribe with Options

```c
// Ext.Events.Tick:Subscribe(callback, options)
static int lua_event_subscribe(lua_State *L) {
    // Event type from closure upvalue
    int event = (int)lua_tointeger(L, lua_upvalueindex(1));

    // Callback is arg 2 (arg 1 is self from colon syntax)
    luaL_checktype(L, 2, LUA_TFUNCTION);

    // Parse options (arg 3, optional table)
    int priority = 100;  // Default
    int once = 0;

    if (lua_istable(L, 3)) {
        lua_getfield(L, 3, "Priority");
        if (lua_isnumber(L, -1)) {
            priority = (int)lua_tointeger(L, -1);
        }
        lua_pop(L, 1);

        lua_getfield(L, 3, "Once");
        if (lua_isboolean(L, -1)) {
            once = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);
    }

    // Store callback ref
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Allocate handler
    if (g_handler_counts[event] >= MAX_EVENT_HANDLERS) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
        return luaL_error(L, "Too many handlers for event %s", g_event_names[event]);
    }

    uint64_t handler_id = g_next_handler_id++;
    int idx = g_handler_counts[event]++;
    g_handlers[event][idx] = (EventHandler){
        .callback_ref = ref,
        .priority = priority,
        .once = once,
        .handler_id = handler_id
    };

    // Re-sort by priority
    sort_handlers_by_priority(event);

    // Return handler ID
    lua_pushinteger(L, (lua_Integer)handler_id);
    return 1;
}
```

#### 1.4 Lua API: Unsubscribe

```c
// Ext.Events.Tick:Unsubscribe(handlerId)
static int lua_event_unsubscribe(lua_State *L) {
    int event = (int)lua_tointeger(L, lua_upvalueindex(1));
    uint64_t handler_id = (uint64_t)luaL_checkinteger(L, 2);

    // Check if currently dispatching - defer if so
    if (g_dispatch_depth[event] > 0) {
        if (g_deferred_unsub_count < 256) {
            g_deferred_unsubs[g_deferred_unsub_count++] =
                (DeferredUnsubscribe){event, handler_id};
            lua_pushboolean(L, 1);  // Will be removed
        } else {
            lua_pushboolean(L, 0);  // Queue full
        }
        return 1;
    }

    // Immediate removal
    int found = remove_handler(event, handler_id);
    lua_pushboolean(L, found);
    return 1;
}

static int remove_handler(EventType event, uint64_t handler_id) {
    for (int i = 0; i < g_handler_counts[event]; i++) {
        if (g_handlers[event][i].handler_id == handler_id) {
            // Release callback ref
            luaL_unref(L, LUA_REGISTRYINDEX, g_handlers[event][i].callback_ref);

            // Shift remaining handlers
            for (int j = i; j < g_handler_counts[event] - 1; j++) {
                g_handlers[event][j] = g_handlers[event][j + 1];
            }
            g_handler_counts[event]--;
            return 1;
        }
    }
    return 0;
}
```

#### 1.5 Ext.OnNextTick() Helper

```c
// Ext.OnNextTick(callback)
static int lua_on_next_tick(lua_State *L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    // Subscribe to Tick with Once=true, default priority
    lua_pushvalue(L, 1);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    if (g_handler_counts[EVENT_TICK] >= MAX_EVENT_HANDLERS) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
        return luaL_error(L, "Too many Tick handlers");
    }

    uint64_t handler_id = g_next_handler_id++;
    int idx = g_handler_counts[EVENT_TICK]++;
    g_handlers[EVENT_TICK][idx] = (EventHandler){
        .callback_ref = ref,
        .priority = 100,
        .once = 1,  // Auto-unsubscribe
        .handler_id = handler_id
    };

    sort_handlers_by_priority(EVENT_TICK);

    // Return handler ID (can be used to cancel before it fires)
    lua_pushinteger(L, (lua_Integer)handler_id);
    return 1;
}
```

#### 1.6 Registration

```c
void lua_events_register(lua_State *L, int ext_index) {
    // Initialize storage
    events_init();

    // Create Ext.Events table
    lua_newtable(L);

    // Register each event as an object with Subscribe/Unsubscribe methods
    for (int i = 0; i < EVENT_MAX; i++) {
        create_event_object(L, i);
        lua_setfield(L, -2, g_event_names[i]);
    }

    lua_setfield(L, ext_index, "Events");

    // Register Ext.OnNextTick
    lua_pushcfunction(L, lua_on_next_tick);
    lua_setfield(L, ext_index, "OnNextTick");
}

static void create_event_object(lua_State *L, int event) {
    lua_newtable(L);

    // Subscribe method
    lua_pushinteger(L, event);
    lua_pushcclosure(L, lua_event_subscribe, 1);
    lua_setfield(L, -2, "Subscribe");

    // Unsubscribe method
    lua_pushinteger(L, event);
    lua_pushcclosure(L, lua_event_unsubscribe, 1);
    lua_setfield(L, -2, "Unsubscribe");
}
```

---

### Phase 2: StatsLoaded + ModuleLoadStarted Events (Priority: HIGH)

**Effort:** Medium
**Risk:** Medium (requires hook discovery for StatsLoaded)
**Value:** High (enables stat modifications)

#### 2.1 ModuleLoadStarted Event

**Location:** `src/mod/mod_loader.c`

Fire before PAK files are loaded:

```c
void mod_load_all(lua_State *L) {
    // Fire ModuleLoadStarted before any loading
    events_fire(L, EVENT_MODULE_LOAD_STARTED);

    // ... existing mod loading logic
}
```

**Timing:** Earliest possible event in mod loading sequence.

#### 2.2 StatsLoaded Event

**Research Required:** Find hook point via Ghidra

**Strategy:**
1. Search for `RPGStats::Load` function
2. Hook after stats parsing completes
3. Verify `Ext.Stats.GetAll()` works after event fires

**Ghidra Tasks:**
```bash
# Run Ghidra script to find stats loading functions
./ghidra/scripts/run_analysis.sh find_stats_load.py
```

**Potential Hook Locations (Windows BG3SE reference):**
- `RPGStats::LoadProc` - Main loading function
- `CRPGStats_Object_Manager::Load` - Object manager init
- After `ModifierLists` and `Objects` arrays populated

**Implementation Once Hook Found:**

```c
// In stats_manager.c or new hook location
static void (*orig_StatsLoad)(void*, void*) = NULL;

static void fake_StatsLoad(void* mgr, void* paths) {
    // Call original
    if (orig_StatsLoad) {
        orig_StatsLoad(mgr, paths);
    }

    // Fire StatsLoaded after load completes
    if (g_lua_state) {
        log_message("[Events] Stats loaded - firing StatsLoaded event");
        events_fire(g_lua_state, EVENT_STATS_LOADED);
    }
}
```

**Fallback if Hook Not Found:**
Fire StatsLoaded from `stats_manager_on_session_loaded()` when stats system becomes ready.

---

### Phase 3: GameStateChanged Event (Priority: MEDIUM - Deferred)

**Effort:** High
**Risk:** High (requires extensive reverse engineering)
**Value:** Medium (pause/unpause detection)

**Research Required:**
1. Find `GameStateEventManager` global pointers via pattern scanning
2. Or hook state transition functions directly
3. Determine GameState enum values on macOS

**Deferred to v0.14.0** if hook points not easily discoverable.

**Alternative for v0.13.0:**
- Provide `Ext.GetGameState()` query function instead of event
- Poll-based approach using Tick event

---

## Files to Create/Modify

### New Files

| File | Purpose |
|------|---------|
| `src/lua/lua_events.h` | Event system header |
| `src/lua/lua_events.c` | Event system implementation (~400 lines) |
| `ghidra/scripts/find_stats_load.py` | Script to find stats loading hook |

### Modified Files

| File | Changes |
|------|---------|
| `src/injector/main.c` | Remove old event code, add Tick firing in fake_Event |
| `src/mod/mod_loader.c` | Fire ModuleLoadStarted event |
| `src/stats/stats_manager.c` | Fire StatsLoaded event (fallback location) |
| `CMakeLists.txt` | Add `src/lua/lua_events.c` |
| `src/core/version.h` | Bump to v0.13.0 |
| `ROADMAP.md` | Update Ext.Events parity (10% → 50%) |

---

## Acceptance Criteria

### Phase 1 (Tick Event + System Upgrade)

- [ ] `Ext.Events.Tick:Subscribe(fn)` registers handler
- [ ] `Ext.Events.Tick:Subscribe(fn, {Priority=50})` respects priority
- [ ] `Ext.Events.Tick:Subscribe(fn, {Once=true})` auto-unsubscribes
- [ ] Subscribe returns uint64 handler ID
- [ ] `Ext.Events.Tick:Unsubscribe(id)` removes handler
- [ ] Tick handlers receive `{DeltaTime=float}` payload
- [ ] Tick fires ~30Hz (verified via timing)
- [ ] `Ext.OnNextTick(fn)` runs once on next frame
- [ ] Handler errors logged but don't crash dispatch
- [ ] Subscribe during dispatch deferred to after dispatch
- [ ] Existing SessionLoading/SessionLoaded/ResetCompleted still work

### Phase 2 (StatsLoaded + ModuleLoadStarted)

- [ ] `Ext.Events.ModuleLoadStarted:Subscribe(fn)` fires before PAK load
- [ ] `Ext.Events.StatsLoaded:Subscribe(fn)` fires after stats ready
- [ ] `Ext.Stats.GetAll()` works in StatsLoaded handler

### Performance Requirements

- [ ] Tick event with 0 handlers: <1μs overhead
- [ ] Tick event with 10 handlers: <100μs total
- [ ] No memory leaks from Once handlers
- [ ] Handler count limit enforced (64 per event)

---

## Testing Plan

### Unit Tests

```lua
-- Test priority ordering
local order = {}
Ext.Events.Tick:Subscribe(function() table.insert(order, "B") end, {Priority=100, Once=true})
Ext.Events.Tick:Subscribe(function() table.insert(order, "A") end, {Priority=50, Once=true})
Ext.Events.Tick:Subscribe(function() table.insert(order, "C") end, {Priority=150, Once=true})
-- After one tick: order should be {"A", "B", "C"}
```

### Console Commands

Add debug commands for testing:
- `!events` - List handler counts per event
- `!tick_test` - Subscribe test handler, report timing

### Performance Test

```lua
-- Measure Tick overhead
local count = 0
local start = Ext.Timer.MonotonicTime()
Ext.Events.Tick:Subscribe(function()
    count = count + 1
    if count >= 300 then  -- ~10 seconds
        local elapsed = Ext.Timer.MonotonicTime() - start
        Ext.Print(string.format("300 ticks in %.2fs = %.1f Hz", elapsed/1000, 300/(elapsed/1000)))
    end
end)
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Tick performance impact | Document best practices, recommend timers for delays |
| StatsLoaded hook not found | Fall back to firing from stats_manager_on_session_loaded() |
| GameStateChanged too complex | Defer to Phase 3, provide polling alternative |
| Handler memory leaks | Once flag auto-cleanup, limit handler count |
| Dispatch reentrancy | Track dispatch depth, defer modifications |

---

## Dependencies

- None (uses existing hook infrastructure)

## Blockers

- **StatsLoaded:** Requires Ghidra research for hook point
- **GameStateChanged:** Requires extensive reverse engineering (deferred)

---

## References

### Internal
- Issue #11: Implement Ext.Events API - Engine Event System
- `src/injector/main.c:594-725` - Current event implementation
- `src/injector/main.c:2113-2120` - fake_Event hook (Tick location)
- `ROADMAP.md:282-291` - Event requirements

### Windows BG3SE Reference
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Lua/LuaBinding.cpp:601-623` - Event firing
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/LuaScripts/Libs/Events/SubscribableEvent.lua` - Subscribe/Unsubscribe
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Lua/Server/LuaServer.cpp:176-183` - GameStateChanged

### External
- [Dobby Framework](https://github.com/jmpews/Dobby) - Hooking library
- [Game Programming Patterns - State](https://gameprogrammingpatterns.com/state.html)
