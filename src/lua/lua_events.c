/**
 * BG3SE-macOS - Event System Implementation
 *
 * Advanced event subscription system with:
 * - Priority-based handler ordering (lower priority = called first)
 * - Once flag for auto-unsubscription after first call
 * - Handler ID return for explicit unsubscription
 * - Deferred modifications during dispatch to prevent iterator corruption
 * - Protected calls to prevent cascade failures
 */

#include "lua_events.h"
#include "../core/logging.h"

#include <string.h>

// ============================================================================
// Constants
// ============================================================================

#define MAX_EVENT_HANDLERS 64
#define MAX_DEFERRED_OPERATIONS 256
#define DEFAULT_PRIORITY 100

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    int callback_ref;       // Lua registry reference
    int priority;           // Lower = first (default 100)
    int once;               // Auto-unsubscribe after first call
    uint64_t handler_id;    // Unique ID for unsubscription
} EventHandler;

typedef struct {
    BG3SEEventType event;
    uint64_t handler_id;
} DeferredUnsubscribe;

// ============================================================================
// Static State
// ============================================================================

static EventHandler g_handlers[EVENT_MAX][MAX_EVENT_HANDLERS];
static int g_handler_counts[EVENT_MAX] = {0};
static uint64_t g_next_handler_id = 1;  // Global counter, never reuse
static int g_dispatch_depth[EVENT_MAX] = {0};  // Reentrancy tracking
static int g_initialized = 0;
static bool g_trace_enabled = false;  // Event tracing for debugging

// Deferred unsubscriptions (processed after dispatch completes)
static DeferredUnsubscribe g_deferred_unsubs[MAX_DEFERRED_OPERATIONS];
static int g_deferred_unsub_count = 0;

// Event names for logging and Lua
static const char *g_event_names[EVENT_MAX] = {
    "SessionLoading",
    "SessionLoaded",
    "ResetCompleted",
    "Tick",
    "StatsLoaded",
    "ModuleLoadStarted",
    "GameStateChanged",
    "KeyInput",
    "DoConsoleCommand",
    "LuaConsoleInput",
    "Log",                 // Log message interception (Windows parity)
    // Engine events (Issue #51)
    "TurnStarted",
    "TurnEnded",
    "CombatStarted",
    "CombatEnded",
    "StatusApplied",
    "StatusRemoved",
    "EquipmentChanged",
    "LevelUp",
    // Additional engine events (Issue #51 expansion)
    "Died",
    "Downed",
    "Resurrected",
    "SpellCast",
    "SpellCastFinished",
    "HitNotification",
    "ShortRestStarted",
    "ApprovalChanged",
    // Lifecycle events (Issue #51 expansion)
    "StatsStructureLoaded",
    "ModuleResume",
    "Shutdown",
    // Functor events (Issue #53)
    "ExecuteFunctor",
    "AfterExecuteFunctor",
    "DealDamage",
    "DealtDamage",
    "BeforeDealDamage"
};

// ============================================================================
// Internal: Priority Sort
// ============================================================================

/**
 * Sort handlers by priority (lower first) using insertion sort.
 * Stable sort preserves registration order for equal priorities.
 */
static void sort_handlers_by_priority(BG3SEEventType event) {
    int count = g_handler_counts[event];
    if (count <= 1) return;

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

// ============================================================================
// Internal: Remove Handler
// ============================================================================

static int remove_handler_by_id(lua_State *L, BG3SEEventType event, uint64_t handler_id) {
    for (int i = 0; i < g_handler_counts[event]; i++) {
        if (g_handlers[event][i].handler_id == handler_id) {
            // Release callback reference
            if (g_handlers[event][i].callback_ref != LUA_NOREF &&
                g_handlers[event][i].callback_ref != LUA_REFNIL) {
                luaL_unref(L, LUA_REGISTRYINDEX, g_handlers[event][i].callback_ref);
            }

            // Shift remaining handlers down using memmove (ARM64 SIMD-optimized)
            int remaining = g_handler_counts[event] - i - 1;
            if (remaining > 0) {
                memmove(&g_handlers[event][i],
                        &g_handlers[event][i + 1],
                        remaining * sizeof(EventHandler));
            }
            g_handler_counts[event]--;

            return 1;  // Found and removed
        }
    }
    return 0;  // Not found
}

// ============================================================================
// Internal: Process Deferred Unsubscriptions
// ============================================================================

static void process_deferred_unsubscribes(lua_State *L, BG3SEEventType event) {
    // Process all deferred unsubscriptions for this event
    // Using swap-and-pop for O(1) removal instead of O(n) shift
    int i = 0;
    while (i < g_deferred_unsub_count) {
        if (g_deferred_unsubs[i].event == event) {
            remove_handler_by_id(L, event, g_deferred_unsubs[i].handler_id);

            // Swap with last element and pop (O(1) removal)
            g_deferred_unsubs[i] = g_deferred_unsubs[--g_deferred_unsub_count];
            // Don't increment i - check same index again (now contains swapped element)
        } else {
            i++;
        }
    }
}

// ============================================================================
// Public API: Initialize
// ============================================================================

void events_init(void) {
    if (g_initialized) return;

    // Initialize handler counts and dispatch depth
    // Note: g_handlers array doesn't need initialization - only slots up to
    // g_handler_counts[e] are ever accessed, and they're properly filled on Subscribe
    memset(g_handler_counts, 0, sizeof(g_handler_counts));
    memset(g_dispatch_depth, 0, sizeof(g_dispatch_depth));

    g_next_handler_id = 1;
    g_deferred_unsub_count = 0;
    g_initialized = 1;

    LOG_EVENTS_INFO("Event system initialized");
}

// ============================================================================
// Public API: Fire Event
// ============================================================================

void events_fire(lua_State *L, BG3SEEventType event) {
    if (!L || event >= EVENT_MAX) return;

    int count = g_handler_counts[event];
    if (count == 0) return;

    // Log for non-Tick events (Tick is too frequent)
    if (event != EVENT_TICK) {
        LOG_EVENTS_DEBUG("Firing %s (%d handlers)", g_event_names[event], count);
    }

    g_dispatch_depth[event]++;

    for (int i = 0; i < g_handler_counts[event]; i++) {
        EventHandler *h = &g_handlers[event][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        // Get callback from registry
        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table (empty for basic events)
        lua_newtable(L);

        // Protected call to prevent cascade failures
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("Error in %s handler (id=%llu): %s",
                       g_event_names[event], h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag - queue for deferred removal
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){event, h->handler_id};
            }
        }
    }

    g_dispatch_depth[event]--;

    // Process deferred unsubscriptions when dispatch completes
    if (g_dispatch_depth[event] == 0) {
        process_deferred_unsubscribes(L, event);
    }
}

// ============================================================================
// Public API: Fire Tick Event (with DeltaTime)
// ============================================================================

void events_fire_tick(lua_State *L, float delta_time) {
    if (!L) return;

    int count = g_handler_counts[EVENT_TICK];
    if (count == 0) return;

    g_dispatch_depth[EVENT_TICK]++;

    for (int i = 0; i < g_handler_counts[EVENT_TICK]; i++) {
        EventHandler *h = &g_handlers[EVENT_TICK][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        // Get callback from registry
        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with DeltaTime
        lua_newtable(L);
        lua_pushnumber(L, delta_time);
        lua_setfield(L, -2, "DeltaTime");

        // Protected call
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("Tick handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_TICK, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_TICK]--;

    if (g_dispatch_depth[EVENT_TICK] == 0) {
        process_deferred_unsubscribes(L, EVENT_TICK);
    }
}

// ============================================================================
// Public API: Fire GameStateChanged Event (with FromState and ToState)
// ============================================================================

void events_fire_game_state_changed(lua_State *L, int fromState, int toState) {
    if (!L) return;

    int count = g_handler_counts[EVENT_GAME_STATE_CHANGED];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing GameStateChanged (from=%d, to=%d, %d handlers)",
                fromState, toState, count);

    g_dispatch_depth[EVENT_GAME_STATE_CHANGED]++;

    for (int i = 0; i < g_handler_counts[EVENT_GAME_STATE_CHANGED]; i++) {
        EventHandler *h = &g_handlers[EVENT_GAME_STATE_CHANGED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        // Get callback from registry
        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with FromState and ToState
        lua_newtable(L);
        lua_pushinteger(L, fromState);
        lua_setfield(L, -2, "FromState");
        lua_pushinteger(L, toState);
        lua_setfield(L, -2, "ToState");

        // Protected call
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("GameStateChanged handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_GAME_STATE_CHANGED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_GAME_STATE_CHANGED]--;

    if (g_dispatch_depth[EVENT_GAME_STATE_CHANGED] == 0) {
        process_deferred_unsubscribes(L, EVENT_GAME_STATE_CHANGED);
    }
}

void events_fire_key_input(lua_State *L, int keyCode, bool pressed, int modifiers, const char *character) {
    if (!L) return;

    int count = g_handler_counts[EVENT_KEY_INPUT];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing KeyInput (key=%d, pressed=%d, mods=0x%x, %d handlers)",
                keyCode, pressed, modifiers, count);

    g_dispatch_depth[EVENT_KEY_INPUT]++;

    for (int i = 0; i < g_handler_counts[EVENT_KEY_INPUT]; i++) {
        EventHandler *h = &g_handlers[EVENT_KEY_INPUT][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            // Create event data table
            lua_newtable(L);
            lua_pushinteger(L, keyCode);
            lua_setfield(L, -2, "Key");
            lua_pushboolean(L, pressed);
            lua_setfield(L, -2, "Pressed");
            lua_pushinteger(L, modifiers);
            lua_setfield(L, -2, "Modifiers");
            if (character && character[0]) {
                lua_pushstring(L, character);
            } else {
                lua_pushnil(L);
            }
            lua_setfield(L, -2, "Character");

            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                LOG_EVENTS_ERROR("KeyInput handler %llu error: %s",
                           (unsigned long long)h->handler_id, err ? err : "unknown");
                lua_pop(L, 1);
            }

            if (h->once) {
                if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                    g_deferred_unsubs[g_deferred_unsub_count++] =
                        (DeferredUnsubscribe){EVENT_KEY_INPUT, h->handler_id};
                }
            }
        } else {
            lua_pop(L, 1);
        }
    }

    g_dispatch_depth[EVENT_KEY_INPUT]--;

    if (g_dispatch_depth[EVENT_KEY_INPUT] == 0) {
        process_deferred_unsubscribes(L, EVENT_KEY_INPUT);
    }
}

// ============================================================================
// Public API: Fire DoConsoleCommand Event
// ============================================================================

bool events_fire_do_console_command(lua_State *L, const char *command) {
    if (!L) return false;

    int count = g_handler_counts[EVENT_DO_CONSOLE_COMMAND];
    if (count == 0) return false;

    LOG_EVENTS_DEBUG("Firing DoConsoleCommand (command=%s, %d handlers)", command, count);

    bool prevented = false;
    g_dispatch_depth[EVENT_DO_CONSOLE_COMMAND]++;

    for (int i = 0; i < g_handler_counts[EVENT_DO_CONSOLE_COMMAND]; i++) {
        EventHandler *h = &g_handlers[EVENT_DO_CONSOLE_COMMAND][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with Command and Prevent fields
        lua_newtable(L);
        lua_pushstring(L, command);
        lua_setfield(L, -2, "Command");
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, "Prevent");

        // Keep reference to event table to check Prevent after call
        lua_pushvalue(L, -1);
        int event_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("DoConsoleCommand handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        } else {
            // Check if handler set Prevent = true
            lua_rawgeti(L, LUA_REGISTRYINDEX, event_ref);
            lua_getfield(L, -1, "Prevent");
            if (lua_toboolean(L, -1)) {
                prevented = true;
            }
            lua_pop(L, 2);  // Prevent value and event table
        }
        luaL_unref(L, LUA_REGISTRYINDEX, event_ref);

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_DO_CONSOLE_COMMAND, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_DO_CONSOLE_COMMAND]--;

    if (g_dispatch_depth[EVENT_DO_CONSOLE_COMMAND] == 0) {
        process_deferred_unsubscribes(L, EVENT_DO_CONSOLE_COMMAND);
    }

    return prevented;
}

// ============================================================================
// Public API: Fire LuaConsoleInput Event
// ============================================================================

bool events_fire_lua_console_input(lua_State *L, const char *input) {
    if (!L) return false;

    int count = g_handler_counts[EVENT_LUA_CONSOLE_INPUT];
    if (count == 0) return false;

    LOG_EVENTS_DEBUG("Firing LuaConsoleInput (%d handlers)", count);

    bool prevented = false;
    g_dispatch_depth[EVENT_LUA_CONSOLE_INPUT]++;

    for (int i = 0; i < g_handler_counts[EVENT_LUA_CONSOLE_INPUT]; i++) {
        EventHandler *h = &g_handlers[EVENT_LUA_CONSOLE_INPUT][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with Input and Prevent fields
        lua_newtable(L);
        lua_pushstring(L, input);
        lua_setfield(L, -2, "Input");
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, "Prevent");

        // Keep reference to event table to check Prevent after call
        lua_pushvalue(L, -1);
        int event_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("LuaConsoleInput handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        } else {
            // Check if handler set Prevent = true
            lua_rawgeti(L, LUA_REGISTRYINDEX, event_ref);
            lua_getfield(L, -1, "Prevent");
            if (lua_toboolean(L, -1)) {
                prevented = true;
            }
            lua_pop(L, 2);  // Prevent value and event table
        }
        luaL_unref(L, LUA_REGISTRYINDEX, event_ref);

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_LUA_CONSOLE_INPUT, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_LUA_CONSOLE_INPUT]--;

    if (g_dispatch_depth[EVENT_LUA_CONSOLE_INPUT] == 0) {
        process_deferred_unsubscribes(L, EVENT_LUA_CONSOLE_INPUT);
    }

    return prevented;
}

// ============================================================================
// Public API: Get Handler Count
// ============================================================================

int events_get_handler_count(BG3SEEventType event) {
    if (event < 0 || event >= EVENT_MAX) return 0;
    return g_handler_counts[event];
}

// ============================================================================
// Public API: Get Event Name
// ============================================================================

const char *events_get_name(BG3SEEventType event) {
    if (event < 0 || event >= EVENT_MAX) return "Unknown";
    return g_event_names[event];
}

// ============================================================================
// Public API: Event Tracing
// ============================================================================

void events_set_trace_enabled(bool enabled) {
    g_trace_enabled = enabled;
    LOG_EVENTS_INFO("Event tracing %s", enabled ? "ENABLED" : "DISABLED");
}

bool events_get_trace_enabled(void) {
    return g_trace_enabled;
}

// ============================================================================
// Lua API: Subscribe
// ============================================================================

/**
 * Event:Subscribe(callback, [options])
 *
 * Options table:
 *   Priority: number (default 100, lower = called first)
 *   Once: boolean (default false, auto-unsubscribe after first call)
 *
 * Returns: handler ID (integer) for use with Unsubscribe
 */
static int lua_event_subscribe(lua_State *L) {
    // Event type from closure upvalue
    int event = (int)lua_tointeger(L, lua_upvalueindex(1));
    if (event < 0 || event >= EVENT_MAX) {
        return luaL_error(L, "Invalid event type");
    }

    // Callback is arg 2 (arg 1 is self due to colon syntax)
    luaL_checktype(L, 2, LUA_TFUNCTION);

    // Parse options (arg 3, optional table)
    int priority = DEFAULT_PRIORITY;
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

    // Check handler limit
    if (g_handler_counts[event] >= MAX_EVENT_HANDLERS) {
        return luaL_error(L, "Too many handlers for event %s (max %d)",
                         g_event_names[event], MAX_EVENT_HANDLERS);
    }

    // Store callback in registry
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Allocate handler
    uint64_t handler_id = g_next_handler_id++;
    int idx = g_handler_counts[event]++;

    g_handlers[event][idx].callback_ref = ref;
    g_handlers[event][idx].priority = priority;
    g_handlers[event][idx].once = once;
    g_handlers[event][idx].handler_id = handler_id;

    // Re-sort by priority
    sort_handlers_by_priority(event);

    // Log subscription (not for Tick - too noisy)
    if (event != EVENT_TICK) {
        LOG_EVENTS_DEBUG("Subscribed to %s (id=%llu, priority=%d, once=%d)",
                   g_event_names[event], handler_id, priority, once);
    }

    // Return handler ID
    lua_pushinteger(L, (lua_Integer)handler_id);
    return 1;
}

// ============================================================================
// Lua API: Unsubscribe
// ============================================================================

/**
 * Event:Unsubscribe(handlerId)
 *
 * Returns: boolean (true if handler was found and removed)
 */
static int lua_event_unsubscribe(lua_State *L) {
    // Event type from closure upvalue
    int event = (int)lua_tointeger(L, lua_upvalueindex(1));
    if (event < 0 || event >= EVENT_MAX) {
        return luaL_error(L, "Invalid event type");
    }

    // Handler ID is arg 2 (arg 1 is self)
    uint64_t handler_id = (uint64_t)luaL_checkinteger(L, 2);

    // If currently dispatching, defer the removal
    if (g_dispatch_depth[event] > 0) {
        if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] =
                (DeferredUnsubscribe){event, handler_id};
            lua_pushboolean(L, 1);  // Will be removed
        } else {
            LOG_EVENTS_WARN("Deferred unsubscribe queue full");
            lua_pushboolean(L, 0);
        }
        return 1;
    }

    // Immediate removal
    int found = remove_handler_by_id(L, event, handler_id);

    if (found && event != EVENT_TICK) {
        LOG_EVENTS_DEBUG("Unsubscribed from %s (id=%llu)",
                   g_event_names[event], handler_id);
    }

    lua_pushboolean(L, found);
    return 1;
}

// ============================================================================
// Lua API: OnNextTick
// ============================================================================

/**
 * Ext.OnNextTick(callback)
 *
 * Convenience function to subscribe to Tick with Once=true.
 * Returns: handler ID (can be used to cancel before it fires)
 */
static int lua_on_next_tick(lua_State *L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    // Check handler limit
    if (g_handler_counts[EVENT_TICK] >= MAX_EVENT_HANDLERS) {
        return luaL_error(L, "Too many Tick handlers");
    }

    // Store callback in registry
    lua_pushvalue(L, 1);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Allocate handler with Once=true
    uint64_t handler_id = g_next_handler_id++;
    int idx = g_handler_counts[EVENT_TICK]++;

    g_handlers[EVENT_TICK][idx].callback_ref = ref;
    g_handlers[EVENT_TICK][idx].priority = DEFAULT_PRIORITY;
    g_handlers[EVENT_TICK][idx].once = 1;  // Auto-unsubscribe
    g_handlers[EVENT_TICK][idx].handler_id = handler_id;

    // Re-sort by priority
    sort_handlers_by_priority(EVENT_TICK);

    // Return handler ID
    lua_pushinteger(L, (lua_Integer)handler_id);
    return 1;
}

// ============================================================================
// Internal: Create Event Object
// ============================================================================

static void create_event_object(lua_State *L, BG3SEEventType event) {
    lua_newtable(L);

    // Subscribe method with event type as upvalue
    lua_pushinteger(L, event);
    lua_pushcclosure(L, lua_event_subscribe, 1);
    lua_setfield(L, -2, "Subscribe");

    // Unsubscribe method with event type as upvalue
    lua_pushinteger(L, event);
    lua_pushcclosure(L, lua_event_unsubscribe, 1);
    lua_setfield(L, -2, "Unsubscribe");
}

// ============================================================================
// Public API: Register Lua API
// ============================================================================

void lua_events_register(lua_State *L, int ext_table_index) {
    // Initialize event system
    events_init();

    // Convert negative index to absolute
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Events table
    lua_newtable(L);

    // Register all events
    for (int i = 0; i < EVENT_MAX; i++) {
        create_event_object(L, i);
        lua_setfield(L, -2, g_event_names[i]);
    }

    lua_setfield(L, ext_table_index, "Events");

    // Register Ext.OnNextTick
    lua_pushcfunction(L, lua_on_next_tick);
    lua_setfield(L, ext_table_index, "OnNextTick");

    LOG_EVENTS_INFO("Ext.Events namespace registered with %d event types", EVENT_MAX);

    // Initialize Log event callback with the logging system
    events_init_log_callback(L);
}

// ============================================================================
// Engine Events - Fire Functions (Issue #51)
// ============================================================================

void events_fire_turn_started(lua_State *L, uint64_t entity, int round) {
    if (!L) return;

    int count = g_handler_counts[EVENT_TURN_STARTED];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing TurnStarted (entity=0x%llx, round=%d, %d handlers)",
                (unsigned long long)entity, round, count);

    g_dispatch_depth[EVENT_TURN_STARTED]++;

    for (int i = 0; i < g_handler_counts[EVENT_TURN_STARTED]; i++) {
        EventHandler *h = &g_handlers[EVENT_TURN_STARTED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)entity);
        lua_setfield(L, -2, "Entity");
        lua_pushinteger(L, round);
        lua_setfield(L, -2, "Round");

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("TurnStarted handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_TURN_STARTED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_TURN_STARTED]--;

    if (g_dispatch_depth[EVENT_TURN_STARTED] == 0) {
        process_deferred_unsubscribes(L, EVENT_TURN_STARTED);
    }
}

// ============================================================================
// Osiris Bridge Events (Issue #51 - TurnStarted/TurnEnded from Osiris)
// ============================================================================

void events_fire_turn_started_from_osiris(lua_State *L, const char *characterGuid) {
    if (!L) return;

    int count = g_handler_counts[EVENT_TURN_STARTED];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing TurnStarted from Osiris (guid=%s, %d handlers)",
                characterGuid ? characterGuid : "nil", count);

    g_dispatch_depth[EVENT_TURN_STARTED]++;

    for (int i = 0; i < g_handler_counts[EVENT_TURN_STARTED]; i++) {
        EventHandler *h = &g_handlers[EVENT_TURN_STARTED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with CharacterGuid
        lua_newtable(L);
        if (characterGuid) {
            lua_pushstring(L, characterGuid);
        } else {
            lua_pushnil(L);
        }
        lua_setfield(L, -2, "CharacterGuid");

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("TurnStarted (Osiris) handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_TURN_STARTED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_TURN_STARTED]--;

    if (g_dispatch_depth[EVENT_TURN_STARTED] == 0) {
        process_deferred_unsubscribes(L, EVENT_TURN_STARTED);
    }
}

void events_fire_turn_ended_from_osiris(lua_State *L, const char *characterGuid) {
    if (!L) return;

    int count = g_handler_counts[EVENT_TURN_ENDED];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing TurnEnded from Osiris (guid=%s, %d handlers)",
                characterGuid ? characterGuid : "nil", count);

    g_dispatch_depth[EVENT_TURN_ENDED]++;

    for (int i = 0; i < g_handler_counts[EVENT_TURN_ENDED]; i++) {
        EventHandler *h = &g_handlers[EVENT_TURN_ENDED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with CharacterGuid
        lua_newtable(L);
        if (characterGuid) {
            lua_pushstring(L, characterGuid);
        } else {
            lua_pushnil(L);
        }
        lua_setfield(L, -2, "CharacterGuid");

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("TurnEnded (Osiris) handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_TURN_ENDED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_TURN_ENDED]--;

    if (g_dispatch_depth[EVENT_TURN_ENDED] == 0) {
        process_deferred_unsubscribes(L, EVENT_TURN_ENDED);
    }
}

void events_fire_status_applied(lua_State *L, uint64_t entity, const char *statusId, uint64_t source) {
    if (!L) return;

    int count = g_handler_counts[EVENT_STATUS_APPLIED];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing StatusApplied (entity=0x%llx, status=%s, source=0x%llx, %d handlers)",
                (unsigned long long)entity, statusId ? statusId : "nil",
                (unsigned long long)source, count);

    g_dispatch_depth[EVENT_STATUS_APPLIED]++;

    for (int i = 0; i < g_handler_counts[EVENT_STATUS_APPLIED]; i++) {
        EventHandler *h = &g_handlers[EVENT_STATUS_APPLIED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)entity);
        lua_setfield(L, -2, "Entity");
        lua_pushstring(L, statusId ? statusId : "");
        lua_setfield(L, -2, "StatusId");
        lua_pushinteger(L, (lua_Integer)source);
        lua_setfield(L, -2, "Source");

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("StatusApplied handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_STATUS_APPLIED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_STATUS_APPLIED]--;

    if (g_dispatch_depth[EVENT_STATUS_APPLIED] == 0) {
        process_deferred_unsubscribes(L, EVENT_STATUS_APPLIED);
    }
}

// ============================================================================
// Functor Events (Issue #53)
// ============================================================================

void events_fire_execute_functor(lua_State *L, int ctxType, void *functors, void *context) {
    if (!L) return;

    int count = g_handler_counts[EVENT_EXECUTE_FUNCTOR];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing ExecuteFunctor (ctx=%d, functors=%p, context=%p, %d handlers)",
                ctxType, functors, context, count);

    g_dispatch_depth[EVENT_EXECUTE_FUNCTOR]++;

    for (int i = 0; i < g_handler_counts[EVENT_EXECUTE_FUNCTOR]; i++) {
        EventHandler *h = &g_handlers[EVENT_EXECUTE_FUNCTOR][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table
        lua_newtable(L);
        lua_pushinteger(L, ctxType);
        lua_setfield(L, -2, "ContextType");
        lua_pushinteger(L, (lua_Integer)(uintptr_t)functors);
        lua_setfield(L, -2, "FunctorListPtr");
        lua_pushinteger(L, (lua_Integer)(uintptr_t)context);
        lua_setfield(L, -2, "ContextPtr");

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("ExecuteFunctor handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_EXECUTE_FUNCTOR, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_EXECUTE_FUNCTOR]--;

    if (g_dispatch_depth[EVENT_EXECUTE_FUNCTOR] == 0) {
        process_deferred_unsubscribes(L, EVENT_EXECUTE_FUNCTOR);
    }
}

void events_fire_after_execute_functor(lua_State *L, int ctxType, void *functors, void *context) {
    if (!L) return;

    int count = g_handler_counts[EVENT_AFTER_EXECUTE_FUNCTOR];
    if (count == 0) return;

    LOG_EVENTS_DEBUG("Firing AfterExecuteFunctor (ctx=%d, %d handlers)", ctxType, count);

    g_dispatch_depth[EVENT_AFTER_EXECUTE_FUNCTOR]++;

    for (int i = 0; i < g_handler_counts[EVENT_AFTER_EXECUTE_FUNCTOR]; i++) {
        EventHandler *h = &g_handlers[EVENT_AFTER_EXECUTE_FUNCTOR][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table
        lua_newtable(L);
        lua_pushinteger(L, ctxType);
        lua_setfield(L, -2, "ContextType");
        lua_pushinteger(L, (lua_Integer)(uintptr_t)functors);
        lua_setfield(L, -2, "FunctorListPtr");
        lua_pushinteger(L, (lua_Integer)(uintptr_t)context);
        lua_setfield(L, -2, "ContextPtr");

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_EVENTS_ERROR("AfterExecuteFunctor handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_AFTER_EXECUTE_FUNCTOR, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_AFTER_EXECUTE_FUNCTOR]--;

    if (g_dispatch_depth[EVENT_AFTER_EXECUTE_FUNCTOR] == 0) {
        process_deferred_unsubscribes(L, EVENT_AFTER_EXECUTE_FUNCTOR);
    }
}

// ============================================================================
// Log Event (Windows BG3SE Parity)
// ============================================================================

// Static Lua state for log callback (set during init)
static lua_State *g_log_callback_L = NULL;
static int g_log_callback_id = -1;
static bool g_log_event_dispatching = false;  // Prevent recursion

/**
 * Fire the Log event with message data.
 * Returns true if any handler set e.Prevent = true.
 */
bool events_fire_log(lua_State *L, const char *level, const char *module, const char *message) {
    if (!L) return false;

    // Prevent infinite recursion (logging from within log handler)
    if (g_log_event_dispatching) return false;

    int count = g_handler_counts[EVENT_LOG];
    if (count == 0) return false;

    g_log_event_dispatching = true;
    g_dispatch_depth[EVENT_LOG]++;

    bool prevented = false;

    for (int i = 0; i < g_handler_counts[EVENT_LOG]; i++) {
        EventHandler *h = &g_handlers[EVENT_LOG][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table
        lua_newtable(L);

        lua_pushstring(L, level ? level : "INFO");
        lua_setfield(L, -2, "Level");

        lua_pushstring(L, module ? module : "Core");
        lua_setfield(L, -2, "Module");

        lua_pushstring(L, message ? message : "");
        lua_setfield(L, -2, "Message");

        // Add Prevent field (initialized to false)
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, "Prevent");

        // Keep a reference to check Prevent after call
        lua_pushvalue(L, -1);
        int event_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            // Don't use LOG_EVENTS_ERROR here - would cause recursion!
            fprintf(stderr, "[BG3SE] Log event handler error: %s\n", err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Check if Prevent was set
        lua_rawgeti(L, LUA_REGISTRYINDEX, event_ref);
        lua_getfield(L, -1, "Prevent");
        if (lua_toboolean(L, -1)) {
            prevented = true;
        }
        lua_pop(L, 2);  // Pop Prevent and event table
        luaL_unref(L, LUA_REGISTRYINDEX, event_ref);

        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_LOG, h->handler_id};
            }
        }

        if (prevented) break;  // Stop early if prevented
    }

    g_dispatch_depth[EVENT_LOG]--;

    if (g_dispatch_depth[EVENT_LOG] == 0) {
        process_deferred_unsubscribes(L, EVENT_LOG);
    }

    g_log_event_dispatching = false;
    return prevented;
}

/**
 * Log callback for the C logging system.
 * Forwards log messages to Lua handlers.
 */
static void log_event_callback(LogLevel level, LogModule module,
                               const char *message, void *userdata) {
    (void)userdata;

    if (!g_log_callback_L) return;
    if (g_log_event_dispatching) return;  // Prevent recursion

    // Convert level and module to strings
    const char *level_str = log_level_name(level);
    const char *module_str = log_module_name(module);

    events_fire_log(g_log_callback_L, level_str, module_str, message);
}

/**
 * Initialize the Log event callback with the logging system.
 */
void events_init_log_callback(lua_State *L) {
    if (g_log_callback_id >= 0) {
        // Already registered
        return;
    }

    g_log_callback_L = L;

    // Register callback with the logging system
    // Only forward messages that pass the current level filter
    g_log_callback_id = log_register_callback(log_event_callback, NULL,
                                              LOG_LEVEL_DEBUG, 0);

    if (g_log_callback_id >= 0) {
        // Enable callback output flag so callbacks actually get invoked
        uint32_t flags = log_get_output_flags();
        log_set_output_flags(flags | LOG_OUTPUT_CALLBACK);
        LOG_LUA_INFO("Log event callback registered (id=%d)", g_log_callback_id);
    }
}

// ============================================================================
// One-Frame Component Polling (Issue #51)
// ============================================================================

// Forward declaration - implemented in entity_system.c
extern int lua_entity_get_all_with_component(lua_State *L);

// Helper: Poll for entities with a specific component and call handler for each
static void poll_oneframe_component(lua_State *L, const char *componentName,
                                    void (*handler)(lua_State*, uint64_t)) {
    if (g_trace_enabled) {
        LOG_EVENTS_INFO("[TRACE] Polling component: %s", componentName);
    }

    lua_getglobal(L, "Ext");
    if (!lua_istable(L, -1)) { lua_pop(L, 1); return; }

    lua_getfield(L, -1, "Entity");
    if (!lua_istable(L, -1)) { lua_pop(L, 2); return; }

    lua_getfield(L, -1, "GetAllEntitiesWithComponent");
    if (!lua_isfunction(L, -1)) { lua_pop(L, 3); return; }

    lua_pushstring(L, componentName);
    if (lua_pcall(L, 1, 1, 0) == LUA_OK && lua_istable(L, -1)) {
        int entity_count = 0;
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            if (lua_isinteger(L, -1)) {
                uint64_t entity = (uint64_t)lua_tointeger(L, -1);
                entity_count++;
                if (g_trace_enabled) {
                    LOG_EVENTS_INFO("[TRACE] Found entity 0x%llx with %s",
                                    (unsigned long long)entity, componentName);
                }
                handler(L, entity);
            }
            lua_pop(L, 1);  // Pop value, keep key
        }
        if (g_trace_enabled && entity_count > 0) {
            LOG_EVENTS_INFO("[TRACE] %s: %d entities processed", componentName, entity_count);
        }
    } else if (g_trace_enabled) {
        // Log if the component wasn't found (typeIndex=65535 case)
        const char *err = lua_tostring(L, -1);
        if (err) {
            LOG_EVENTS_DEBUG("[TRACE] GetAllEntitiesWithComponent failed for %s: %s",
                            componentName, err);
        }
    }
    lua_pop(L, 3);  // Pop result + Entity + Ext
}

// Individual event handlers for each one-frame component type
static void handle_turn_started(lua_State *L, uint64_t entity) {
    events_fire_turn_started(L, entity, 0);  // Round extracted from component if needed
}

static void handle_turn_ended(lua_State *L, uint64_t entity) {
    // Fire TurnEnded event
    if (g_handler_counts[EVENT_TURN_ENDED] == 0) return;

    g_dispatch_depth[EVENT_TURN_ENDED]++;
    for (int i = 0; i < g_handler_counts[EVENT_TURN_ENDED]; i++) {
        EventHandler *h = &g_handlers[EVENT_TURN_ENDED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_TURN_ENDED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_TURN_ENDED]--;
    if (g_dispatch_depth[EVENT_TURN_ENDED] == 0) process_deferred_unsubscribes(L, EVENT_TURN_ENDED);
}

static void handle_combat_started(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_COMBAT_STARTED] == 0) return;

    g_dispatch_depth[EVENT_COMBAT_STARTED]++;
    for (int i = 0; i < g_handler_counts[EVENT_COMBAT_STARTED]; i++) {
        EventHandler *h = &g_handlers[EVENT_COMBAT_STARTED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "CombatId");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_COMBAT_STARTED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_COMBAT_STARTED]--;
    if (g_dispatch_depth[EVENT_COMBAT_STARTED] == 0) process_deferred_unsubscribes(L, EVENT_COMBAT_STARTED);
}

static void handle_combat_left(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_COMBAT_ENDED] == 0) return;

    g_dispatch_depth[EVENT_COMBAT_ENDED]++;
    for (int i = 0; i < g_handler_counts[EVENT_COMBAT_ENDED]; i++) {
        EventHandler *h = &g_handlers[EVENT_COMBAT_ENDED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_COMBAT_ENDED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_COMBAT_ENDED]--;
    if (g_dispatch_depth[EVENT_COMBAT_ENDED] == 0) process_deferred_unsubscribes(L, EVENT_COMBAT_ENDED);
}

static void handle_status_applied(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_STATUS_APPLIED] == 0) return;

    g_dispatch_depth[EVENT_STATUS_APPLIED]++;
    for (int i = 0; i < g_handler_counts[EVENT_STATUS_APPLIED]; i++) {
        EventHandler *h = &g_handlers[EVENT_STATUS_APPLIED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            // TODO: Extract StatusId from component data
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_STATUS_APPLIED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_STATUS_APPLIED]--;
    if (g_dispatch_depth[EVENT_STATUS_APPLIED] == 0) process_deferred_unsubscribes(L, EVENT_STATUS_APPLIED);
}

static void handle_status_removed(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_STATUS_REMOVED] == 0) return;

    g_dispatch_depth[EVENT_STATUS_REMOVED]++;
    for (int i = 0; i < g_handler_counts[EVENT_STATUS_REMOVED]; i++) {
        EventHandler *h = &g_handlers[EVENT_STATUS_REMOVED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_STATUS_REMOVED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_STATUS_REMOVED]--;
    if (g_dispatch_depth[EVENT_STATUS_REMOVED] == 0) process_deferred_unsubscribes(L, EVENT_STATUS_REMOVED);
}

static void handle_equipment_changed(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_EQUIPMENT_CHANGED] == 0) return;

    g_dispatch_depth[EVENT_EQUIPMENT_CHANGED]++;
    for (int i = 0; i < g_handler_counts[EVENT_EQUIPMENT_CHANGED]; i++) {
        EventHandler *h = &g_handlers[EVENT_EQUIPMENT_CHANGED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_EQUIPMENT_CHANGED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_EQUIPMENT_CHANGED]--;
    if (g_dispatch_depth[EVENT_EQUIPMENT_CHANGED] == 0) process_deferred_unsubscribes(L, EVENT_EQUIPMENT_CHANGED);
}

static void handle_level_up(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_LEVEL_UP] == 0) return;

    g_dispatch_depth[EVENT_LEVEL_UP]++;
    for (int i = 0; i < g_handler_counts[EVENT_LEVEL_UP]; i++) {
        EventHandler *h = &g_handlers[EVENT_LEVEL_UP][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            // TODO: Extract PreviousLevel and NewLevel from component
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_LEVEL_UP, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_LEVEL_UP]--;
    if (g_dispatch_depth[EVENT_LEVEL_UP] == 0) process_deferred_unsubscribes(L, EVENT_LEVEL_UP);
}

// ============================================================================
// Additional One-Frame Handlers (Issue #51 expansion)
// ============================================================================

static void handle_died(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_DIED] == 0) return;

    g_dispatch_depth[EVENT_DIED]++;
    for (int i = 0; i < g_handler_counts[EVENT_DIED]; i++) {
        EventHandler *h = &g_handlers[EVENT_DIED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_DIED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_DIED]--;
    if (g_dispatch_depth[EVENT_DIED] == 0) process_deferred_unsubscribes(L, EVENT_DIED);
}

static void handle_downed(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_DOWNED] == 0) return;

    g_dispatch_depth[EVENT_DOWNED]++;
    for (int i = 0; i < g_handler_counts[EVENT_DOWNED]; i++) {
        EventHandler *h = &g_handlers[EVENT_DOWNED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_DOWNED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_DOWNED]--;
    if (g_dispatch_depth[EVENT_DOWNED] == 0) process_deferred_unsubscribes(L, EVENT_DOWNED);
}

static void handle_resurrected(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_RESURRECTED] == 0) return;

    g_dispatch_depth[EVENT_RESURRECTED]++;
    for (int i = 0; i < g_handler_counts[EVENT_RESURRECTED]; i++) {
        EventHandler *h = &g_handlers[EVENT_RESURRECTED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_RESURRECTED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_RESURRECTED]--;
    if (g_dispatch_depth[EVENT_RESURRECTED] == 0) process_deferred_unsubscribes(L, EVENT_RESURRECTED);
}

static void handle_spell_cast(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_SPELL_CAST] == 0) return;

    g_dispatch_depth[EVENT_SPELL_CAST]++;
    for (int i = 0; i < g_handler_counts[EVENT_SPELL_CAST]; i++) {
        EventHandler *h = &g_handlers[EVENT_SPELL_CAST][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            // TODO: Extract SpellId from component
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_SPELL_CAST, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_SPELL_CAST]--;
    if (g_dispatch_depth[EVENT_SPELL_CAST] == 0) process_deferred_unsubscribes(L, EVENT_SPELL_CAST);
}

static void handle_spell_cast_finished(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_SPELL_CAST_FINISHED] == 0) return;

    g_dispatch_depth[EVENT_SPELL_CAST_FINISHED]++;
    for (int i = 0; i < g_handler_counts[EVENT_SPELL_CAST_FINISHED]; i++) {
        EventHandler *h = &g_handlers[EVENT_SPELL_CAST_FINISHED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_SPELL_CAST_FINISHED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_SPELL_CAST_FINISHED]--;
    if (g_dispatch_depth[EVENT_SPELL_CAST_FINISHED] == 0) process_deferred_unsubscribes(L, EVENT_SPELL_CAST_FINISHED);
}

static void handle_hit_notification(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_HIT_NOTIFICATION] == 0) return;

    g_dispatch_depth[EVENT_HIT_NOTIFICATION]++;
    for (int i = 0; i < g_handler_counts[EVENT_HIT_NOTIFICATION]; i++) {
        EventHandler *h = &g_handlers[EVENT_HIT_NOTIFICATION][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_HIT_NOTIFICATION, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_HIT_NOTIFICATION]--;
    if (g_dispatch_depth[EVENT_HIT_NOTIFICATION] == 0) process_deferred_unsubscribes(L, EVENT_HIT_NOTIFICATION);
}

static void handle_short_rest_started(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_SHORT_REST_STARTED] == 0) return;

    g_dispatch_depth[EVENT_SHORT_REST_STARTED]++;
    for (int i = 0; i < g_handler_counts[EVENT_SHORT_REST_STARTED]; i++) {
        EventHandler *h = &g_handlers[EVENT_SHORT_REST_STARTED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_SHORT_REST_STARTED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_SHORT_REST_STARTED]--;
    if (g_dispatch_depth[EVENT_SHORT_REST_STARTED] == 0) process_deferred_unsubscribes(L, EVENT_SHORT_REST_STARTED);
}

static void handle_approval_changed(lua_State *L, uint64_t entity) {
    if (g_handler_counts[EVENT_APPROVAL_CHANGED] == 0) return;

    g_dispatch_depth[EVENT_APPROVAL_CHANGED]++;
    for (int i = 0; i < g_handler_counts[EVENT_APPROVAL_CHANGED]; i++) {
        EventHandler *h = &g_handlers[EVENT_APPROVAL_CHANGED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (lua_isfunction(L, -1)) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)entity);
            lua_setfield(L, -2, "Entity");
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
        if (h->once && g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] = (DeferredUnsubscribe){EVENT_APPROVAL_CHANGED, h->handler_id};
        }
    }
    g_dispatch_depth[EVENT_APPROVAL_CHANGED]--;
    if (g_dispatch_depth[EVENT_APPROVAL_CHANGED] == 0) process_deferred_unsubscribes(L, EVENT_APPROVAL_CHANGED);
}

void events_poll_oneframe_components(lua_State *L) {
    if (!L) return;

    // Only poll if we have subscribers to any engine events
    int total_handlers = 0;
    for (int i = EVENT_TURN_STARTED; i <= EVENT_APPROVAL_CHANGED; i++) {
        total_handlers += g_handler_counts[i];
    }
    if (total_handlers == 0) return;

    // Combat turn events - now registered via Ghidra discovery
    if (g_handler_counts[EVENT_TURN_STARTED] > 0) {
        poll_oneframe_component(L, "esv::TurnStartedEventOneFrameComponent", handle_turn_started);
    }
    if (g_handler_counts[EVENT_TURN_ENDED] > 0) {
        poll_oneframe_component(L, "esv::TurnEndedEventOneFrameComponent", handle_turn_ended);
    }

    // Combat join event (fires when entity joins combat)
    if (g_handler_counts[EVENT_COMBAT_STARTED] > 0) {
        poll_oneframe_component(L, "esv::combat::JoinEventOneFrameComponent", handle_combat_started);
    }

    // Combat flee success (fires when entity leaves combat via flee)
    if (g_handler_counts[EVENT_COMBAT_ENDED] > 0) {
        poll_oneframe_component(L, "esv::combat::FleeSuccessOneFrameComponent", handle_combat_left);
    }

    // Equipment events - use equipped/unequipped events
    if (g_handler_counts[EVENT_EQUIPMENT_CHANGED] > 0) {
        poll_oneframe_component(L, "esv::item::EquippedEventOneFrameComponent", handle_equipment_changed);
        poll_oneframe_component(L, "esv::item::UnequippedEventOneFrameComponent", handle_equipment_changed);
    }

    // Status events - use activation/deactivation events
    if (g_handler_counts[EVENT_STATUS_APPLIED] > 0) {
        poll_oneframe_component(L, "esv::status::ActivationEventOneFrameComponent", handle_status_applied);
    }
    if (g_handler_counts[EVENT_STATUS_REMOVED] > 0) {
        poll_oneframe_component(L, "esv::status::DeactivationEventOneFrameComponent", handle_status_removed);
    }

    // Level up event - now registered via Ghidra discovery
    if (g_handler_counts[EVENT_LEVEL_UP] > 0) {
        poll_oneframe_component(L, "esv::stats::LevelChangedOneFrameComponent", handle_level_up);
    }

    // ========================================================================
    // Additional events (Issue #51 expansion)
    // ========================================================================

    // Death events
    if (g_handler_counts[EVENT_DIED] > 0) {
        poll_oneframe_component(L, "esv::death::ExecuteDieLogicEventOneFrameComponent", handle_died);
    }
    if (g_handler_counts[EVENT_DOWNED] > 0) {
        poll_oneframe_component(L, "esv::death::DownedEventOneFrameComponent", handle_downed);
    }
    if (g_handler_counts[EVENT_RESURRECTED] > 0) {
        poll_oneframe_component(L, "esv::death::ResurrectedEventOneFrameComponent", handle_resurrected);
    }

    // Spell events
    if (g_handler_counts[EVENT_SPELL_CAST] > 0) {
        poll_oneframe_component(L, "eoc::spell_cast::CastEventOneFrameComponent", handle_spell_cast);
    }
    if (g_handler_counts[EVENT_SPELL_CAST_FINISHED] > 0) {
        poll_oneframe_component(L, "eoc::spell_cast::FinishedEventOneFrameComponent", handle_spell_cast_finished);
    }

    // Hit events
    if (g_handler_counts[EVENT_HIT_NOTIFICATION] > 0) {
        poll_oneframe_component(L, "esv::hit::HitNotificationEventOneFrameComponent", handle_hit_notification);
    }

    // Rest events
    if (g_handler_counts[EVENT_SHORT_REST_STARTED] > 0) {
        poll_oneframe_component(L, "esv::rest::ShortRestResultEventOneFrameComponent", handle_short_rest_started);
    }

    // Approval events
    if (g_handler_counts[EVENT_APPROVAL_CHANGED] > 0) {
        poll_oneframe_component(L, "esv::approval::RatingsChangedOneFrameComponent", handle_approval_changed);
    }
}
