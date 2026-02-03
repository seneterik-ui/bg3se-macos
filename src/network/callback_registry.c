/**
 * BG3SE-macOS - Callback Registry Implementation
 *
 * Manages request/reply correlation for NetChannel API.
 * Uses Lua registry (luaL_ref) to store callback functions.
 *
 * Issue #6: NetChannel API
 */

#include "callback_registry.h"
#include "../core/logging.h"
#include <lauxlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// Static State
// ============================================================================

static CallbackEntry g_callbacks[MAX_PENDING_CALLBACKS];
static uint64_t g_next_request_id = 1;
static bool g_initialized = false;

// ============================================================================
// Time Utilities
// ============================================================================

static uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// ============================================================================
// Public API
// ============================================================================

void callback_registry_init(void) {
    if (g_initialized) return;

    memset(g_callbacks, 0, sizeof(g_callbacks));
    g_next_request_id = 1;
    g_initialized = true;

    LOG_NET_DEBUG("Callback registry initialized");
}

uint64_t callback_registry_register(lua_State *L) {
    if (!g_initialized) {
        callback_registry_init();
    }

    // Verify there's a function at stack top
    if (!lua_isfunction(L, -1)) {
        LOG_NET_ERROR("callback_registry_register: expected function at stack top");
        lua_pop(L, 1);  // Pop the non-function to maintain stack balance
        return 0;
    }

    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (!g_callbacks[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        LOG_NET_ERROR("Callback registry full (%d callbacks)", MAX_PENDING_CALLBACKS);
        lua_pop(L, 1);  // Pop the function
        return 0;
    }

    // Store function in Lua registry
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    if (ref == LUA_REFNIL || ref == LUA_NOREF) {
        LOG_NET_ERROR("Failed to store callback in Lua registry");
        return 0;
    }

    // Assign request ID and store
    uint64_t request_id = g_next_request_id++;

    g_callbacks[slot].request_id = request_id;
    g_callbacks[slot].lua_ref = ref;
    g_callbacks[slot].owner_L = L;  // Track owning Lua state
    g_callbacks[slot].timestamp = get_current_time_ms();
    g_callbacks[slot].active = true;

    LOG_NET_DEBUG("Registered callback: request_id=%llu, slot=%d, ref=%d, owner=%p",
                (unsigned long long)request_id, slot, ref, (void*)L);

    return request_id;
}

bool callback_registry_retrieve(lua_State *L, uint64_t request_id) {
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (g_callbacks[i].active && g_callbacks[i].request_id == request_id) {
            // Verify we're using the correct Lua state
            if (g_callbacks[i].owner_L != L) {
                LOG_NET_WARN("Callback retrieve: state mismatch (registered=%p, requesting=%p)",
                            (void*)g_callbacks[i].owner_L, (void*)L);
                // Use the owner state for the operation
                L = g_callbacks[i].owner_L;
            }

            // Push callback function onto stack
            lua_rawgeti(L, LUA_REGISTRYINDEX, g_callbacks[i].lua_ref);

            // Release the reference (one-shot callback)
            luaL_unref(L, LUA_REGISTRYINDEX, g_callbacks[i].lua_ref);

            // Clear slot
            g_callbacks[i].active = false;
            g_callbacks[i].request_id = 0;
            g_callbacks[i].lua_ref = LUA_NOREF;
            g_callbacks[i].owner_L = NULL;

            LOG_NET_DEBUG("Retrieved callback: request_id=%llu",
                        (unsigned long long)request_id);

            return true;
        }
    }

    LOG_NET_WARN("Callback not found: request_id=%llu",
                (unsigned long long)request_id);
    return false;
}

bool callback_registry_exists(uint64_t request_id) {
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (g_callbacks[i].active && g_callbacks[i].request_id == request_id) {
            return true;
        }
    }
    return false;
}

bool callback_registry_cancel(lua_State *L, uint64_t request_id) {
    (void)L;  // L is unused - we use the owner state instead
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (g_callbacks[i].active && g_callbacks[i].request_id == request_id) {
            // Use the owner Lua state for unref (not the passed-in L)
            lua_State *owner = g_callbacks[i].owner_L;
            if (owner) {
                luaL_unref(owner, LUA_REGISTRYINDEX, g_callbacks[i].lua_ref);
            }

            // Clear slot
            g_callbacks[i].active = false;
            g_callbacks[i].request_id = 0;
            g_callbacks[i].lua_ref = LUA_NOREF;
            g_callbacks[i].owner_L = NULL;

            LOG_NET_DEBUG("Cancelled callback: request_id=%llu",
                        (unsigned long long)request_id);

            return true;
        }
    }
    return false;
}

int callback_registry_cleanup_expired(lua_State *L, uint64_t timeout_ms) {
    (void)L;  // L is unused now - we use the owner state instead
    uint64_t now = get_current_time_ms();
    int cleaned = 0;

    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (g_callbacks[i].active) {
            uint64_t age = now - g_callbacks[i].timestamp;
            if (age > timeout_ms) {
                // Use the owner Lua state for unref (critical for cross-state safety)
                lua_State *owner = g_callbacks[i].owner_L;
                if (owner) {
                    luaL_unref(owner, LUA_REGISTRYINDEX, g_callbacks[i].lua_ref);
                }

                LOG_NET_WARN("Expired callback: request_id=%llu, age=%llums",
                            (unsigned long long)g_callbacks[i].request_id,
                            (unsigned long long)age);

                // Clear slot
                g_callbacks[i].active = false;
                g_callbacks[i].request_id = 0;
                g_callbacks[i].lua_ref = LUA_NOREF;
                g_callbacks[i].owner_L = NULL;

                cleaned++;
            }
        }
    }

    if (cleaned > 0) {
        LOG_NET_DEBUG("Cleaned up %d expired callbacks", cleaned);
    }

    return cleaned;
}

int callback_registry_count(void) {
    int count = 0;
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (g_callbacks[i].active) {
            count++;
        }
    }
    return count;
}
