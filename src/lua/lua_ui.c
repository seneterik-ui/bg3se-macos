/**
 * lua_ui.c - Lua Bindings for Ext.UI (Noesis Stub API)
 *
 * MCM uses Ext.UI for ESC menu button injection via Noesis.
 * macOS BG3 does not use Noesis, so these are graceful stubs.
 * MCM checks for nil returns and degrades to IMGUI-only mode.
 */

#include "lua_ui.h"
#include "../core/logging.h"

#include "../../lib/lua/src/lauxlib.h"

static int s_warned = 0;

static void warn_once(const char *func) {
    if (!s_warned) {
        log_message("[INFO] [Ext.UI] %s called — Noesis UI not available on macOS (MCM will use IMGUI fallback)", func);
        s_warned = 1;
    }
}

/**
 * Ext.UI.GetRoot() -> nil
 */
static int lua_ui_get_root(lua_State *L) {
    warn_once("GetRoot");
    lua_pushnil(L);
    return 1;
}

/**
 * Ext.UI.RegisterType(name) -> nil (no-op)
 */
static int lua_ui_register_type(lua_State *L) {
    (void)luaL_checkstring(L, 1);
    warn_once("RegisterType");
    lua_pushnil(L);
    return 1;
}

/**
 * Ext.UI.Instantiate(name) -> nil
 */
static int lua_ui_instantiate(lua_State *L) {
    (void)luaL_checkstring(L, 1);
    warn_once("Instantiate");
    lua_pushnil(L);
    return 1;
}

/**
 * Ext.UI.IsReady() -> false
 */
static int lua_ui_is_ready(lua_State *L) {
    lua_pushboolean(L, 0);
    return 1;
}

/**
 * Ext.UI.SetValue(path, value) -> nil (no-op)
 */
static int lua_ui_set_value(lua_State *L) {
    (void)L;
    return 0;
}

/**
 * Ext.UI.GetValue(path) -> nil
 */
static int lua_ui_get_value(lua_State *L) {
    (void)L;
    lua_pushnil(L);
    return 1;
}

void lua_ext_register_ui(lua_State *L, int ext_table_idx) {
    // Normalize index
    if (ext_table_idx < 0) ext_table_idx = lua_gettop(L) + ext_table_idx + 1;

    // Create Ext.UI table
    lua_newtable(L);

    lua_pushcfunction(L, lua_ui_get_root);
    lua_setfield(L, -2, "GetRoot");

    lua_pushcfunction(L, lua_ui_register_type);
    lua_setfield(L, -2, "RegisterType");

    lua_pushcfunction(L, lua_ui_instantiate);
    lua_setfield(L, -2, "Instantiate");

    lua_pushcfunction(L, lua_ui_is_ready);
    lua_setfield(L, -2, "IsReady");

    lua_pushcfunction(L, lua_ui_set_value);
    lua_setfield(L, -2, "SetValue");

    lua_pushcfunction(L, lua_ui_get_value);
    lua_setfield(L, -2, "GetValue");

    // Set Ext.UI = table
    lua_setfield(L, ext_table_idx, "UI");

    LOG_LUA_INFO("Registered Ext.UI namespace (Noesis stubs for MCM compatibility)");
}
